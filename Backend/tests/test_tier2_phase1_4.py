"""
Phase 1.4 Test Suite — Tier 2 Detection Hardening & Verification.

Covers:
1. Domain Intelligence & RDAP / WHOIS Cascading Fallback & SSRF Safety
2. Positive & Negative Caching with TTL Semantics and LRU Eviction
3. Domain-Age Semantics (VERIFIED_NEW, VERIFIED_ESTABLISHED, UNKNOWN, LOOKUP_FAILED)
4. Threat Analyzer (RFC 2822 sender parsing, typosquatting, compound bonuses)
5. ML Model (singleton concurrency lock, class probability semantics, non-downgrade fallback)
6. Gateway execute_tier2 end-to-end integration and bounded scoring
"""

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from tier_2.whois_client import WhoisClient, get_whois_client
from tier_2.domain_intel import analyze_domain_age, aget_domain_age, SCORE_UNKNOWN, SCORE_NEW, SCORE_OK
from tier_2.analyzer import ThreatAnalyzer, ThreatAnalysis
from tier_2.ml_model import PhishingMLModel, get_ml_model
from models.gateway_models import DomainStatus


# ============================================================
# 1. DOMAIN INTELLIGENCE & RDAP / WHOIS TESTS
# ============================================================

@pytest.mark.asyncio
async def test_whois_rdap_success():
    """RDAP over HTTPS returns valid registration event and computes domain age."""
    client = WhoisClient(enable_cache=False, enable_rdap=True)

    mock_rdap_data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_rdap_data

    with patch("whois.whois", side_effect=Exception("Library socket blocked")):
        with patch("tier_2.whois_client.is_safe_url", return_value=True):
            with patch.object(client.http_client, "get", new_callable=AsyncMock, return_value=mock_resp):
                age, source = await client.get_domain_age("rdap-test.com")
                assert age is not None
                assert age > 1000
                assert source == "rdap"

    await client.close()


@pytest.mark.asyncio
async def test_whois_rdap_ssrf_protection():
    """RDAP client rejects private/internal URLs to prevent SSRF."""
    client = WhoisClient(enable_cache=False, enable_rdap=True)

    # Attempt to query private/loopback domain via RDAP
    with patch("tier_2.whois_client.is_safe_url", return_value=False):
        age = await client._get_from_rdap("127.0.0.1")
        assert age is None

    await client.close()


@pytest.mark.asyncio
async def test_whois_rdap_redirect_ssrf_blocked():
    """RDAP redirect to internal cloud metadata (169.254.169.254) is blocked."""
    client = WhoisClient(enable_cache=False, enable_rdap=True)

    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch.object(client.http_client, "get", new_callable=AsyncMock, return_value=redirect_resp):
        with patch("tier_2.whois_client.is_safe_url", side_effect=[True, False]):
            age = await client._get_from_rdap("evil-redirect.com")
            assert age is None

    await client.close()


@pytest.mark.asyncio
async def test_whois_timeout_graceful():
    """All providers timing out returns (None, 'unknown') without unhandled exceptions."""
    client = WhoisClient(enable_cache=False, enable_rdap=True, library_timeout=0.1, rdap_timeout=0.1)

    with patch("whois.whois", side_effect=TimeoutError("Socket timeout")):
        with patch.object(client.http_client, "get", side_effect=httpx.TimeoutException("RDAP timeout")):
            age, source = await client.get_domain_age("timeout-domain.org")
            assert age is None
            assert source == "unknown"

    await client.close()


@pytest.mark.asyncio
async def test_whois_negative_cache():
    """Failed lookup caches negative result and returns instantly on subsequent request."""
    client = WhoisClient(enable_cache=True, negative_cache_ttl=300)

    with patch("whois.whois", side_effect=Exception("Unregistered domain")):
        with patch.object(client, "_get_from_rdap", new_callable=AsyncMock, return_value=None):
            # First attempt: miss, all providers fail, negative entry cached
            age1, source1 = await client.get_domain_age("nonexistent-test-domain.xyz")
            assert age1 is None
            assert source1 == "unknown"

            # Second attempt: negative cache hit
            age2, source2 = await client.get_domain_age("nonexistent-test-domain.xyz")
            assert age2 is None
            assert source2 == "cache:negative"

    await client.close()


@pytest.mark.asyncio
async def test_whois_key_normalization():
    """Domain normalization strips whitespace, casing, and trailing dots to match cache keys."""
    client = WhoisClient()
    k1 = client._cache_key("  Sub.EXAMPLE.com.  ")
    k2 = client._cache_key("sub.example.com")
    assert k1 == k2
    await client.close()


# ============================================================
# 2. DOMAIN-AGE SEMANTICS & SCORING TESTS
# ============================================================

def test_analyze_domain_age_verified_new():
    """Age < 30 days is CRITICAL with score 100.0."""
    score, status, msg = analyze_domain_age(12)
    assert score == SCORE_NEW
    assert status == "CRITICAL"
    assert "12 days old" in msg


def test_analyze_domain_age_verified_suspicious():
    """Age 30..364 days is SUSPICIOUS with score 60.0."""
    score, status, msg = analyze_domain_age(120)
    assert score == 60.0
    assert status == "SUSPICIOUS"
    assert "120 days old" in msg


def test_analyze_domain_age_verified_established():
    """Age >= 365 days is OK with score 10.0."""
    score, status, msg = analyze_domain_age(800)
    assert score == SCORE_OK
    assert status == "OK"
    assert "established" in msg


def test_analyze_domain_age_unknown_neutral():
    """Missing domain age defaults to 50.0 (neutral uncertainty, never 70.0)."""
    score, status, msg = analyze_domain_age(None)
    assert score == 50.0
    assert status == "UNKNOWN"
    assert "Could not verify" in msg


def test_analyze_domain_age_lookup_failed_explicit():
    """Explicit LOOKUP_FAILED reports provider failure and retains neutral 50.0."""
    score, status, msg = analyze_domain_age(None, lookup_status="LOOKUP_FAILED")
    assert score == 50.0
    assert status == "UNKNOWN"
    assert "timed out or provider unavailable" in msg


# ============================================================
# 3. THREAT ANALYZER & SENDER PARSING TESTS
# ============================================================

@pytest.mark.asyncio
async def test_threat_analyzer_rfc2822_sender_typosquatting():
    """RFC 2822 formatted sender extracts domain cleanly and flags typosquatting."""
    sender = "PayPal Billing <support@paypa1.com>"
    body = "Please update your account payment details."

    res = await ThreatAnalyzer.analyze_threat(email_body=body, sender=sender, links=[], use_ml=False)
    assert any("typosquatting:paypal.com" in f for f in res.flagged_phrases)
    assert res.threat_level >= 40


@pytest.mark.asyncio
async def test_threat_analyzer_compound_escalation():
    """Urgency + Financial + Link indicators trigger compound escalation bonuses."""
    sender = "alert@unknown-sender.org"
    body = "URGENT: Your unpaid invoice is overdue. Immediate wire transfer required today!"
    links = ["http://192.168.1.50/invoice.pdf"]

    res = await ThreatAnalyzer.analyze_threat(email_body=body, sender=sender, links=links, use_ml=False)
    assert res.threat_level >= 70
    assert "Urgency" in res.category or "Financial" in res.category
    assert any("ip_based_link" in f for f in res.flagged_phrases)


@pytest.mark.asyncio
async def test_threat_analyzer_ml_timeout_does_not_downgrade():
    """When ML inference times out, base threat score is NOT downgraded."""
    mock_model = MagicMock()
    mock_model.is_loaded.return_value = True
    mock_model.predict = AsyncMock(return_value=(50.0, "timeout"))

    with (
        patch("tier_2.analyzer.get_ml_model", new_callable=AsyncMock, return_value=mock_model),
        patch("tier_2.analyzer.ML_AVAILABLE", True),
        patch.dict("os.environ", {"ML_ENABLED": "true"}),
    ):
        body = "URGENT: Your password will expire immediately. Verify your account login credentials now!"
        res = await ThreatAnalyzer.analyze_threat(
            email_body=body,
            sender="admin@notice-alert.xyz",
            links=["http://10.0.0.1/login"],
            use_ml=True,
        )
        # Base threat with urgency + credential + IP link is >= 70.
        # Degraded ML should not drag it down below base threat.
        assert res.threat_level >= 70
        assert "ML:Degraded" in res.category


# ============================================================
# 4. ML MODEL (DISTILBERT) LIFECYCLE & CONCURRENCY TESTS
# ============================================================

@pytest.mark.asyncio
async def test_ml_model_singleton_concurrency():
    """Concurrent calls to get_ml_model return identical instance via lock."""
    import tier_2.ml_model as ml_mod

    ml_mod._ml_model_instance = None

    tasks = [get_ml_model() for _ in range(10)]
    models = await asyncio.gather(*tasks)

    # Every returned reference must be the exact same singleton instance
    first_model = models[0]
    for m in models[1:]:
        assert m is first_model

    ml_mod._ml_model_instance = None


@pytest.mark.asyncio
async def test_ml_model_class_mapping_correctness():
    """Confirm binary/multi-class mapping: Class 0 is benign, Class 1 is phishing."""
    model = PhishingMLModel(model_name="test-model")

    # Mock tokenizer & model returning high prob at index 1 (phishing)
    mock_tok = MagicMock()
    mock_tok.return_value = {"input_ids": MagicMock()}

    mock_outputs = MagicMock()
    mock_torch = MagicMock()
    # Logits where index 1 dominates
    mock_probs = MagicMock()
    mock_probs.cpu().numpy.return_value = [[0.05, 0.95]]
    mock_torch.softmax.return_value = mock_probs

    with (
        patch.object(ml_mod := __import__("tier_2.ml_model", fromlist=["ml_model"]), "TRANSFORMERS_AVAILABLE", True),
        patch.object(ml_mod, "torch", mock_torch),
    ):
        model.tokenizer = mock_tok
        model.model = MagicMock()
        model._loaded = True

        score, conf = await model.predict("Malicious phishing sample text.")
        assert score == 95.0
        assert conf == "phishing"


# ============================================================
# 5. GATEWAY EXECUTE_TIER2 INTEGRATION TESTS
# ============================================================

@pytest.mark.asyncio
async def test_execute_tier2_normal_benign():
    """End-to-end execute_tier2 on benign email produces structured bounded Tier2Result."""
    from gateway import execute_tier2

    with patch("gateway.aget_domain_age", new_callable=AsyncMock, return_value=500):
        res = await execute_tier2(
            sender="Alice Colleague <alice@company.com>",
            body="Hello team, here is the weekly project update.",
            links=["https://company.com/updates"],
        )
        assert res.score < 40.0
        assert res.domain_analysis.status == DomainStatus.OK
        assert res.domain_analysis.score == 10.0
        assert 0.0 <= res.score <= 100.0
        assert res.execution_time_ms > 0.0


@pytest.mark.asyncio
async def test_execute_tier2_unresolvable_domain_neutral_score():
    """When domain lookup times out / fails, domain score is 50.0 UNKNOWN, never 70.0."""
    from gateway import execute_tier2

    with patch("gateway.aget_domain_age", new_callable=AsyncMock, side_effect=asyncio.TimeoutError("Timeout")):
        res = await execute_tier2(
            sender="Notifications <alerts@unresolvable-domain.invalid>",
            body="Your statement is available online.",
            links=[],
        )
        assert res.domain_analysis.score == 50.0
        assert res.domain_analysis.status == DomainStatus.UNKNOWN
        assert any("timed out or provider unavailable" in e for e in res.evidence)
