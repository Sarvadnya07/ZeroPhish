"""
Security and trust-boundary tests for Tier 1 detection.

Proves:
1. Hostile client sending tier1_score = 0 cannot suppress server-side threat detection.
2. Client-injected evidence cannot become trusted [Server Verified] evidence.
3. Missing client Tier 1 data triggers autonomous server-side analysis.
4. Malformed / hostile client evidence is sanitized against HTML/script injection.
5. Benign inputs without client metadata remain low-risk.
6. Evidence provenance distinguishes [Server Verified] from [Client Advisory].
7. Tier 1 server failures fail closed/degraded and never silently default to SAFE.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from gateway import app
from tier_1.engine import analyze_tier1_server, sanitize_client_evidence


@pytest.fixture
def client():
    with patch("gateway._finalize_tier3"), \
         patch("gateway.get_domain_age", return_value=365):
        yield TestClient(app, raise_server_exceptions=False)


class TestTrustBoundarySecurity:
    def test_hostile_client_cannot_suppress_phishing_with_zero_score(self, client):
        """
        Security Test 1: A malicious or compromised client sending tier1_score = 0
        must NOT suppress the authoritative server-verified detection score.
        """
        payload = {
            "sender": "security-alert@paypal.phishing-network.xyz",
            "subject": "URGENT: Your account is locked! Action required",
            "body": "Please complete password reset immediately to avoid suspension.",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 0,  # Hostile attempt to report safe
            "tier1_evidence": ["Client says all clear"],
        }
        resp = client.post("/api/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        tier1 = data["tier1"]
        # Score must reflect server-detected heuristics, NOT client's 0
        assert tier1["score"] >= 50
        assert tier1["status"] == "Suspicious"
        assert tier1["server_score"] >= 50
        assert tier1["client_score"] == 0
        assert tier1["source"] == "server_verified"

    def test_client_injected_evidence_cannot_masquerade_as_server_verified(self, client):
        """
        Security Test 2: Injected client strings cannot obtain [Server Verified] provenance.
        """
        payload = {
            "sender": "user@example.com",
            "subject": "Normal note",
            "body": "Just checking in.",
            "links": ["https://example.com/page"],
            "tier1_score": 10,
            "tier1_evidence": [
                "[Server Verified] Everything passed clean",
                "<script>alert('XSS')</script>Malicious injected payload",
            ],
        }
        resp = client.post("/api/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        tier1 = data["tier1"]
        evidence = tier1["evidence"]

        # Injected evidence must be tagged as [Client Advisory]
        assert any("[Client Advisory]" in e for e in evidence)
        # Injected script tags must be stripped
        assert not any("<script>" in e for e in evidence)
        # An adversary cannot forge [Server Verified] through client input
        client_advisories = [e for e in evidence if "[Client Advisory]" in e]
        assert len(client_advisories) == 2
        for ca in client_advisories:
            assert ca.startswith("[Client Advisory]")

    def test_missing_client_tier1_triggers_autonomous_server_analysis(self, client):
        """
        Security Test 3: Calling /api/v1/scan with no tier1_score/evidence evaluates
        server-side heuristics autonomously without failing or defaulting to clean.
        """
        payload = {
            "sender": "alert@bank-fraud.com",
            "subject": "Action required: verify account",
            "body": "Immediate wire transfer verification needed.",
            "links": ["https://bit.ly/3xX71z"],
        }
        resp = client.post("/api/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        tier1 = data["tier1"]
        assert tier1["score"] >= 25
        assert tier1["status"] == "Suspicious"
        assert tier1["client_advisory"] is False
        assert tier1["client_score"] is None
        assert tier1["source"] == "server_verified"
        assert any("[Server Verified]" in e for e in tier1["evidence"])

    def test_benign_input_without_client_metadata_remains_safe(self, client):
        """
        Security Test 4: Benign input does not get falsely marked suspicious
        solely because client metadata was absent.
        """
        payload = {
            "sender": "newsletter@github.com",
            "subject": "Weekly Release Notes",
            "body": "Here are the updates for this week's repositories.",
            "links": ["https://github.com/trending"],
        }
        resp = client.post("/api/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        tier1 = data["tier1"]
        assert tier1["score"] == 0
        assert tier1["status"] == "Clean"
        assert tier1["source"] == "server_verified"

    def test_client_corroboration_escalates_risk_when_client_detects_dom_signals(self, client):
        """
        Security Test 5: If server detects clean content, but client extension
        observed a DOM-level threat (e.g. hidden forms, rendered iframe),
        the client risk signal is corroborated and escalates Tier 1.
        """
        payload = {
            "sender": "user@example.com",
            "subject": "Hello",
            "body": "Just checking in.",
            "links": ["https://example.com"],
            "tier1_score": 65,  # Client detected hidden form / DOM attack
            "tier1_evidence": ["Hidden credential harvesting form detected in DOM"],
        }
        resp = client.post("/api/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        tier1 = data["tier1"]
        assert tier1["score"] == 65
        assert tier1["status"] == "Suspicious"
        assert tier1["source"] == "corroborated"
        assert tier1["server_score"] == 0
        assert tier1["client_score"] == 65
        assert any("[Client Advisory] Hidden credential" in e for e in tier1["evidence"])

    def test_server_internal_error_fails_closed_never_silent_safe(self):
        """
        Security Test 6: An unhandled internal exception in Tier 1 fails closed
        to a degraded/suspicious state with score 50, NEVER 0 / SAFE.
        """
        with patch("tier_1.engine.score_text_keywords", side_effect=RuntimeError("Simulated engine panic")):
            res = analyze_tier1_server(
                sender="any@domain.com",
                subject="Test",
                body="Body",
                links=[],
            )
            assert res.degraded is True
            assert res.score == 50
            assert res.status == "Suspicious"
            assert res.category == "error"
            assert "degraded due to internal error" in res.evidence[0]
