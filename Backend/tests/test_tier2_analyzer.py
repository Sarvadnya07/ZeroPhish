"""
Unit tests for tier_2/analyzer.py.
Covers regex pattern matches, suspicious URLs, IP links, punycode, TLDs, typosquatting, compound heuristics, and ML integration.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tier_2.analyzer import ThreatAnalysis, ThreatAnalyzer


@pytest.mark.asyncio
async def test_analyzer_clean_email():
    """Test standard clean email produces Safe category and low score."""
    body = "Hi team, please find attached the meeting notes from today's discussion."
    sender = "colleague@company.com"
    links = ["https://company.com/notes"]

    result = await ThreatAnalyzer.analyze_threat(
        email_body=body, sender=sender, links=links, use_ml=False
    )
    assert result.threat_level < 20
    assert result.category == "Safe"
    assert "No significant threat" in result.reasoning


@pytest.mark.asyncio
async def test_analyzer_urgency_and_credential_harvest():
    """Test compound urgency + credential threat patterns."""
    body = (
        "URGENT: Your password will expire immediately. Verify your account login credentials now!"
    )
    sender = "security-update@randomhost.xyz"
    links = ["http://192.168.1.100/login", "https://xn--pypal-4ve.com/verify"]

    result = await ThreatAnalyzer.analyze_threat(
        email_body=body, sender=sender, links=links, use_ml=False
    )
    assert result.threat_level >= 70
    assert "Urgency" in result.category or "Credential" in result.category
    assert any("ip_based_link" in p for p in result.flagged_phrases)
    assert any("punycode_link" in p for p in result.flagged_phrases)


@pytest.mark.asyncio
async def test_analyzer_typosquatting_detection():
    """Test Levenshtein distance typosquatting on known brand domains."""
    body = "Please review your pending wire transfer."
    sender = "support@paypa1.com"
    links = []

    result = await ThreatAnalyzer.analyze_threat(
        email_body=body, sender=sender, links=links, use_ml=False
    )
    assert any("typosquatting:paypal.com" in p for p in result.flagged_phrases)
    assert result.threat_level >= 40


@pytest.mark.asyncio
async def test_analyzer_redirect_tracking():
    """Test redirect tracking through url shorteners."""
    short_url = "https://bit.ly/malicious-link"
    mock_resp = MagicMock()
    mock_resp.url = "https://phishing-site.xyz/login"

    with patch("httpx.AsyncClient.head", new_callable=AsyncMock, return_value=mock_resp), \
         patch("security.middleware.is_safe_url", return_value=True):
        final_url, errs = await ThreatAnalyzer.track_redirects(short_url)
        assert final_url == "https://phishing-site.xyz/login"
        assert len(errs) == 0


@pytest.mark.asyncio
async def test_analyzer_ml_enhancement():
    """Test ML model integration in analyzer."""
    body = "Your bank account has been locked. Click to unlock."
    mock_model = MagicMock()
    mock_model.is_loaded.return_value = True
    mock_model.predict = AsyncMock(return_value=(90.0, "phishing"))

    with (
        patch("tier_2.analyzer.get_ml_model", new_callable=AsyncMock, return_value=mock_model),
        patch("tier_2.analyzer.ML_AVAILABLE", True),
        patch.dict("os.environ", {"ML_ENABLED": "true"}),
    ):
        res = await ThreatAnalyzer.analyze_threat(
            email_body=body, sender="service@bank.com", links=[], use_ml=True
        )
        assert res.threat_level >= 60
        assert "ML:Phishing" in res.category
