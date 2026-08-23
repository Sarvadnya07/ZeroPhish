"""
Unit tests for email_scanner/dns_validator.py.
"""

from unittest.mock import MagicMock, patch

import pytest

from email_scanner.dns_validator import DNSAuthRecord, DnsValidator


class MockTxtRecord:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return f'"{self._text}"'


@pytest.mark.asyncio
async def test_dns_validator_spf_and_dmarc_reject():
    """Test domain with valid SPF and DMARC p=reject."""
    mock_spf_answers = [MockTxtRecord("v=spf1 include:_spf.google.com ~all")]
    mock_dmarc_answers = [MockTxtRecord("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@google.com")]

    def mock_resolve(domain, rdtype, lifetime=5):
        if domain == "google.com":
            return mock_spf_answers
        elif domain == "_dmarc.google.com":
            return mock_dmarc_answers
        raise Exception("NXDOMAIN")

    with patch("dns.resolver.resolve", side_effect=mock_resolve):
        record = await DnsValidator.validate("google.com")
        assert record.domain == "google.com"
        assert record.spf_valid is True
        assert record.spf_record == "v=spf1 include:_spf.google.com ~all"
        assert record.dmarc_policy == "reject"
        assert record.dmarc_pct == 100
        assert record.score_penalty == 0


@pytest.mark.asyncio
async def test_dns_validator_missing_records():
    """Test domain with no SPF or DMARC records (full penalty)."""
    with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        record = await DnsValidator.validate("unconfigured-domain.com")
        assert record.spf_valid is False
        assert record.spf_record is None
        assert record.dmarc_record is None
        assert record.dmarc_policy is None
        # Penalty: 10 (no spf) + 10 (no dmarc) + 5 (policy none/None) = 25
        assert record.score_penalty == 25


@pytest.mark.asyncio
async def test_dns_validator_dmarc_policy_none_with_pct():
    """Test domain with SPF and DMARC policy=none and custom pct."""
    mock_spf_answers = [MockTxtRecord("v=spf1 -all")]
    mock_dmarc_answers = [MockTxtRecord("v=DMARC1; p=none; pct=50;")]

    def mock_resolve(domain, rdtype, lifetime=5):
        if domain == "monitoring-only.com":
            return mock_spf_answers
        elif domain == "_dmarc.monitoring-only.com":
            return mock_dmarc_answers
        raise Exception("NXDOMAIN")

    with patch("dns.resolver.resolve", side_effect=mock_resolve):
        record = await DnsValidator.validate("monitoring-only.com")
        assert record.spf_valid is True
        assert record.dmarc_policy == "none"
        assert record.dmarc_pct == 50
        # Penalty: 0 (spf) + 0 (dmarc present) + 5 (policy none) = 5
        assert record.score_penalty == 5


@pytest.mark.asyncio
async def test_dns_validator_multiple_txt_records():
    """Test searching through multiple non-SPF TXT records."""
    mock_spf_answers = [
        MockTxtRecord("google-site-verification=abcdef"),
        MockTxtRecord("v=spf1 redirect=_spf.example.com"),
    ]

    with patch("dns.resolver.resolve", return_value=mock_spf_answers):
        spf = DnsValidator._get_spf("example.com")
        assert spf == "v=spf1 redirect=_spf.example.com"
