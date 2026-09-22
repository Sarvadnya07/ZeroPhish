"""
Adversarial test suite for Tier 1 detection engine.

Evaluates evasion resistance against:
- Unicode confusables & homoglyph spoofing
- Punycode domains
- IP-based URL hostnames
- Dangerous TLDs (.zip, .mov, .top, .xyz)
- URL shorteners
- Brand spoofing in display name & anchor text
- Extreme inputs (empty text, oversized link lists, whitespace evasion)
"""

import pytest
from tier_1.engine import analyze_tier1_server


class TestAdversarialUnicodeAndHomoglyphs:
    def test_cyrillic_homoglyph_in_sender_domain(self):
        # 'pаypal.com' with Cyrillic 'а' (\u0430)
        res = analyze_tier1_server(
            sender="service@p\u0430ypal.com",
            subject="Account update",
            body="Please review your settings.",
            links=["https://example.com"],
        )
        assert res.score >= 16
        assert any("non-ascii" in e.lower() for e in res.evidence)

    def test_cyrillic_homoglyph_in_link_domain(self):
        # 'microsоft.com' with Cyrillic 'о' (\u043e)
        res = analyze_tier1_server(
            sender="user@test.org",
            subject="Documentation",
            body="Review document at the portal.",
            links=["https://micros\u043eft.com/login"],
        )
        assert res.score >= 22
        assert any("non-ascii homoglyph in link" in e.lower() for e in res.evidence)

    def test_punycode_link_evasion(self):
        # xn--80ak6aa92e.com (apple.com with Cyrillic)
        res = analyze_tier1_server(
            sender="user@test.org",
            subject="Security warning",
            body="Check your account now.",
            links=["https://xn--80ak6aa92e.com/verify"],
        )
        assert res.score >= 18
        assert any("punycode domain in link" in e.lower() for e in res.evidence)


class TestAdversarialIPAndRouting:
    def test_raw_ipv4_address_in_link(self):
        res = analyze_tier1_server(
            sender="billing@company.com",
            subject="Invoice details",
            body="Your invoice is ready.",
            links=["http://198.51.100.24:8080/invoice.pdf"],
        )
        assert res.score >= 20
        assert any("ip-based url" in e.lower() for e in res.evidence)

    def test_ipv6_address_in_link(self):
        res = analyze_tier1_server(
            sender="user@company.com",
            subject="File share",
            body="Here is the link.",
            links=["http://[2001:db8::1]/file"],
        )
        assert res.score >= 20
        assert any("ip-based url" in e.lower() for e in res.evidence)

    def test_url_shortener_evasion(self):
        res = analyze_tier1_server(
            sender="user@external.org",
            subject="Important survey",
            body="Please fill out this quick form.",
            links=["https://tinyurl.com/xyz12345"],
        )
        assert res.score >= 12
        assert any("shortener" in e.lower() for e in res.evidence)

    def test_dangerous_tld_zip(self):
        res = analyze_tier1_server(
            sender="hr@recruiting-firm.com",
            subject="Resume attachment",
            body="Candidate portfolio available here.",
            links=["https://candidate-resume.zip/archive.zip"],
        )
        assert res.score >= 10
        assert any("suspicious top-level domain: .zip" in e.lower() for e in res.evidence)


class TestBrandSpoofingAndImpersonation:
    def test_display_name_spoofs_microsoft_with_external_domain(self):
        res = analyze_tier1_server(
            sender='"Microsoft Office 365 Team" <admin@compromised-server.info>',
            subject="Your subscription has expired",
            body="Please renew immediately.",
            links=["https://compromised-server.info/renew"],
        )
        assert res.score >= 18
        assert any("suggests microsoft.com" in e.lower() for e in res.evidence)

    def test_link_brand_mismatch_claims_paypal(self):
        res = analyze_tier1_server(
            sender="service@notifications.org",
            subject="Payment confirmation",
            body="View your transaction.",
            links=["https://paypal-security-center.attacker-site.com/auth"],
        )
        assert res.score >= 30
        assert any("brand mismatch" in e.lower() for e in res.evidence)


class TestEvasiveInputFormatting:
    def test_mixed_case_urgency_and_excessive_spacing(self):
        res = analyze_tier1_server(
            sender="support@alert.com",
            subject="uRgEnT :   aCtIoN    rEqUiReD",
            body="Your aCcOuNt is LoCkEd. Please VeRiFy now.",
            links=["https://bit.ly/evasive1"],
        )
        assert res.score >= 35
        assert res.status == "Suspicious"

    def test_empty_and_whitespace_fields_handled_cleanly(self):
        res = analyze_tier1_server(
            sender="   ",
            subject="",
            body="   \n   \t  ",
            links=[],
        )
        assert res.score == 4  # Only sender unavailable penalty
        assert res.status == "Clean"
        assert res.degraded is False

    def test_malformed_url_schemes_do_not_crash_engine(self):
        res = analyze_tier1_server(
            sender="test@example.com",
            subject="Hello",
            body="Check links",
            links=["http://", "not-a-valid-url", "javascript:void(0)", "https:////invalid"],
        )
        assert isinstance(res.score, int)
        assert res.degraded is False
