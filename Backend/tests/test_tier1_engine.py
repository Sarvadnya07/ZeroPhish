"""
Unit tests for the authoritative server-side Tier 1 heuristic engine.

Tests all heuristic rules:
- Keywords (urgency, credential harvesting, financial fraud)
- Sender analysis (punycode, homoglyphs, brand spoofing, allowlist)
- Link analysis (IP-based URLs, punycode, homoglyphs, shorteners, suspicious TLDs, brand mismatches)
- False-positive mitigation
- Performance benchmarks
"""

import time
import pytest
from tier_1.engine import (
    analyze_tier1_server,
    base_domain,
    classify_tier1_category,
    contains_non_ascii,
    is_ip_hostname,
    normalize_domain,
    sanitize_client_evidence,
)


class TestDomainHelpers:
    def test_normalize_domain(self):
        assert normalize_domain("WWW.Example.Com") == "example.com"
        assert normalize_domain("  sub.domain.org  ") == "sub.domain.org"
        assert normalize_domain("") == ""
        assert normalize_domain(None) == ""

    def test_base_domain(self):
        assert base_domain("login.paypal.com") == "paypal.com"
        assert base_domain("www.google.co.uk") == "google.co.uk"
        assert base_domain("support.amazon.com.au") == "amazon.com.au"
        assert base_domain("localhost") == "localhost"

    def test_is_ip_hostname(self):
        assert is_ip_hostname("192.168.1.1") is True
        assert is_ip_hostname("10.0.0.1") is True
        assert is_ip_hostname("::1") is True
        assert is_ip_hostname("[2001:db8::1]") is True
        assert is_ip_hostname("example.com") is False
        assert is_ip_hostname("192.168.1.1.com") is False

    def test_contains_non_ascii(self):
        assert contains_non_ascii("paypal.com") is False
        assert contains_non_ascii("pаypal.com") is True  # Cyrillic 'а'


class TestKeywordHeuristics:
    def test_urgency_keywords(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            subject="URGENT: Action required immediately",
            body="Your mailbox is locked and account is suspended.",
        )
        assert res.score >= 30
        assert res.status == "Suspicious"
        assert any("urgent" in e.lower() for e in res.evidence)

    def test_credential_harvesting_keywords(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            subject="Security Notice",
            body="Please complete your password reset and sign in to continue.",
        )
        assert res.score >= 20
        assert res.category in ("spam", "phishing")

    def test_financial_fraud_keywords(self):
        res = analyze_tier1_server(
            sender="billing@external.net",
            subject="Invoice details",
            body="Please execute the wire transfer or send gift card as payment.",
        )
        assert res.score >= 25
        assert res.status == "Suspicious"


class TestSenderHeuristics:
    def test_allowlisted_sender(self):
        res = analyze_tier1_server(
            sender="notifications@google.com",
            subject="Project update",
            body="Here is the report from yesterday.",
        )
        assert res.score == 0
        assert res.status == "Clean"
        assert res.category == "safe"
        assert any("allowlist" in e.lower() for e in res.evidence)

    def test_display_name_spoofing(self):
        res = analyze_tier1_server(
            sender='"PayPal Customer Support" <helpdesk@fraudulent-network.com>',
            subject="Account update",
            body="Please update your profile.",
        )
        assert res.score >= 18
        assert any("suggests paypal.com" in e.lower() for e in res.evidence)

    def test_punycode_sender(self):
        res = analyze_tier1_server(
            sender="security@xn--pypal-4ve.com",
            subject="Notice",
            body="Check this.",
        )
        assert res.score >= 12
        assert any("punycode" in e.lower() for e in res.evidence)

    def test_homoglyph_sender(self):
        res = analyze_tier1_server(
            sender="security@pаypal.com",  # Cyrillic 'а'
            subject="Notice",
            body="Check this.",
        )
        assert res.score >= 16
        assert any("non-ascii" in e.lower() for e in res.evidence)


class TestLinkHeuristics:
    def test_ip_based_url(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            body="Click here to login.",
            links=["http://203.0.113.15/login.html"],
        )
        assert res.score >= 20
        assert any("ip-based url" in e.lower() for e in res.evidence)

    def test_punycode_link(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            body="Update your account.",
            links=["https://xn--app-9oa.com/login"],
        )
        assert res.score >= 18
        assert any("punycode domain in link" in e.lower() for e in res.evidence)

    def test_url_shortener(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            body="Read the doc.",
            links=["https://bit.ly/3xX71z"],
        )
        assert res.score >= 12
        assert any("shortener" in e.lower() for e in res.evidence)

    def test_suspicious_tld(self):
        res = analyze_tier1_server(
            sender="user@test.org",
            body="Download report.",
            links=["https://financial-statement.zip/download"],
        )
        assert res.score >= 10
        assert any("suspicious top-level domain: .zip" in e.lower() for e in res.evidence)

    def test_brand_mismatch_link(self):
        res = analyze_tier1_server(
            sender="service@unknown.org",
            body="Verify your account.",
            links=["https://paypal-verify-login.phishingsite.com/auth"],
        )
        assert res.score >= 30
        assert any("brand mismatch" in e.lower() for e in res.evidence)


class TestFalsePositiveMitigation:
    def test_related_organization_links_mitigate_urgency_score(self):
        # Email has urgency words totaling > 25 pts, sender is internal org, all links match sender org
        res = analyze_tier1_server(
            sender="hr@acme-corp.com",
            subject="Action required: quarterly review",
            body="Immediate action required. Please verify spreadsheet before deadline. Mailbox locked.",
            links=["https://portal.acme-corp.com/docs"],
        )
        assert res.score == 9
        assert res.status == "Clean"
        assert any("false-positive mitigation" in e.lower() for e in res.evidence)


class TestPerformance:
    def test_latency_sub_five_milliseconds(self):
        # Measure latency over 50 iterations
        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            analyze_tier1_server(
                sender='"Microsoft Security" <security@external-domain.xyz>',
                subject="URGENT: Action required for your account",
                body="Your mailbox is locked. Please verify password reset immediately.",
                links=["https://bit.ly/3xX71z", "http://192.168.1.1/login"],
            )
            times.append((time.perf_counter() - t0) * 1000)

        avg_latency_ms = sum(times) / len(times)
        assert avg_latency_ms < 5.0, f"Average latency too high: {avg_latency_ms:.2f}ms"
