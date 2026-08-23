"""
Unit tests for Phase 8 Real Threat-Feed Access Verification, Status Model Classification,
Safe Credential Presence Checking, and Blocker Telemetry Generation.
"""

import io
import json
import os
import urllib.error
from pathlib import Path

import pytest

from ml.data.verifier import SourceAccessReportItem, SourceAccessStatus, ThreatFeedAccessVerifier


def test_source_access_status_enums():
    assert SourceAccessStatus.LIVE_ACCESS.value == "LIVE_ACCESS"
    assert SourceAccessStatus.AUTH_REQUIRED.value == "AUTH_REQUIRED"
    assert SourceAccessStatus.SAMPLE_ONLY.value == "SAMPLE_ONLY"
    assert SourceAccessStatus.FIXTURE_ONLY.value == "FIXTURE_ONLY"
    assert SourceAccessStatus.UNAVAILABLE.value == "UNAVAILABLE"
    assert SourceAccessStatus.FORBIDDEN.value == "FORBIDDEN"
    assert SourceAccessStatus.RATE_LIMITED.value == "RATE_LIMITED"


def test_source_access_report_item_to_dict():
    item = SourceAccessReportItem(
        source_name="Test Source",
        status=SourceAccessStatus.LIVE_ACCESS,
        mode="API",
        endpoint_url="https://example.com/api",
        auth_required=False,
        license_status="Open Data",
        http_status=200,
        bytes_received=1000,
        raw_records_count=50,
        unique_domains_count=45,
        fetch_ms=12.5,
        parse_ms=2.1,
        total_ms=14.6,
        sha256_checksum="test_sha",
        notes="Test note",
        blocker="None",
        required_action="None",
    )
    d = item.to_dict()
    assert d["source_name"] == "Test Source"
    assert d["status"] == "LIVE_ACCESS"
    assert d["bytes_received"] == 1000
    assert d["fetch_ms"] == 12.5


def test_credential_presence_safe_check():
    assert (
        ThreatFeedAccessVerifier._check_env_credential_presence("DEFINITELY_NONEXISTENT_KEY_12345")
        is False
    )
    os.environ["TEST_DUMMY_KEY"] = "configured_value"
    try:
        assert ThreatFeedAccessVerifier._check_env_credential_presence("TEST_DUMMY_KEY") is True
    finally:
        os.environ.pop("TEST_DUMMY_KEY", None)


def test_verifier_sample_mode_offline():
    verifier = ThreatFeedAccessVerifier(allow_sample=True)
    report = verifier.run_full_verification()

    assert "overall_decision" in report
    assert "sources" in report
    assert len(report["sources"]) == 5

    tranco_res = next(s for s in report["sources"] if "Tranco" in s["source_name"])
    assert tranco_res["status"] == "SAMPLE_ONLY"
    assert tranco_res["mode"] == "SAMPLE"

    reports_dir = Path(__file__).resolve().parents[1] / "ml" / "data" / "reports"
    assert (reports_dir / "source_access_v4.json").exists()
    assert (reports_dir / "source_access_v4.md").exists()


def test_phishtank_auth_required_when_key_missing(monkeypatch):
    monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
    verifier = ThreatFeedAccessVerifier(allow_sample=False)
    res = verifier.verify_phishtank_access()
    assert res.status == SourceAccessStatus.AUTH_REQUIRED
    assert res.auth_required is True
    assert "missing" in res.blocker.lower()


def test_phishtank_with_key_mock_network(monkeypatch):
    monkeypatch.setenv("PHISHTANK_API_KEY", "test_mock_key")
    verifier = ThreatFeedAccessVerifier(allow_sample=False)

    class MockResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return json.dumps([{"url": "http://evil.com/phish", "phish_id": 123}]).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: MockResponse())
    res = verifier.verify_phishtank_access()
    assert res.status == SourceAccessStatus.LIVE_ACCESS
    assert res.raw_records_count == 1


def test_tranco_network_error_handling(monkeypatch):
    verifier = ThreatFeedAccessVerifier(allow_sample=False)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError(None, 404, "Not Found", None, None)
        ),
    )
    res = verifier.verify_tranco_access()
    assert res.status == SourceAccessStatus.UNAVAILABLE
    assert res.http_status == 404


def test_cloud_cdn_and_adversarial_classification():
    verifier = ThreatFeedAccessVerifier(allow_sample=False)
    cdn_res = verifier.verify_cloud_cdn_access()
    adv_res = verifier.verify_adversarial_access()

    assert cdn_res.status == SourceAccessStatus.SAMPLE_ONLY
    assert adv_res.status == SourceAccessStatus.FIXTURE_ONLY
