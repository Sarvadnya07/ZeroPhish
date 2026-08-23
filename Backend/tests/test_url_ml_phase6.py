"""
Unit tests for Phase 6 Automated Threat Feed Synchronization, Idempotency,
Source Health Tracking, Dataset Growth Auditing, and Snapshot Immutability.
"""

import json
from pathlib import Path

import pytest

from ml.data.growth import DatasetGrowthTracker
from ml.data.normalization.url_normalizer import URLNormalizer
from ml.data.schemas.v3 import SourceApprovalStatus
from ml.data.sync import SourceHealthTracker, ThreatFeedSyncEngine


def test_source_health_tracker_state():
    tracker = SourceHealthTracker()
    tracker.record_sync_event(
        source_name="Test Feed",
        status="HEALTHY",
        records_fetched=50,
        records_accepted=48,
        records_rejected=2,
        duplicate_count=1,
        conflict_count=1,
        bytes_received=1024,
        checksum="abcd1234",
        latency_ms=15.5,
    )
    assert "Test Feed" in tracker.health_records
    rec = tracker.health_records["Test Feed"]
    assert rec["status"] == "HEALTHY"
    assert rec["records_fetched"] == 50
    assert rec["latency_ms"] == 15.5


def test_sync_engine_idempotency_and_raw_archiving(tmp_path):
    engine = ThreatFeedSyncEngine(data_dir=tmp_path)

    # First sync: SUCCESS
    res1 = engine.sync_source("tranco")
    assert res1["status"] == "SUCCESS"
    assert res1["records_count"] > 0
    assert "payload_hash" in res1

    # Second sync: SKIPPED_ALREADY_PROCESSED (idempotent)
    res2 = engine.sync_source("tranco")
    assert res2["status"] == "SKIPPED_ALREADY_PROCESSED"
    assert res2["payload_hash"] == res1["payload_hash"]


def test_sync_engine_blocks_unapproved_source(tmp_path):
    engine = ThreatFeedSyncEngine(data_dir=tmp_path)
    from ml.data.adapters.feed_adapters import RestrictedFeedTestAdapter

    engine.adapters["restricted"] = RestrictedFeedTestAdapter()

    res = engine.sync_source("restricted")
    assert res["status"] == "SKIPPED_UNAPPROVED"


def test_dataset_growth_tracker_and_target_audit():
    report = DatasetGrowthTracker.generate_growth_report()
    assert "growth_timeline" in report
    assert "target_scale_audit" in report

    audit = report["target_scale_audit"]
    assert audit["target_domains"] == 10000
    assert audit["target_domains_status"] == "TARGET NOT REACHED"
    assert audit["evaluation_verdict"] == "PROMISING — NEEDS MORE DATA"


def test_url_redaction_for_storage_privacy():
    url_with_jwt = "https://example.com/api/v1?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&user=admin"
    redacted = URLNormalizer.redact_sensitive_params(url_with_jwt)
    assert "jwt=%5BREDACTED%5D" in redacted or "jwt=[REDACTED]" in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
