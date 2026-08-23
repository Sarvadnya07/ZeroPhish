"""
Unit tests for Phase 5 Threat-Feed Ingestion, Legal Governance, Multi-Level Deduplication,
Domain-Disjoint Splitting, and Benchmark v3 Manifest Persistence.
"""

from pathlib import Path

import pytest

from ml.data.adapters.base import ThreatFeedAdapter
from ml.data.adapters.feed_adapters import (
    AdversarialRedTeamAdapter,
    CloudCDNAdapter,
    OpenPhishAdapter,
    PhishTankAdapter,
    RestrictedFeedTestAdapter,
    TrancoAdapter,
)
from ml.data.deduplication.deduplicator import MultiLevelDeduplicator
from ml.data.normalization.url_normalizer import URLNormalizer
from ml.data.pipeline import BenchmarkV3Builder, ThreatFeedIngestionOrchestrator
from ml.data.schemas.v3 import FeedIngestionStatus, SourceApprovalStatus
from ml.data.splitting.disjoint_splitter import DomainDisjointSplitter
from ml.data.storage.snapshot_manager import SnapshotStorageManager


def test_feed_adapter_protocols_and_governance():
    adapters = [
        TrancoAdapter(),
        OpenPhishAdapter(),
        PhishTankAdapter(),
        CloudCDNAdapter(),
        AdversarialRedTeamAdapter(),
    ]
    for ad in adapters:
        assert isinstance(ad, ThreatFeedAdapter)
        gov = ad.get_governance()
        assert gov.status == SourceApprovalStatus.APPROVED
        assert gov.license_type != ""
        assert gov.source_name != ""
        assert ad.get_feed_status() == FeedIngestionStatus.SUCCESS


def test_restricted_source_blocked_by_governance():
    restricted_ad = RestrictedFeedTestAdapter()
    gov = restricted_ad.get_governance()
    assert gov.status == SourceApprovalStatus.RESTRICTED

    orchestrator = ThreatFeedIngestionOrchestrator()
    orchestrator.adapters.append(restricted_ad)
    records, dq_report, govs, _ = orchestrator.ingest_approved_sources()

    # Restricted source should be marked DISABLED and not contribute to records
    assert dq_report.source_status_summary[gov.source_name] == FeedIngestionStatus.DISABLED
    assert not any("restricted-data.example.com" in r.url_original for r in records)


def test_url_normalizer_views_and_redaction():
    raw_url = (
        "https://auth.example.com:8443/login?token=secret123&utm_source=email&ref=campaign#top"
    )

    # Model input form preserves port, token, path
    model_form = URLNormalizer.to_model_input_form(raw_url)
    assert ":8443" in model_form
    assert "token=secret123" in model_form

    # Dedupe canonical form strips tracking and lowercases
    canon_form = URLNormalizer.to_dedupe_canonical_form(raw_url)
    assert "utm_source" not in canon_form
    assert "token=secret123" in canon_form
    assert "#top" not in canon_form

    # Redaction mode masks sensitive token
    redacted = URLNormalizer.redact_sensitive_params(raw_url)
    assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted
    assert "secret123" not in redacted


def test_multilevel_deduplicator_levels():
    raw = [
        {"url": "https://test.com/login?utm_source=1", "label": 0},
        {"url": "https://test.com/login?utm_source=2", "label": 0},  # Level 3 duplicate
        {"url": "https://test.com/login?utm_source=3", "label": 1},  # Conflict
        {"url": "https://other.com/portal", "label": 0},
    ]
    res = MultiLevelDeduplicator.process_records(raw)
    assert res.level3_tracking_duplicates >= 1
    assert res.conflicting_labels_count == 1
    assert len(res.unique_records) == 2


def test_domain_disjoint_splitter_guarantees():
    orchestrator = ThreatFeedIngestionOrchestrator()
    records, _, _, _ = orchestrator.ingest_approved_sources()

    splits, manifest = DomainDisjointSplitter.create_4way_split(records, seed=42)
    assert manifest.disjoint_guarantee_verified is True
    assert manifest.final_test_frozen is True

    train_doms = {r.registered_domain for r in splits["TRAIN"]}
    cal_doms = {r.registered_domain for r in splits["CALIBRATION"]}
    val_doms = {r.registered_domain for r in splits["VALIDATION"]}
    test_doms = {r.registered_domain for r in splits["FINAL_TEST"]}

    assert train_doms.isdisjoint(cal_doms)
    assert train_doms.isdisjoint(val_doms)
    assert train_doms.isdisjoint(test_doms)
    assert cal_doms.isdisjoint(val_doms)
    assert cal_doms.isdisjoint(test_doms)
    assert val_doms.isdisjoint(test_doms)


@pytest.mark.asyncio
async def test_benchmark_v3_manifest_generation():
    res = await BenchmarkV3Builder.build_benchmark_v3()
    assert res["quality_report"]["benchmark_id"] == "url_benchmark_v3"
    assert res["split_manifest"]["final_test_frozen"] is True
    assert res["throughput"]["preprocessing_records_per_sec"] > 0

    benchmark_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks"
    assert (benchmark_dir / "dataset_manifest_v3.json").exists()

    reports_dir = Path(__file__).resolve().parents[1] / "ml" / "data" / "reports"
    assert (reports_dir / "dataset_quality_report_v3.json").exists()
    assert (reports_dir / "conflict_report_v3.json").exists()
