"""
Unit tests for Phase 7 Bulk Threat-Feed Acquisition, Granular Network Telemetry,
Operational Mode Reporting, and Immutable url_benchmark_v4 Release Validation.
"""

import json
from pathlib import Path

import pytest

from ml.data.adapters.feed_adapters import (
    AdversarialRedTeamAdapter,
    CloudCDNAdapter,
    OpenPhishAdapter,
    PhishTankAdapter,
    TrancoAdapter,
)
from ml.data.pipeline import BenchmarkV3Builder
from ml.data.schemas.v3 import AdapterOperationalMode, FeedIngestionStatus
from ml.data.sync import ThreatFeedSyncEngine


def test_adapter_operational_modes():
    t_adapter = TrancoAdapter(mode=AdapterOperationalMode.SAMPLE)
    assert t_adapter.mode == AdapterOperationalMode.SAMPLE
    gov = t_adapter.get_governance()
    assert gov.operational_mode == AdapterOperationalMode.SAMPLE

    records = t_adapter.fetch_records()
    assert len(records) > 0
    assert hasattr(t_adapter, "last_telemetry")
    assert t_adapter.last_telemetry.total_sync_ms >= 0.0


def test_telemetry_breakdown_separation():
    op_adapter = OpenPhishAdapter(mode=AdapterOperationalMode.SAMPLE)
    records = op_adapter.fetch_records()
    assert len(records) > 0
    tel = op_adapter.last_telemetry
    assert tel.http_status == 200
    assert tel.bytes_downloaded > 0
    assert tel.content_parse_ms >= 0.0


def test_sync_engine_records_operational_mode(tmp_path):
    engine = ThreatFeedSyncEngine(data_dir=tmp_path, default_mode=AdapterOperationalMode.SAMPLE)
    res = engine.sync_source("openphish")
    assert res["status"] == "SUCCESS"
    assert (
        res["operational_mode"] == "AdapterOperationalMode.SAMPLE"
        or "SAMPLE" in res["operational_mode"]
    )


@pytest.mark.asyncio
async def test_url_benchmark_v4_release_manifests():
    res = await BenchmarkV3Builder.build_benchmark_v3(version="v4")
    assert res["quality_report"]["benchmark_id"] == "url_benchmark_v4"
    assert res["split_manifest"]["final_test_frozen"] is True

    b4_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "url_benchmark_v4"
    assert (b4_dir / "dataset_manifest.json").exists()
    assert (b4_dir / "source_manifest.json").exists()
    assert (b4_dir / "split_manifest.json").exists()
    assert (b4_dir / "evaluation_results.json").exists()
    assert (b4_dir / "calibration_results.json").exists()
    assert (b4_dir / "threshold_results.json").exists()
    assert (b4_dir / "error_analysis.json").exists()

    # Verify historical benchmarks remain intact
    b_root = Path(__file__).resolve().parents[1] / "ml" / "benchmarks"
    assert (b_root / "dataset_manifest_v2.json").exists()
    assert (b_root / "dataset_manifest_v3.json").exists()
