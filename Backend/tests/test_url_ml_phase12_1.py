"""
Unit tests for Phase 12.1 Forensic Shadow Telemetry & Statistical Consistency Audit.
"""

from pathlib import Path

import pytest

from ml.shadow.audit import ShadowTelemetryAuditor
from ml.shadow.config import ShadowConfig, ShadowMode
from ml.shadow.service import ExtendedShadowService


@pytest.mark.asyncio
async def test_shadow_telemetry_forensic_audit():
    res = await ShadowTelemetryAuditor.run_forensic_audit()

    assert res["total_observations"] > 0
    assert "counts" in res
    assert "latency" in res
    assert "discrepancy_diagnosis" in res

    assert "BENCHMARK REPLAY ONLY" in res["discrepancy_diagnosis"]["workload_classification"]

    audit_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow_audit"
    assert (audit_dir / "raw_observations_audit.json").exists()
    assert (audit_dir / "latency_recalculation.json").exists()
    assert (audit_dir / "cpu_savings_recalculation.json").exists()
    assert (audit_dir / "final_shadow_audit_report.md").exists()


@pytest.mark.asyncio
async def test_production_invariance_and_graceful_cleanup():
    cfg = ShadowConfig(mode=ShadowMode.STAGING, sample_rate=1.00)
    service = ExtendedShadowService(config=cfg)

    obs = await service.execute_observation("https://test.com/", "SAFE", 5.0)
    assert obs.production_verdict == "SAFE"

    # Verify graceful shutdown completes without errors
    await service.graceful_shutdown()
    assert len(service._active_tasks) == 0
