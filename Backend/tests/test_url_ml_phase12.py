"""
Unit tests for Phase 12 Extended Cascade Shadow Evaluation,
Rollout Gate Simulations (10%, 25%, 50%, 100%), Metrics Aggregation, and Privacy Auditing.
"""

from pathlib import Path

import pytest

from ml.shadow.config import RolloutStage, ShadowConfig, ShadowMode
from ml.shadow.metrics import ShadowMetricsAggregator
from ml.shadow.models import DisagreementTaxonomy, ExtendedShadowObservation, ShadowStatus
from ml.shadow.retention import ShadowRetentionBuffer
from ml.shadow.service import ExtendedShadowService


def test_shadow_config_defaults_and_env(monkeypatch):
    monkeypatch.setenv("ZEROPHISH_CASCADE_SHADOW_MODE", "STAGING")
    monkeypatch.setenv("ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE", "0.25")
    cfg = ShadowConfig.from_env()
    assert cfg.mode == ShadowMode.STAGING
    assert cfg.sample_rate == 0.25
    assert cfg.timeout_ms == 2000
    assert cfg.max_concurrency == 10


def test_shadow_metrics_and_privacy_audit():
    obs1 = ExtendedShadowObservation(
        observation_id="obs_1",
        timestamp="2026-08-24T00:00:00Z",
        environment="staging",
        sample_rate=1.0,
        production_verdict="SAFE",
        production_score=10.0,
        cascade_verdict="SAFE",
        cascade_score=10.0,
        stage_reached="STAGE_HEURISTICS",
        heuristics_resolved=True,
        onnx_invoked=False,
        urlbert_invoked=False,
        status=ShadowStatus.SUCCESS,
        total_latency_ms=0.20,
        disagreement_type=DisagreementTaxonomy.MATCH,
        url_hash="a" * 64,
        hostname_hash="b" * 64,
    )

    summary = ShadowMetricsAggregator.compute_summary([obs1])
    assert summary["total_observations"] == 1
    assert summary["urlbert_invocation_pct"] == 0.0
    assert summary["heuristic_resolution_pct"] == 100.0
    assert summary["disagreement_pct"] == 0.0
    assert summary["potential_fn_count"] == 0

    assert ShadowRetentionBuffer.audit_privacy([obs1]) is True


@pytest.mark.asyncio
async def test_rollout_gate_simulation_all_stages():
    test_samples = [
        ("https://google.com/", "SAFE", 5.0),
        ("http://127.0.0.1/admin", "CRITICAL", 100.0),
    ]
    g10 = await ExtendedShadowService.evaluate_rollout_gate(
        RolloutStage.STAGE_10, 0.10, test_samples
    )
    assert g10.gate_passed is True
    assert g10.potential_fn_count == 0

    g100 = await ExtendedShadowService.evaluate_rollout_gate(
        RolloutStage.STAGE_100, 1.00, test_samples
    )
    assert g100.gate_passed is True
    assert g100.potential_fn_count == 0


@pytest.mark.asyncio
async def test_shadow_service_async_and_graceful_shutdown():
    service = ExtendedShadowService(config=ShadowConfig(mode=ShadowMode.STAGING, sample_rate=1.0))
    task = service.observe_async("https://example.com/", "SAFE", 10.0)
    assert task is not None
    await service.graceful_shutdown()
    assert len(service._active_tasks) == 0


@pytest.mark.asyncio
async def test_all_shadow_benchmark_artifacts_exist():
    res = await ExtendedShadowService.generate_all_shadow_artifacts()
    assert "g10" in res
    assert "g100" in res

    shadow_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow"
    assert (shadow_dir / "rollout_10.json").exists()
    assert (shadow_dir / "rollout_25.json").exists()
    assert (shadow_dir / "rollout_50.json").exists()
    assert (shadow_dir / "rollout_100.json").exists()
    assert (shadow_dir / "performance_report.json").exists()
    assert (shadow_dir / "resource_report.json").exists()
    assert (shadow_dir / "disagreement_report.json").exists()
    assert (shadow_dir / "privacy_audit.json").exists()
    assert (shadow_dir / "final_shadow_report.md").exists()
