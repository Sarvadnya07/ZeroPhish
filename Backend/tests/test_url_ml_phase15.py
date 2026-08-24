"""
Unit tests for Phase 15 Large External Staging Shadow Evaluation,
Reconciliation of >=1,000 Observations, Deep-Path Invocation Rates,
Temporal Stability, and Privacy Audit.
"""

from pathlib import Path

import pytest

from ml.shadow.large_evaluator import LargeStagingShadowEvaluator


@pytest.mark.asyncio
async def test_large_staging_shadow_evaluation():
    res = await LargeStagingShadowEvaluator.evaluate_large_shadow_workload(
        target_observations=1000,
        sample_rate=0.10,
    )
    assert res["status"] == "LARGE_EXTERNAL_SHADOW_VERIFIED"
    assert res["target_observations"] == 1000
    assert res["total_requests"] == 10000
    assert res["onnx_invocations"] == 100
    assert res["urlbert_invocations"] == 50
    assert res["critical_false_negatives"] == 0
    assert res["recommendation"] == "B. REMAIN AT 10% SHADOW"

    large_dir = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "large_external"
    )
    assert (large_dir / "run_manifest.json").exists()
    assert (large_dir / "request_accounting.json").exists()
    assert (large_dir / "stage_distribution.json").exists()
    assert (large_dir / "invocation_rates.json").exists()
    assert (large_dir / "latency_report.json").exists()
    assert (large_dir / "shadow_overhead.json").exists()
    assert (large_dir / "disagreement_report.json").exists()
    assert (large_dir / "resource_report.json").exists()
    assert (large_dir / "temporal_stability.json").exists()
    assert (large_dir / "model_health.json").exists()
    assert (large_dir / "privacy_audit.json").exists()
    assert (large_dir / "promotion_gate.json").exists()
    assert (large_dir / "final_report.md").exists()
