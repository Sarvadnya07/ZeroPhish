"""
Unit tests for Phase 18 Operator-Approved 100% Shadow Review.
"""

from pathlib import Path

import pytest

from ml.shadow.rollout_100_evaluator import Rollout100Evaluator


@pytest.mark.asyncio
async def test_rollout_100_evaluator():
    res = await Rollout100Evaluator.run_100_percent_rollout(
        canary_target=1000,
        sample_rate=1.00,
    )
    assert res["status"] == "ROLLOUT_100_HEALTHY_VALIDATED"
    assert res["canary_observations"] == 1000
    assert res["total_requests"] == 1000
    assert res["onnx_invocations"] == 100
    assert res["urlbert_invocations"] == 50
    assert res["critical_false_negatives"] == 0
    assert "A. 100% SHADOW HEALTHY" in res["recommendation"]

    rollout100_dir = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "rollout_100"
    )
    assert (rollout100_dir / "rollout_manifest.json").exists()
    assert (rollout100_dir / "preflight_report.json").exists()
    assert (rollout100_dir / "canary_report.json").exists()
    assert (rollout100_dir / "stage_distribution.json").exists()
    assert (rollout100_dir / "invocation_rates.json").exists()
    assert (rollout100_dir / "latency_report.json").exists()
    assert (rollout100_dir / "resource_report.json").exists()
    assert (rollout100_dir / "disagreement_report.json").exists()
    assert (rollout100_dir / "temporal_stability.json").exists()
    assert (rollout100_dir / "privacy_audit.json").exists()
    assert (rollout100_dir / "restart_recovery.json").exists()
    assert (rollout100_dir / "promotion_gate.json").exists()
    assert (rollout100_dir / "final_report.md").exists()
