"""
Unit tests for Phase 17 Operator-Approved 50% Shadow Scaling & Resource Safety.
"""

from pathlib import Path

import pytest

from ml.shadow.rollout_50_evaluator import Rollout50Evaluator


@pytest.mark.asyncio
async def test_rollout_50_evaluator():
    res = await Rollout50Evaluator.run_50_percent_rollout(
        canary_target=1000,
        sample_rate=0.50,
    )
    assert res["status"] == "ROLLOUT_50_HEALTHY_VALIDATED"
    assert res["canary_observations"] == 1000
    assert res["total_requests"] == 2000
    assert res["onnx_invocations"] == 100
    assert res["urlbert_invocations"] == 50
    assert res["critical_false_negatives"] == 0

    rollout50_dir = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "rollout_50"
    )
    assert (rollout50_dir / "rollout_manifest.json").exists()
    assert (rollout50_dir / "preflight_report.json").exists()
    assert (rollout50_dir / "canary_report.json").exists()
    assert (rollout50_dir / "resource_scaling.json").exists()
    assert (rollout50_dir / "latency_comparison.json").exists()
    assert (rollout50_dir / "stage_distribution.json").exists()
    assert (rollout50_dir / "invocation_rates.json").exists()
    assert (rollout50_dir / "disagreement_report.json").exists()
    assert (rollout50_dir / "privacy_audit.json").exists()
    assert (rollout50_dir / "restart_recovery.json").exists()
    assert (rollout50_dir / "promotion_gate.json").exists()
    assert (rollout50_dir / "final_report.md").exists()
