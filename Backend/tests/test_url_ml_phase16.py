"""
Unit tests for Phase 16 Operator-Approved 25% Shadow Rollout & Stability Validation.
"""

from pathlib import Path

import pytest

from ml.shadow.rollout_25_evaluator import Rollout25Evaluator


@pytest.mark.asyncio
async def test_rollout_25_evaluator():
    res = await Rollout25Evaluator.run_25_percent_rollout(
        canary_target=500,
        extended_target=2500,
        sample_rate=0.25,
    )
    assert res["status"] == "ROLLOUT_25_HEALTHY_VALIDATED"
    assert res["canary_observations"] == 500
    assert res["extended_observations"] == 2500
    assert res["onnx_invocations"] == 250
    assert res["urlbert_invocations"] == 125
    assert res["critical_false_negatives"] == 0

    rollout_dir = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "rollout_25"
    )
    assert (rollout_dir / "rollout_manifest.json").exists()
    assert (rollout_dir / "canary_report.json").exists()
    assert (rollout_dir / "stage_distribution.json").exists()
    assert (rollout_dir / "invocation_rates.json").exists()
    assert (rollout_dir / "latency_report.json").exists()
    assert (rollout_dir / "resource_report.json").exists()
    assert (rollout_dir / "disagreement_report.json").exists()
    assert (rollout_dir / "privacy_audit.json").exists()
    assert (rollout_dir / "stability_report.json").exists()
    assert (rollout_dir / "promotion_gate.json").exists()
    assert (rollout_dir / "final_report.md").exists()
