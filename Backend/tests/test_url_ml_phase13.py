"""
Unit tests for Phase 13 Real Staging Shadow Evaluation, Granular Tail-Latency Forensics,
Cold vs Warm Isolation, Data Provenance Tagging, and Non-Interfering Client Latency.
"""

from pathlib import Path

import pytest

from ml.shadow.staging import StagingShadowEngine


@pytest.mark.asyncio
async def test_granular_latency_instrumentation_profile():
    obs = await StagingShadowEngine.profile_observation_latency(
        url="https://google.com/search?q=test",
        production_verdict="SAFE",
        production_score=5.0,
        is_cold_start=False,
    )
    assert obs.data_provenance == "REAL_STAGING"
    assert obs.preprocessing_ms >= 0.0
    assert obs.heuristic_ms >= 0.0
    assert obs.total_wall_ms >= 0.0
    assert obs.is_cold_start is False
    assert len(obs.url_hash) == 64


@pytest.mark.asyncio
async def test_real_staging_shadow_evaluation_and_artifacts():
    res = await StagingShadowEngine.evaluate_real_staging_shadow(count=50)

    assert res["total_observations_count"] == 50
    assert res["data_provenance"] == "REAL_STAGING"
    assert res["disagreement_analysis"]["potential_false_negatives"] == 0
    assert res["user_latency_impact"]["user_response_invariance_verified"] is True
    assert "MODEL_LOAD" in res["tail_latency_forensics"]["root_cause_classification"]

    shadow_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow"
    assert (shadow_dir / "staging_shadow_report.json").exists()
    assert (shadow_dir / "staging_shadow_report.md").exists()
