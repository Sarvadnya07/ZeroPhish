"""
Unit tests for Phase 13.2 Controlled Staging Traffic Generator,
Safety Environment Guards, End-to-End API Dispatch, and Artifact Verification.
"""

from pathlib import Path

import pytest

from ml.data.staging_workload import StagingWorkloadGenerator


def test_safety_environment_and_production_guards():
    # 1. Guard against production environment
    with pytest.raises(
        ValueError,
        match="SAFETY VIOLATION: Staging workload generator cannot run against production",
    ):
        StagingWorkloadGenerator(base_url="http://127.0.0.1:8000", env="production")

    # 2. Guard against production base URL
    with pytest.raises(ValueError, match="SAFETY VIOLATION: Refusing to target production domain"):
        StagingWorkloadGenerator(base_url="https://api.zerophish.com", env="staging")


@pytest.mark.asyncio
async def test_staging_workload_generator_end_to_end():
    res = await StagingWorkloadGenerator.run_workload(count=20, rate_rps=100.0)

    assert res["requests_sent"] == 20
    assert res["status"] == "CONTROLLED_STAGING_TRAFFIC_VERIFIED"
    assert res["p50_ms"] >= 0.0
    assert "stage_distribution" in res

    staging_dir = (
        Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow" / "staging_controlled"
    )
    assert (staging_dir / "workload_manifest.json").exists()
    assert (staging_dir / "request_summary.json").exists()
    assert (staging_dir / "stage_distribution.json").exists()
    assert (staging_dir / "invocation_rates.json").exists()
    assert (staging_dir / "latency_report.json").exists()
    assert (staging_dir / "disagreement_report.json").exists()
    assert (staging_dir / "security_subset_report.json").exists()
    assert (staging_dir / "response_invariance_report.json").exists()
    assert (staging_dir / "final_report.md").exists()
