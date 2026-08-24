"""
Unit tests for Phase 13.1 Genuine Staging Shadow Observation, Traffic Provenance Enforcement,
24-Hour Window & Minimum Observation Gates, and Artifact Integrity.
"""

from pathlib import Path

import pytest

from ml.shadow.models import DisagreementTaxonomy, ExtendedShadowObservation, ShadowStatus
from ml.shadow.real_staging import RealStagingTelemetryValidator


def test_traffic_provenance_validation():
    valid_obs = ExtendedShadowObservation(
        observation_id="obs_valid",
        timestamp="2026-08-24T12:00:00Z",
        environment="staging",
        data_provenance="REAL_STAGING",
        sample_rate=0.10,
        production_verdict="SAFE",
        production_score=10.0,
        status=ShadowStatus.SUCCESS,
        total_latency_ms=0.20,
        url_hash="a" * 64,
        hostname_hash="b" * 64,
    )
    assert RealStagingTelemetryValidator.validate_provenance(valid_obs) is True

    replay_obs = ExtendedShadowObservation(
        observation_id="obs_replay",
        timestamp="2026-08-24T12:00:00Z",
        environment="staging",
        data_provenance="BENCHMARK_REPLAY",
        sample_rate=0.10,
        production_verdict="SAFE",
        production_score=10.0,
        status=ShadowStatus.SUCCESS,
        total_latency_ms=0.20,
        url_hash="a" * 64,
        hostname_hash="b" * 64,
    )
    assert RealStagingTelemetryValidator.validate_provenance(replay_obs) is False


@pytest.mark.asyncio
async def test_insufficient_real_staging_traffic_gate():
    # When zero observations exist, validator must report INSUFFICIENT_REAL_STAGING_EVIDENCE
    res = await RealStagingTelemetryValidator.evaluate_real_staging_corpus(observations=[])
    assert res["summary"]["total_observations"] == 0
    assert res["summary"]["gate_status"] == "INSUFFICIENT_REAL_STAGING_EVIDENCE"
    assert res["gate_report"]["recommended_action"] == "REMAIN_AT_10_PERCENT_SHADOW"


@pytest.mark.asyncio
async def test_promotion_gate_with_sufficient_corpus():
    # Build 1000 valid synthetic test staging observations to verify gate logic
    corpus = [
        ExtendedShadowObservation(
            observation_id=f"obs_{i}",
            timestamp="2026-08-24T12:00:00Z",
            environment="staging",
            data_provenance="REAL_STAGING",
            sample_rate=0.10,
            production_verdict="SAFE",
            production_score=10.0,
            cascade_verdict="SAFE",
            cascade_score=10.0,
            stage_reached="STAGE_HEURISTICS",
            heuristics_resolved=True,
            status=ShadowStatus.SUCCESS,
            total_latency_ms=0.20,
            disagreement_type=DisagreementTaxonomy.MATCH,
            url_hash="a" * 64,
            hostname_hash="b" * 64,
        )
        for i in range(1000)
    ]
    res = await RealStagingTelemetryValidator.evaluate_real_staging_corpus(
        observations=corpus, window_hours=24.0
    )
    assert res["summary"]["total_observations"] == 1000
    assert res["summary"]["gate_status"] == "READY_FOR_25_PERCENT"
    assert res["gate_report"]["promotion_eligible"] is True


@pytest.mark.asyncio
async def test_staging_real_artifacts_exist():
    _ = await RealStagingTelemetryValidator.evaluate_real_staging_corpus()
    staging_dir = (
        Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow" / "staging_real"
    )
    assert (staging_dir / "window_manifest.json").exists()
    assert (staging_dir / "observation_summary.json").exists()
    assert (staging_dir / "stage_distribution.json").exists()
    assert (staging_dir / "invocation_rates.json").exists()
    assert (staging_dir / "latency_report.json").exists()
    assert (staging_dir / "disagreement_report.json").exists()
    assert (staging_dir / "resource_report.json").exists()
    assert (staging_dir / "privacy_audit.json").exists()
    assert (staging_dir / "stability_report.json").exists()
    assert (staging_dir / "promotion_gate.json").exists()
    assert (staging_dir / "final_report.md").exists()
