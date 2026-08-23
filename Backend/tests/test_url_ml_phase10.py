"""
Unit tests for Phase 10 URL Detection Cascade Simulation, Multi-Stage Execution,
Invocation Reduction Profiling, and Large-Corpus Candidate Evaluation.
"""

import json
from pathlib import Path

import pytest

from ml.benchmark.cascade_evaluator import CascadeEvaluator
from ml.cascade import CascadePredictionResult, CascadeStage, ModelHealthStatus, URLDetectionCascade


@pytest.mark.asyncio
async def test_cascade_hard_security_rule_precedence():
    cascade = URLDetectionCascade()
    res = await cascade.predict_cascade("http://127.0.0.1/admin")
    assert res.stage_reached == CascadeStage.STAGE_HARD_RULE
    assert res.final_score == 100.0
    assert res.verdict == "CRITICAL"
    assert res.onnx_invoked is False
    assert res.urlbert_invoked is False
    assert res.hard_override == "SSRF_PREVENTION"


@pytest.mark.asyncio
async def test_cascade_stages_and_telemetry():
    cascade = URLDetectionCascade()
    res = await cascade.predict_cascade("https://google.com/")
    assert res.stage_reached in (
        CascadeStage.STAGE_HEURISTICS,
        CascadeStage.STAGE_ONNX,
        CascadeStage.STAGE_URLBERT,
    )
    assert res.latency_ms >= 0.0
    assert res.model_health == ModelHealthStatus.MODEL_READY


@pytest.mark.asyncio
async def test_cascade_evaluator_architectures_comparison():
    res = await CascadeEvaluator.evaluate_cascade_architectures(c_fn=10.0, c_fp=1.0, c_ml=0.05)

    assert "Heuristics_Only" in res
    assert "ONNX_Only" in res
    assert "URLBERT_Only" in res
    assert "Full_Hybrid_Heuristics_URLBERT" in res
    assert "Cascade_Heuristics_ONNX_URLBERT" in res

    casc = res["Cascade_Heuristics_ONNX_URLBERT"]
    assert casc["urlbert_invocation_pct"] <= 100.0
    assert casc["fn_safety_violations_count"] == 0
    assert casc["latency_ms"] < res["Full_Hybrid_Heuristics_URLBERT"]["latency_ms"]

    candidate_dir = (
        Path(__file__).resolve().parents[1]
        / "ml"
        / "benchmarks"
        / "url_benchmark_v5_cascade_candidate"
    )
    assert (candidate_dir / "dataset_manifest.json").exists()
    assert (candidate_dir / "cascade_config.json").exists()
    assert (candidate_dir / "cohort_manifest.json").exists()
    assert (candidate_dir / "evaluation_results.json").exists()
    assert (candidate_dir / "latency_results.json").exists()
    assert (candidate_dir / "invocation_results.json").exists()
    assert (candidate_dir / "hard_negative_results.json").exists()
    assert (candidate_dir / "adversarial_results.json").exists()
    assert (candidate_dir / "error_analysis.json").exists()
