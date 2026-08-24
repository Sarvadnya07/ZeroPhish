"""
Unit tests for Phase 14.2 Staging Performance, Trace Profiling,
Shadow ON vs OFF Comparison, and Deep-Path ONNX/URLBERT Model Invocation Validation.
"""

from pathlib import Path

import pytest

from ml.cascade import CascadeStage, URLDetectionCascade
from ml.shadow.deep_path import DeepPathValidator


@pytest.mark.asyncio
async def test_deep_path_onnx_and_urlbert_invocations():
    cascade = URLDetectionCascade()

    # Ambiguous Heuristics -> Stage 3 (ONNX invoked)
    res_onnx = await cascade.predict_cascade("https://xn--portal-login.com/session/restore")
    assert res_onnx.onnx_invoked is True
    assert res_onnx.urlbert_invoked is False
    assert res_onnx.stage_reached == CascadeStage.STAGE_ONNX

    # Ambiguous ONNX -> Stage 4 (URLBERT invoked)
    res_bert = await cascade.predict_cascade("https://xn--warning-portal.com/verify?account=9918")
    assert res_bert.onnx_invoked is True
    assert res_bert.urlbert_invoked is True
    assert res_bert.stage_reached == CascadeStage.STAGE_URLBERT


@pytest.mark.asyncio
async def test_deep_path_validator_evaluates_and_generates_artifacts():
    res = await DeepPathValidator.evaluate_deep_path(count_per_mode=10)
    assert res["status"] == "DEEP_PATH_VALID"
    assert res["onnx_invocations"] >= 1
    assert res["urlbert_invocations"] >= 1
    assert res["shadow_overhead_ms"] < 1.0  # Overhead is strictly sub-millisecond

    perf_dir = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "staging_performance"
    )
    assert (perf_dir / "trace_breakdown.json").exists()
    assert (perf_dir / "shadow_comparison.json").exists()
    assert (perf_dir / "deep_path_validation.json").exists()
    assert (perf_dir / "stage_distribution.json").exists()
    assert (perf_dir / "resource_profile.json").exists()
    assert (perf_dir / "final_report.md").exists()
