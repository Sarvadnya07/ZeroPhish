"""
Unit tests for Phase 10.1 Cascade Integrity Audit, Stage Trace Validation,
Safety Equivalence (Zero Regressions), and Hard Security Determinism.
"""

import json
from pathlib import Path

import pytest

from ml.benchmark.cascade_audit import CascadeIntegrityAuditor
from ml.cascade import CascadeStage, URLDetectionCascade


@pytest.mark.asyncio
async def test_hard_security_tests_determinism():
    cascade = URLDetectionCascade()

    # SSRF / Localhost targets
    ssrf_targets = [
        "http://127.0.0.1/status",
        "http://localhost:8080/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/internal",
    ]
    for target in ssrf_targets:
        res = await cascade.predict_cascade(target)
        assert res.stage_reached == CascadeStage.STAGE_HARD_RULE
        assert res.final_score == 100.0
        assert res.verdict == "CRITICAL"
        assert res.onnx_invoked is False
        assert res.urlbert_invoked is False
        assert res.hard_override == "SSRF_PREVENTION"


@pytest.mark.asyncio
async def test_cascade_full_integrity_audit():
    res = await CascadeIntegrityAuditor.audit_cascade_integrity()

    assert "invocation_rates" in res
    assert "latency" in res
    assert "safety" in res
    assert res["safety"]["cascade_regressions_count"] == 0
    assert res["safety"]["safety_gate_passed"] is True

    candidate_dir = (
        Path(__file__).resolve().parents[1]
        / "ml"
        / "benchmarks"
        / "url_benchmark_v5_cascade_candidate"
    )
    assert (candidate_dir / "stage_trace.json").exists()
    assert (candidate_dir / "safety_equivalence.json").exists()
    assert (candidate_dir / "cascade_integrity_audit.json").exists()
    assert (candidate_dir / "final_cascade_audit_report.md").exists()
