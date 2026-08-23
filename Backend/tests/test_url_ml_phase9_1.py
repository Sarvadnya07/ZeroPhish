"""
Unit tests for Phase 9.1 Forensic Benchmark Integrity Audit, Latency Diagnostics,
Split Isolation Verification, and Reproducibility Validation.
"""

import json
from pathlib import Path

import pytest

from ml.benchmark.benchmark_v5_audit import BenchmarkIntegrityAuditor, LatencyForensicsAuditor


@pytest.mark.asyncio
async def test_latency_forensics_diagnostics():
    sample_urls = [
        "https://google.com/search",
        "http://paypa1-security.com/login",
        "https://github.com/torvalds/linux",
    ]
    res = await LatencyForensicsAuditor.measure_all_components(sample_urls, iterations=10)

    assert "preprocessing" in res
    assert "heuristics" in res
    assert "mock_predictor_measured" in res
    assert "urlbert_actual_model" in res
    assert "onnx_actual_model" in res
    assert "risk_fusion" in res

    # Verify diagnostic difference between mock and real transformer
    assert res["mock_predictor_measured"]["mean_ms"] < 0.1  # Fast in-memory mock
    assert res["urlbert_actual_model"]["mean_ms"] > 5.0  # Real transformer forward pass


@pytest.mark.asyncio
async def test_benchmark_v5_full_integrity_audit():
    audit_res = await BenchmarkIntegrityAuditor.run_full_audit()

    assert "overlap_audit" in audit_res
    assert audit_res["overlap_audit"]["disjoint_guarantee_verified"] is True
    assert audit_res["overlap_audit"]["final_test_holdout_contamination_detected"] is False

    assert "metric_recalc" in audit_res
    assert audit_res["metric_recalc"]["recalculated_on_raw_predictions"] is True

    audit_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "url_benchmark_v5_audit"
    assert (audit_dir / "benchmark_execution_trace.json").exists()
    assert (audit_dir / "latency_audit.json").exists()
    assert (audit_dir / "cohort_overlap_report.json").exists()
    assert (audit_dir / "metric_recalculation.json").exists()
    assert (audit_dir / "calibration_audit.json").exists()
    assert (audit_dir / "threshold_audit.json").exists()
    assert (audit_dir / "fusion_audit.json").exists()
    assert (audit_dir / "data_provenance_audit.json").exists()
    assert (audit_dir / "final_audit_report.md").exists()
