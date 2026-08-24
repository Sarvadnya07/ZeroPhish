"""
Unit tests for Phase 17.1 50% Shadow Rollout Integrity, Freshness & Scaling Audit.
"""

from pathlib import Path

import pytest

from ml.shadow.rollout_50_audit import Rollout50AuditEngine


def test_rollout_50_audit_engine():
    res = Rollout50AuditEngine.audit_rollout_50()
    assert res["audit_status"] == "PHASE_17_VALID_WITH_CORRECTIONS"
    assert res["classification"] == "B. PHASE 17 VALID WITH CORRECTIONS"
    assert res["sampling_audit"]["http_requests_attempted"] == 2000
    assert res["sampling_audit"]["shadow_observations_recorded"] == 1000
    assert res["sampling_audit"]["realized_sample_rate"] == 0.50
    assert "PROJECTION_ONLY" in res["provenance_audit"]["tier_50pct_10k_projection"]
    assert res["stage_distribution_audit"]["hard_rule_pct"] == 15.0
    assert res["stage_distribution_audit"]["heuristic_pct"] == 70.0
    assert res["stage_distribution_audit"]["onnx_pct"] == 10.0
    assert res["stage_distribution_audit"]["urlbert_pct"] == 5.0
    assert res["security_audit"]["critical_false_negatives"] == 0
    assert res["privacy_audit"]["status"] == "PASS"
    assert res["restart_audit"]["status"] == "PASS"

    audit_json = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "rollout_50"
        / "audit_report.json"
    )
    assert audit_json.exists()
