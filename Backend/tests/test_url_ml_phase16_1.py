"""
Unit tests for Phase 16.1 25% Shadow Rollout Integrity & Measurement Audit.
"""

from pathlib import Path

import pytest

from ml.shadow.rollout_25_audit import Rollout25AuditEngine


def test_rollout_25_audit_engine():
    res = Rollout25AuditEngine.audit_rollout_25()
    assert res["audit_status"] == "PHASE_16_VALID"
    assert res["classification"] == "A. PHASE 16 VALID - READY FOR 50% REVIEW"
    assert res["sampling_audit"]["canary_rate"] == 0.25
    assert res["sampling_audit"]["extended_rate"] == 0.25
    assert res["sampling_audit"]["combined_rate"] == 0.25
    assert res["stage_distribution_audit"]["hard_rule_pct"] == 15.0
    assert res["stage_distribution_audit"]["heuristic_pct"] == 70.0
    assert res["stage_distribution_audit"]["onnx_pct"] == 10.0
    assert res["stage_distribution_audit"]["urlbert_pct"] == 5.0
    assert res["security_audit"]["critical_false_negatives"] == 0
    assert res["privacy_audit"]["status"] == "PASS"

    audit_json = (
        Path(__file__).resolve().parents[2]
        / "Backend"
        / "ml"
        / "benchmarks"
        / "shadow"
        / "rollout_25"
        / "audit_report.json"
    )
    assert audit_json.exists()
