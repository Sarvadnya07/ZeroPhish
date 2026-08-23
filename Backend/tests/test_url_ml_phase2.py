"""
Unit tests for Phase 2 URL ML Benchmark, Dataset Pipeline, Calibration, and Operating Points.
All tests are 100% deterministic, offline, and verify mathematical calibration guarantees.
"""

import numpy as np
import pytest

from ml.benchmark.dataset_pipeline import (
    BenchmarkSample,
    DatasetPipeline,
    get_curated_benchmark_corpus,
)
from ml.calibration import (
    IsotonicCalibrator,
    PlattCalibrator,
    compute_brier_score,
    compute_ece,
    compute_roc_pr_auc,
    find_optimal_operating_points,
    sweep_thresholds,
)
from ml.fusion import RiskFusionEngine
from ml.url_predictor import MockURLPredictor, ModelHealthState, URLBERTPredictor


def test_dataset_pipeline_tracking_param_stripping():
    raw_url = "https://example.com/login?utm_source=newsletter&user=admin&fbclid=123"
    cleaned = DatasetPipeline.strip_tracking_params(raw_url)
    assert "utm_source" not in cleaned
    assert "fbclid" not in cleaned
    assert "user=admin" in cleaned


def test_dataset_pipeline_deduplication_and_metrics():
    raw_records = [
        ("https://example.com/page1?ref=123", 0, "legit", False),
        ("https://example.com/page1?ref=456", 0, "legit", False),  # Duplicate after param strip
        ("https://phishing.xyz/login", 1, "phish", False),
    ]
    samples, report = DatasetPipeline.prepare_dataset(raw_records)
    assert len(samples) == 2
    assert report.exact_duplicate_count == 1
    assert report.benign_count == 1
    assert report.phishing_count == 1


def test_dataset_domain_disjoint_split_guarantee():
    corpus = get_curated_benchmark_corpus()
    samples, _ = DatasetPipeline.prepare_dataset(corpus)

    train, cal, test = DatasetPipeline.create_domain_disjoint_split(samples, seed=42)

    train_domains = {s.domain for s in train}
    cal_domains = {s.domain for s in cal}
    test_domains = {s.domain for s in test}

    # Verify zero domain leakage between splits
    assert train_domains.isdisjoint(cal_domains)
    assert train_domains.isdisjoint(test_domains)
    assert cal_domains.isdisjoint(test_domains)


def test_platt_calibration_fitting():
    # Synthetic uncalibrated overconfident scores
    y_scores = [-2.0, -1.5, -0.5, 0.5, 1.5, 2.0]
    y_true = [0, 0, 0, 1, 1, 1]

    calibrator = PlattCalibrator().fit(y_scores, y_true)
    assert calibrator.is_fitted is True

    probs = calibrator.predict_proba([-2.0, 2.0])
    assert len(probs) == 2
    assert probs[0] < probs[1]  # Monotonic probability increase
    assert 0.0 <= probs[0] <= 1.0
    assert 0.0 <= probs[1] <= 1.0


def test_isotonic_calibration_fitting():
    y_scores = [0.1, 0.2, 0.4, 0.7, 0.8, 0.9]
    y_true = [0, 0, 0, 1, 1, 1]

    calibrator = IsotonicCalibrator().fit(y_scores, y_true)
    assert calibrator.is_fitted is True

    probs = calibrator.predict_proba([0.1, 0.9])
    assert probs[0] <= probs[1]


def test_calibration_metrics_ece_and_brier():
    y_true = [0, 0, 1, 1]
    y_prob_perfect = [0.0, 0.0, 1.0, 1.0]
    y_prob_imperfect = [0.4, 0.6, 0.4, 0.6]

    # Perfect predictions have 0 ECE and 0 Brier
    assert compute_ece(y_true, y_prob_perfect) == 0.0
    assert compute_brier_score(y_true, y_prob_perfect) == 0.0

    # Imperfect predictions have positive ECE and Brier
    assert compute_ece(y_true, y_prob_imperfect) > 0.0
    assert compute_brier_score(y_true, y_prob_imperfect) > 0.0


def test_roc_pr_auc_calculation():
    y_true = [0, 0, 1, 1]
    y_prob = [0.1, 0.2, 0.8, 0.9]

    roc_auc, pr_auc = compute_roc_pr_auc(y_true, y_prob)
    assert roc_auc == 1.0
    assert pr_auc == 1.0


def test_threshold_sweep_and_operating_points():
    y_true = [0, 0, 0, 1, 1, 1]
    y_prob = [0.05, 0.10, 0.20, 0.75, 0.85, 0.95]

    sweep = sweep_thresholds(y_true, y_prob, step=0.1)
    assert len(sweep) > 0

    points = find_optimal_operating_points(sweep)
    assert "max_f1" in points
    assert "high_recall_security" in points
    assert "low_fpr_enterprise" in points
    assert "balanced" in points
    assert points["max_f1"]["f1"] == 1.0


def test_model_health_state_transitions():
    predictor = MockURLPredictor()
    assert predictor.get_health_state() == ModelHealthState.MODEL_READY

    unloaded = URLBERTPredictor(model_name="nonexistent")
    assert unloaded.get_health_state() in (
        ModelHealthState.MODEL_FALLBACK,
        ModelHealthState.MODEL_UNAVAILABLE,
    )


def test_security_override_precedence_over_ml_probability():
    """Verify that even a 0.0 ML probability cannot downgrade a hard security trigger."""
    fusion = RiskFusionEngine.fuse(
        tier1_score=5.0,
        tier2_score=5.0,  # ML predicts totally safe
        hard_malicious_triggers=["Known active phishing C2 domain"],
    )
    assert fusion.final_score == 95.0
    assert fusion.verdict == "CRITICAL"
    assert fusion.hard_override_applied is not None
