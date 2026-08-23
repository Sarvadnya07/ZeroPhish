"""
Unit tests for Phase 3 Multi-Source Evaluation, Registered Domain Extraction,
Newton-Raphson Platt Calibration, Bootstrap CIs, and McNemar Significance Testing.
"""

from pathlib import Path

import numpy as np
import pytest

from ml.benchmark.dataset_pipeline import DatasetPipeline
from ml.benchmark.external_dataset import SOURCE_REGISTRY, get_multi_source_benchmark_corpus
from ml.calibration import (
    PlattCalibrator,
    TemperatureScalingCalibrator,
    compute_bootstrap_confidence_intervals,
    compute_cost_sensitive_threshold,
    paired_mcnemar_test,
    sweep_thresholds,
)


def test_source_registry_completeness():
    assert "tranco_top_benign" in SOURCE_REGISTRY
    assert "openphish_community" in SOURCE_REGISTRY
    assert "phishtank_verified" in SOURCE_REGISTRY
    assert "cloud_cdn_benign" in SOURCE_REGISTRY
    assert "adversarial_curated" in SOURCE_REGISTRY

    for key, prov in SOURCE_REGISTRY.items():
        assert prov.license_type != ""
        assert prov.collection_date != ""


def test_registered_domain_extraction():
    assert DatasetPipeline.extract_registered_domain("sub.example.com") == "example.com"
    assert DatasetPipeline.extract_registered_domain("deep.nested.portal.co.uk") == "portal.co.uk"
    assert DatasetPipeline.extract_registered_domain("app.gov.br") == "app.gov.br"
    assert DatasetPipeline.extract_registered_domain("localhost") == "localhost"


def test_multi_source_corpus_loading():
    corpus = get_multi_source_benchmark_corpus()
    assert len(corpus) >= 40
    samples, report = DatasetPipeline.prepare_dataset(corpus)

    assert len(samples) > 0
    assert report.unique_registered_domains > 0
    assert report.benign_count > 0
    assert report.phishing_count > 0


def test_newton_raphson_platt_calibration_non_identity():
    # Synthetic biased scores where ground truth demands non-identity w and b
    y_scores = np.array([-5.0, -4.0, -3.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    y_true = np.array([0, 0, 0, 1, 1, 1, 1, 1])

    calibrator = PlattCalibrator().fit(y_scores, y_true)
    assert calibrator.is_fitted is True
    # Verify non-trivial fitted slope and intercept
    assert calibrator.w != 0.0
    assert calibrator.b != 0.0

    probs = calibrator.predict_proba([-5.0, 5.0])
    assert probs[0] < 0.05
    assert probs[1] > 0.95


def test_temperature_scaling_calibrator():
    y_logits = np.array([-2.0, -1.0, 1.0, 2.0])
    y_true = np.array([0, 0, 1, 1])

    calibrator = TemperatureScalingCalibrator().fit(y_logits, y_true)
    assert calibrator.is_fitted is True
    assert calibrator.temperature > 0.0

    probs = calibrator.predict_proba(y_logits)
    assert probs[0] < probs[3]


def test_bootstrap_confidence_intervals():
    y_true = [0, 0, 0, 0, 1, 1, 1, 1]
    y_prob = [0.1, 0.15, 0.2, 0.25, 0.8, 0.85, 0.9, 0.95]

    cis = compute_bootstrap_confidence_intervals(y_true, y_prob, threshold=0.5, n_bootstraps=100)
    assert "f1" in cis
    assert "precision" in cis
    assert "recall" in cis
    assert "fpr" in cis

    assert 0.0 <= cis["f1"]["ci_low"] <= cis["f1"]["ci_high"] <= 1.0


def test_paired_mcnemar_significance():
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    # Classifier A gets 7/8 right
    pred_a = [1, 1, 1, 1, 0, 0, 0, 1]
    # Classifier B gets 4/8 right
    pred_b = [0, 0, 1, 1, 1, 1, 0, 0]

    res = paired_mcnemar_test(y_true, pred_a, pred_b)
    assert "statistic" in res
    assert "p_value" in res
    assert "significant" in res
    assert res["b_model_a_superior"] > res["c_model_b_superior"]


def test_cost_sensitive_threshold_optimization():
    y_true = [0, 0, 0, 1, 1, 1]
    y_prob = [0.05, 0.10, 0.20, 0.60, 0.70, 0.80]

    curve = sweep_thresholds(y_true, y_prob, step=0.1)
    best_pt = compute_cost_sensitive_threshold(curve, cost_fn=10.0, cost_fp=1.0)

    assert "threshold" in best_pt
    assert "expected_cost" in best_pt
    # Under high cost of false negatives (10.0), threshold favors higher recall
    assert best_pt["threshold"] <= 0.60


def test_benchmark_artifacts_generation():
    artifact_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks"
    assert (artifact_dir / "dataset_manifest.json").exists()
    assert (artifact_dir / "evaluation_results.json").exists()
    assert (artifact_dir / "calibration_results.json").exists()
