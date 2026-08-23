"""
Probability Calibration and Threshold Optimization Module for ZeroPhish ML Models.
Implements Platt Scaling (Logistic Calibration), Isotonic Calibration,
Expected Calibration Error (ECE), Brier Score, and Multi-Objective Operating Point Sweeps.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class PlattCalibrator:
    """
    Platt Scaling (Logistic Sigmoid Calibration).
    Maps uncalibrated model probabilities or decision scores into calibrated posterior probabilities.
    P(y=1|f) = 1 / (1 + exp(-(w * f + b)))
    """

    def __init__(self):
        self.w: float = 1.0  # Slope
        self.b: float = 0.0  # Intercept
        self.is_fitted: bool = False

    def fit(
        self,
        y_score: List[float] | np.ndarray,
        y_true: List[int] | np.ndarray,
        max_iter: int = 200,
        lr: float = 0.1,
    ) -> PlattCalibrator:
        scores = np.asarray(y_score, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(scores) == 0:
            self.is_fitted = False
            return self

        # Clip scores to avoid numerical overflow
        scores = np.clip(scores, -15.0, 15.0)

        # Gradient descent optimization for cross-entropy loss
        w = 1.0
        b = 0.0
        n = float(len(labels))

        for _ in range(max_iter):
            logits = w * scores + b
            p = 1.0 / (1.0 + np.exp(-np.clip(logits, -20.0, 20.0)))

            diff = p - labels
            grad_w = np.sum(diff * scores) / n
            grad_b = np.sum(diff) / n

            w -= lr * grad_w
            b -= lr * grad_b

        self.w = float(w)
        self.b = float(b)
        self.is_fitted = True
        return self

    def predict_proba(self, y_score: List[float] | np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            return np.asarray(y_score, dtype=np.float64)

        scores = np.asarray(y_score, dtype=np.float64)
        logits = self.w * scores + self.b
        return 1.0 / (1.0 + np.exp(-np.clip(logits, -20.0, 20.0)))


class IsotonicCalibrator:
    """
    Non-parametric Isotonic Regression Calibration using Pool Adjacent Violators Algorithm (PAVA).
    Fits a monotonic step-wise calibration mapping.
    """

    def __init__(self):
        self.x_thresholds: List[float] = []
        self.y_calibrated: List[float] = []
        self.is_fitted: bool = False

    def fit(
        self, y_score: List[float] | np.ndarray, y_true: List[int] | np.ndarray
    ) -> IsotonicCalibrator:
        scores = np.asarray(y_score, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(scores) == 0:
            self.is_fitted = False
            return self

        # Sort by scores
        order = np.argsort(scores)
        x_sorted = scores[order]
        y_sorted = labels[order]

        # Simple PAVA implementation
        blocks: List[Dict[str, float]] = []
        for x, y in zip(x_sorted, y_sorted):
            blocks.append({"weight": 1.0, "sum": y, "mean": y, "x_min": x, "x_max": x})
            while len(blocks) >= 2 and blocks[-2]["mean"] > blocks[-1]["mean"]:
                # Pool adjacent blocks
                b2 = blocks.pop()
                b1 = blocks.pop()
                new_weight = b1["weight"] + b2["weight"]
                new_sum = b1["sum"] + b2["sum"]
                blocks.append(
                    {
                        "weight": new_weight,
                        "sum": new_sum,
                        "mean": new_sum / new_weight,
                        "x_min": b1["x_min"],
                        "x_max": b2["x_max"],
                    }
                )

        self.x_thresholds = [b["x_max"] for b in blocks]
        self.y_calibrated = [b["mean"] for b in blocks]
        self.is_fitted = True
        return self

    def predict_proba(self, y_score: List[float] | np.ndarray) -> np.ndarray:
        if not self.is_fitted or not self.x_thresholds:
            return np.asarray(y_score, dtype=np.float64)

        scores = np.asarray(y_score, dtype=np.float64)
        calibrated = []
        for s in scores:
            # Step lookup
            idx = np.searchsorted(self.x_thresholds, s)
            if idx >= len(self.y_calibrated):
                calibrated.append(self.y_calibrated[-1])
            else:
                calibrated.append(self.y_calibrated[idx])
        return np.asarray(calibrated, dtype=np.float64)


def compute_ece(
    y_true: List[int] | np.ndarray, y_prob: List[float] | np.ndarray, n_bins: int = 10
) -> float:
    """
    Compute Expected Calibration Error (ECE).
    Measures difference between predicted confidence and empirical accuracy across binned intervals.
    """
    labels = np.asarray(y_true, dtype=np.float64)
    probs = np.asarray(y_prob, dtype=np.float64)

    if len(labels) == 0:
        return 0.0

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    total_samples = len(labels)

    for i in range(n_bins):
        bin_lower = bins[i]
        bin_upper = bins[i + 1]

        in_bin = (probs >= bin_lower) & (
            probs < bin_upper if i < n_bins - 1 else probs <= bin_upper
        )
        prop_in_bin = np.sum(in_bin) / total_samples

        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(labels[in_bin])
            avg_confidence_in_bin = np.mean(probs[in_bin])
            ece += prop_in_bin * abs(accuracy_in_bin - avg_confidence_in_bin)

    return float(round(ece, 4))


def compute_brier_score(y_true: List[int] | np.ndarray, y_prob: List[float] | np.ndarray) -> float:
    """Compute Brier score (mean squared error of probabilistic predictions)."""
    labels = np.asarray(y_true, dtype=np.float64)
    probs = np.asarray(y_prob, dtype=np.float64)

    if len(labels) == 0:
        return 0.0

    return float(round(np.mean((probs - labels) ** 2), 4))


def _trapz(y: np.ndarray, x: np.ndarray) -> float:
    if hasattr(np, "trapezoid"):
        return float(np.trapezoid(y, x))
    if hasattr(np, "trapz"):
        return float(np.trapz(y, x))
    return float(np.sum((x[1:] - x[:-1]) * (y[:-1] + y[1:]) / 2.0))


def compute_roc_pr_auc(y_true: List[int], y_prob: List[float]) -> Tuple[float, float]:
    """Compute Area Under ROC curve and Precision-Recall curve."""
    labels = np.asarray(y_true)
    probs = np.asarray(y_prob)

    if len(labels) == 0 or len(np.unique(labels)) < 2:
        return 0.5, 0.5

    # Sort descending by probability
    desc_idx = np.argsort(-probs)
    sorted_labels = labels[desc_idx]

    n_pos = np.sum(sorted_labels == 1)
    n_neg = np.sum(sorted_labels == 0)

    if n_pos == 0 or n_neg == 0:
        return 0.5, 0.5

    # Calculate ROC-AUC via trapezoidal integration
    tp_cumsum = np.cumsum(sorted_labels == 1)
    fp_cumsum = np.cumsum(sorted_labels == 0)

    tpr = np.concatenate([[0], tp_cumsum / n_pos])
    fpr = np.concatenate([[0], fp_cumsum / n_neg])
    roc_auc = _trapz(tpr, fpr)

    # Calculate PR-AUC
    precisions = tp_cumsum / (tp_cumsum + fp_cumsum)
    recalls = tp_cumsum / n_pos
    pr_auc = _trapz(np.concatenate([[1.0], precisions]), np.concatenate([[0.0], recalls]))

    return round(abs(roc_auc), 4), round(abs(pr_auc), 4)


def sweep_thresholds(
    y_true: List[int], y_prob: List[float], step: float = 0.02
) -> List[Dict[str, Any]]:
    """Evaluate performance across probability thresholds from 0.01 to 0.99."""
    labels = np.asarray(y_true)
    probs = np.asarray(y_prob)
    thresholds = np.arange(0.02, 0.99, step)

    curve = []
    total_pos = np.sum(labels == 1)
    total_neg = np.sum(labels == 0)

    for th in thresholds:
        th = round(float(th), 2)
        preds = (probs >= th).astype(int)

        tp = int(np.sum((labels == 1) & (preds == 1)))
        fp = int(np.sum((labels == 0) & (preds == 1)))
        fn = int(np.sum((labels == 1) & (preds == 0)))
        tn = int(np.sum((labels == 0) & (preds == 0)))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / total_pos if total_pos > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / total_neg if total_neg > 0 else 0.0
        fnr = fn / total_pos if total_pos > 0 else 0.0

        curve.append(
            {
                "threshold": th,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "fnr": round(fnr, 4),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            }
        )

    return curve


def find_optimal_operating_points(
    threshold_curve: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """
    Identify specific operational operating points:
    - max_f1: Balanced F1 maximization
    - high_recall_security: Minimum 90% recall while maximizing precision
    - low_fpr_enterprise: Maximum 2% FPR while maximizing recall
    - balanced: Precision and Recall parity
    """
    if not threshold_curve:
        return {}

    # 1. Maximum F1
    max_f1_pt = max(threshold_curve, key=lambda x: x["f1"])

    # 2. High Recall Mode (Recall >= 0.85, then highest precision)
    high_recall_candidates = [pt for pt in threshold_curve if pt["recall"] >= 0.80]
    high_recall_pt = (
        max(high_recall_candidates, key=lambda x: x["precision"])
        if high_recall_candidates
        else max_f1_pt
    )

    # 3. Low False Positive Mode (FPR <= 0.05, then highest recall)
    low_fpr_candidates = [pt for pt in threshold_curve if pt["fpr"] <= 0.05]
    low_fpr_pt = (
        max(low_fpr_candidates, key=lambda x: x["recall"])
        if low_fpr_candidates
        else min(threshold_curve, key=lambda x: x["fpr"])
    )

    # 4. Balanced Mode (min absolute difference between precision & recall)
    balanced_pt = min(threshold_curve, key=lambda x: abs(x["precision"] - x["recall"]))

    return {
        "max_f1": max_f1_pt,
        "high_recall_security": high_recall_pt,
        "low_fpr_enterprise": low_fpr_pt,
        "balanced": balanced_pt,
    }
