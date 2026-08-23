"""
Probability Calibration, Statistical Inference, and Cost-Sensitive Optimization Module.
Implements Platt Scaling (Newton-Raphson MLE), Temperature Scaling, Isotonic Calibration,
Expected Calibration Error (ECE), Brier Score, Bootstrap Confidence Intervals (95% CI),
Paired McNemar Statistical Significance Tests, and Cost-Sensitive Operating Point Optimization.
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class PlattCalibrator:
    """
    Platt Scaling (Logistic Sigmoid Calibration via Newton-Raphson MLE).
    Maps uncalibrated model scores or raw probabilities into calibrated posterior probabilities.
    P(y=1|s) = 1 / (1 + exp(-(w * s + b)))
    """

    def __init__(self):
        self.w: float = 1.0  # Slope / Weight
        self.b: float = 0.0  # Intercept
        self.is_fitted: bool = False

    def fit(
        self,
        y_score: List[float] | np.ndarray,
        y_true: List[int] | np.ndarray,
        max_iter: int = 50,
        tol: float = 1e-6,
    ) -> PlattCalibrator:
        scores = np.asarray(y_score, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(scores) < 2 or len(np.unique(labels)) < 2:
            self.w = 1.0
            self.b = 0.0
            self.is_fitted = False
            return self

        # Clip scores to avoid numerical overflow
        scores = np.clip(scores, -15.0, 15.0)
        n = float(len(labels))

        # Target smoothing (Platt's original prior: Laplace-smoothed targets)
        n_pos = np.sum(labels == 1.0)
        n_neg = np.sum(labels == 0.0)
        t_pos = (n_pos + 1.0) / (n_pos + 2.0)
        t_neg = 1.0 / (n_neg + 2.0)
        t = np.where(labels == 1.0, t_pos, t_neg)

        # Initial parameters: [w, b]
        theta = np.array([1.0, 0.0], dtype=np.float64)

        # Newton-Raphson optimization
        for _ in range(max_iter):
            # Sigmoid: 1 / (1 + exp(-(w * x + b)))
            z = theta[0] * scores + theta[1]
            p = 1.0 / (1.0 + np.exp(-np.clip(z, -20.0, 20.0)))

            # Variance weights: p * (1 - p)
            var = np.maximum(p * (1.0 - p), 1e-12)

            # Error gradient: g = X^T * (p - t)
            diff = p - t
            grad_w = np.sum(diff * scores)
            grad_b = np.sum(diff)
            grad = np.array([grad_w, grad_b], dtype=np.float64)

            # Hessian matrix: H = X^T * W * X
            h_00 = np.sum(var * scores * scores) + 1e-4  # L2 regularization
            h_01 = np.sum(var * scores)
            h_11 = np.sum(var) + 1e-4

            hessian = np.array([[h_00, h_01], [h_01, h_11]], dtype=np.float64)

            try:
                delta = np.linalg.solve(hessian, grad)
                theta -= delta
                if np.sum(delta**2) < tol:
                    break
            except np.linalg.LinAlgError:
                # Gradient step fallback
                theta -= 0.01 * grad
                break

        self.w = float(theta[0])
        self.b = float(theta[1])
        self.is_fitted = True
        return self

    def predict_proba(self, y_score: List[float] | np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            return np.asarray(y_score, dtype=np.float64)

        scores = np.asarray(y_score, dtype=np.float64)
        logits = self.w * scores + self.b
        return 1.0 / (1.0 + np.exp(-np.clip(logits, -20.0, 20.0)))


class TemperatureScalingCalibrator:
    """
    Temperature Scaling for logit outputs: P(y=1|z) = sigmoid(z / T).
    Learns a single positive scalar temperature parameter T > 0.
    """

    def __init__(self):
        self.temperature: float = 1.0
        self.is_fitted: bool = False

    def fit(
        self,
        y_logits: List[float] | np.ndarray,
        y_true: List[int] | np.ndarray,
        max_iter: int = 100,
        lr: float = 0.05,
    ) -> TemperatureScalingCalibrator:
        logits = np.asarray(y_logits, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(logits) < 2 or len(np.unique(labels)) < 2:
            self.is_fitted = False
            return self

        t = 1.0
        for _ in range(max_iter):
            scaled = logits / max(t, 1e-4)
            p = 1.0 / (1.0 + np.exp(-np.clip(scaled, -20.0, 20.0)))
            diff = p - labels
            grad_t = -np.sum(diff * logits / (max(t, 1e-4) ** 2)) / len(labels)
            t = max(0.01, t - lr * grad_t)

        self.temperature = float(t)
        self.is_fitted = True
        return self

    def predict_proba(self, y_logits: List[float] | np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            return np.asarray(y_logits, dtype=np.float64)
        logits = np.asarray(y_logits, dtype=np.float64)
        scaled = logits / max(self.temperature, 1e-4)
        return 1.0 / (1.0 + np.exp(-np.clip(scaled, -20.0, 20.0)))


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

        blocks: List[Dict[str, float]] = []
        for x, y in zip(x_sorted, y_sorted):
            blocks.append({"weight": 1.0, "sum": y, "mean": y, "x_min": x, "x_max": x})
            while len(blocks) >= 2 and blocks[-2]["mean"] > blocks[-1]["mean"]:
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
            idx = np.searchsorted(self.x_thresholds, s)
            if idx >= len(self.y_calibrated):
                calibrated.append(self.y_calibrated[-1])
            else:
                calibrated.append(self.y_calibrated[idx])
        return np.asarray(calibrated, dtype=np.float64)


def compute_ece(
    y_true: List[int] | np.ndarray, y_prob: List[float] | np.ndarray, n_bins: int = 10
) -> float:
    """Compute Expected Calibration Error (ECE)."""
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
    """Identify operational operating points."""
    if not threshold_curve:
        return {}

    max_f1_pt = max(threshold_curve, key=lambda x: x["f1"])
    high_recall_candidates = [pt for pt in threshold_curve if pt["recall"] >= 0.80]
    high_recall_pt = (
        max(high_recall_candidates, key=lambda x: x["precision"])
        if high_recall_candidates
        else max_f1_pt
    )

    low_fpr_candidates = [pt for pt in threshold_curve if pt["fpr"] <= 0.05]
    low_fpr_pt = (
        max(low_fpr_candidates, key=lambda x: x["recall"])
        if low_fpr_candidates
        else min(threshold_curve, key=lambda x: x["fpr"])
    )

    balanced_pt = min(threshold_curve, key=lambda x: abs(x["precision"] - x["recall"]))

    return {
        "max_f1": max_f1_pt,
        "high_recall_security": high_recall_pt,
        "low_fpr_enterprise": low_fpr_pt,
        "balanced": balanced_pt,
    }


def compute_cost_sensitive_threshold(
    threshold_curve: List[Dict[str, Any]],
    cost_fn: float = 10.0,
    cost_fp: float = 1.0,
) -> Dict[str, Any]:
    """
    Find threshold minimizing expected business loss:
    Loss = (FN * cost_fn) + (FP * cost_fp)
    """
    if not threshold_curve:
        return {"threshold": 0.5, "expected_cost": 0.0}

    scored_points = []
    for pt in threshold_curve:
        fn = pt.get("fn", 0)
        fp = pt.get("fp", 0)
        total_cost = (fn * cost_fn) + (fp * cost_fp)
        scored_points.append({**pt, "expected_cost": total_cost})

    best_pt = min(scored_points, key=lambda x: x["expected_cost"])
    return best_pt


def compute_bootstrap_confidence_intervals(
    y_true: List[int],
    y_prob: List[float],
    threshold: float = 0.50,
    n_bootstraps: int = 500,
    alpha: float = 0.05,
    seed: int = 42,
) -> Dict[str, Dict[str, float]]:
    """
    Empirical bootstrap estimation of 95% Confidence Intervals for F1, Precision, Recall, and FPR.
    """
    labels = np.asarray(y_true)
    probs = np.asarray(y_prob)
    n = len(labels)

    if n < 5:
        return {}

    rng = np.random.default_rng(seed)
    f1_boot, prec_boot, rec_boot, fpr_boot = [], [], [], []

    for _ in range(n_bootstraps):
        idx = rng.choice(n, size=n, replace=True)
        sample_y = labels[idx]
        sample_prob = probs[idx]
        preds = (sample_prob >= threshold).astype(int)

        tp = np.sum((sample_y == 1) & (preds == 1))
        fp = np.sum((sample_y == 0) & (preds == 1))
        fn = np.sum((sample_y == 1) & (preds == 0))
        tn = np.sum((sample_y == 0) & (preds == 0))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        f1_boot.append(f1)
        prec_boot.append(prec)
        rec_boot.append(rec)
        fpr_boot.append(fpr)

    def _ci(arr):
        low = np.percentile(arr, 100 * (alpha / 2))
        high = np.percentile(arr, 100 * (1 - alpha / 2))
        return {
            "mean": round(float(np.mean(arr)), 4),
            "ci_low": round(float(low), 4),
            "ci_high": round(float(high), 4),
        }

    return {
        "f1": _ci(f1_boot),
        "precision": _ci(prec_boot),
        "recall": _ci(rec_boot),
        "fpr": _ci(fpr_boot),
    }


def paired_mcnemar_test(
    y_true: List[int],
    y_pred_a: List[int],
    y_pred_b: List[int],
) -> Dict[str, Any]:
    """
    Paired McNemar's Test for comparing two classifiers on identical test instances.
    Evaluates discordance matrix: b (A correct, B wrong) vs c (B correct, A wrong).
    Statistic = (|b - c| - 1)^2 / (b + c) ~ Chi-squared (1 df)
    """
    labels = np.asarray(y_true)
    pred_a = np.asarray(y_pred_a)
    pred_b = np.asarray(y_pred_b)

    correct_a = pred_a == labels
    correct_b = pred_b == labels

    b = int(np.sum(correct_a & ~correct_b))  # A correct, B wrong
    c = int(np.sum(~correct_a & correct_b))  # B correct, A wrong

    if (b + c) == 0:
        return {"statistic": 0.0, "p_value": 1.0, "significant": False, "b": b, "c": c}

    # Edwards continuity correction
    stat = ((abs(b - c) - 1.0) ** 2) / float(b + c) if abs(b - c) >= 1.0 else 0.0

    # Asymptotic p-value approximation for 1 degree of freedom Chi-Square
    # P(X > stat) = erfc(sqrt(stat / 2))
    p_val = math.erfc(math.sqrt(stat / 2.0)) if stat > 0 else 1.0

    return {
        "statistic": round(float(stat), 4),
        "p_value": round(float(p_val), 4),
        "significant": bool(p_val < 0.05),
        "b_model_a_superior": b,
        "c_model_b_superior": c,
    }
