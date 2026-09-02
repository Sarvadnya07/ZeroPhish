"""
Probability Calibration, Statistical Inference, and Cost-Sensitive Optimization Module.

Implements Platt Scaling (Newton‑Raphson MLE), Temperature Scaling, Isotonic Calibration,
Expected Calibration Error (ECE), Brier Score, Bootstrap Confidence Intervals (95% CI),
Paired McNemar Significance Test, and Cost‑Sensitive Operating Point Optimization.

All calibrators support NumPy arrays and Python lists, and include safeguards
against numerical instability.
"""

from __future__ import annotations

import math
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

logger = logging.getLogger(__name__)

# ---------- Constants ----------
EPSILON = 1e-12
CLIP_MIN = -20.0
CLIP_MAX = 20.0
DEFAULT_N_BINS = 10
DEFAULT_N_BOOTSTRAPS = 500
DEFAULT_THRESHOLD = 0.50
DEFAULT_ALPHA = 0.05
DEFAULT_SEED = 42
L2_REGULARIZATION = 1e-4
GRADIENT_DESCENT_LR = 0.01


# ---------- Platt Scaling ----------
class PlattCalibrator:
    """
    Platt Scaling (Logistic Sigmoid) via Newton‑Raphson MLE.

    Maps uncalibrated scores (logits or probabilities) to calibrated posterior
    probabilities: P(y=1 | s) = 1 / (1 + exp(-(w * s + b))).
    """

    def __init__(self) -> None:
        self.w: float = 1.0
        self.b: float = 0.0
        self.is_fitted: bool = False

    def fit(
        self,
        y_score: Union[List[float], np.ndarray],
        y_true: Union[List[int], np.ndarray],
        max_iter: int = 50,
        tol: float = 1e-6,
    ) -> PlattCalibrator:
        """
        Fit the Platt scaling parameters using Newton‑Raphson with L2 regularization.

        Args:
            y_score: Uncalibrated scores (or probabilities) – will be clipped.
            y_true: Binary labels (0/1).
            max_iter: Maximum Newton‑Raphson iterations.
            tol: Convergence tolerance.

        Returns:
            self (fitted calibrator).
        """
        scores = np.asarray(y_score, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(scores) < 2 or len(np.unique(labels)) < 2:
            logger.warning("PlattCalibrator: insufficient data; using identity mapping.")
            self.w = 1.0
            self.b = 0.0
            self.is_fitted = False
            return self

        # Clip scores to avoid overflow
        scores = np.clip(scores, -15.0, 15.0)
        n = float(len(labels))

        # Laplace smoothing of targets (Platt's original prior)
        n_pos = np.sum(labels == 1.0)
        n_neg = np.sum(labels == 0.0)
        t_pos = (n_pos + 1.0) / (n_pos + 2.0)
        t_neg = 1.0 / (n_neg + 2.0)
        t = np.where(labels == 1.0, t_pos, t_neg)

        theta = np.array([1.0, 0.0], dtype=np.float64)

        for _ in range(max_iter):
            z = theta[0] * scores + theta[1]
            p = 1.0 / (1.0 + np.exp(-np.clip(z, CLIP_MIN, CLIP_MAX)))
            var = np.maximum(p * (1.0 - p), EPSILON)

            # Gradient
            diff = p - t
            grad_w = np.sum(diff * scores)
            grad_b = np.sum(diff)
            grad = np.array([grad_w, grad_b])

            # Hessian (with L2 regularization)
            h_00 = np.sum(var * scores * scores) + L2_REGULARIZATION
            h_01 = np.sum(var * scores)
            h_11 = np.sum(var) + L2_REGULARIZATION
            hessian = np.array([[h_00, h_01], [h_01, h_11]])

            try:
                delta = np.linalg.solve(hessian, grad)
                theta -= delta
                if np.sum(delta ** 2) < tol:
                    break
            except np.linalg.LinAlgError:
                # Fallback to gradient descent
                theta -= GRADIENT_DESCENT_LR * grad
                if np.sum(grad ** 2) < tol:
                    break

        self.w = float(theta[0])
        self.b = float(theta[1])
        self.is_fitted = True
        logger.debug("PlattCalibrator fitted: w=%.4f, b=%.4f", self.w, self.b)
        return self

    def predict_proba(self, y_score: Union[List[float], np.ndarray]) -> np.ndarray:
        """Apply fitted Platt scaling to produce calibrated probabilities."""
        if not self.is_fitted:
            return np.asarray(y_score, dtype=np.float64)
        scores = np.asarray(y_score, dtype=np.float64)
        logits = self.w * scores + self.b
        return 1.0 / (1.0 + np.exp(-np.clip(logits, CLIP_MIN, CLIP_MAX)))


# ---------- Temperature Scaling ----------
class TemperatureScalingCalibrator:
    """
    Temperature Scaling for logits: P(y=1 | z) = sigmoid(z / T).

    Learns a single positive temperature parameter T > 0 via gradient descent.
    """

    def __init__(self) -> None:
        self.temperature: float = 1.0
        self.is_fitted: bool = False

    def fit(
        self,
        y_logits: Union[List[float], np.ndarray],
        y_true: Union[List[int], np.ndarray],
        max_iter: int = 100,
        lr: float = 0.05,
    ) -> TemperatureScalingCalibrator:
        logits = np.asarray(y_logits, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(logits) < 2 or len(np.unique(labels)) < 2:
            logger.warning("TemperatureScaling: insufficient data; keeping T=1.0.")
            self.is_fitted = False
            return self

        t = 1.0
        for _ in range(max_iter):
            scaled = logits / max(t, EPSILON)
            p = 1.0 / (1.0 + np.exp(-np.clip(scaled, CLIP_MIN, CLIP_MAX)))
            diff = p - labels
            grad_t = -np.sum(diff * logits / (max(t, EPSILON) ** 2)) / len(labels)
            t = max(0.01, t - lr * grad_t)

        self.temperature = float(t)
        self.is_fitted = True
        logger.debug("TemperatureScaling: T=%.4f", self.temperature)
        return self

    def predict_proba(self, y_logits: Union[List[float], np.ndarray]) -> np.ndarray:
        if not self.is_fitted:
            return np.asarray(y_logits, dtype=np.float64)
        logits = np.asarray(y_logits, dtype=np.float64)
        scaled = logits / max(self.temperature, EPSILON)
        return 1.0 / (1.0 + np.exp(-np.clip(scaled, CLIP_MIN, CLIP_MAX)))


# ---------- Isotonic Calibration ----------
class IsotonicCalibrator:
    """
    Non‑parametric Isotonic Regression via Pool Adjacent Violators Algorithm (PAVA).

    Fits a monotonic step‑wise mapping from scores to calibrated probabilities.
    """

    def __init__(self) -> None:
        self.x_thresholds: List[float] = []
        self.y_calibrated: List[float] = []
        self.is_fitted: bool = False

    def fit(
        self,
        y_score: Union[List[float], np.ndarray],
        y_true: Union[List[int], np.ndarray],
    ) -> IsotonicCalibrator:
        scores = np.asarray(y_score, dtype=np.float64)
        labels = np.asarray(y_true, dtype=np.float64)

        if len(scores) == 0 or len(np.unique(labels)) < 2:
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
                blocks.append({
                    "weight": new_weight,
                    "sum": new_sum,
                    "mean": new_sum / new_weight,
                    "x_min": b1["x_min"],
                    "x_max": b2["x_max"],
                })

        self.x_thresholds = [b["x_max"] for b in blocks]
        self.y_calibrated = [b["mean"] for b in blocks]
        self.is_fitted = True
        return self

    def predict_proba(self, y_score: Union[List[float], np.ndarray]) -> np.ndarray:
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


# ---------- Evaluation Metrics ----------
def compute_ece(
    y_true: Union[List[int], np.ndarray],
    y_prob: Union[List[float], np.ndarray],
    n_bins: int = DEFAULT_N_BINS,
) -> float:
    """Expected Calibration Error (ECE) – lower is better."""
    labels = np.asarray(y_true, dtype=np.float64)
    probs = np.asarray(y_prob, dtype=np.float64)

    if len(labels) == 0:
        return 0.0

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    total = len(labels)

    for i in range(n_bins):
        lower = bins[i]
        upper = bins[i + 1]
        in_bin = (probs >= lower) & (probs < upper if i < n_bins - 1 else probs <= upper)
        prop = np.sum(in_bin) / total
        if prop > 0:
            acc = np.mean(labels[in_bin])
            conf = np.mean(probs[in_bin])
            ece += prop * abs(acc - conf)

    return float(round(ece, 4))


def compute_brier_score(
    y_true: Union[List[int], np.ndarray],
    y_prob: Union[List[float], np.ndarray],
) -> float:
    """Brier score – mean squared error of probabilistic predictions."""
    labels = np.asarray(y_true, dtype=np.float64)
    probs = np.asarray(y_prob, dtype=np.float64)
    if len(labels) == 0:
        return 0.0
    return float(round(np.mean((probs - labels) ** 2), 4))


def _trapz(y: np.ndarray, x: np.ndarray) -> float:
    """Numerical integration via trapezoidal rule (fallback for old NumPy)."""
    if hasattr(np, "trapezoid"):
        return float(np.trapezoid(y, x))
    return float(np.sum((x[1:] - x[:-1]) * (y[:-1] + y[1:]) / 2.0))


def compute_roc_pr_auc(
    y_true: Union[List[int], np.ndarray],
    y_prob: Union[List[float], np.ndarray],
) -> Tuple[float, float]:
    """
    Compute Area Under ROC curve and Area Under Precision‑Recall curve.

    Returns:
        (roc_auc, pr_auc) as floats between 0 and 1.
    """
    labels = np.asarray(y_true)
    probs = np.asarray(y_prob)

    if len(labels) == 0 or len(np.unique(labels)) < 2:
        return 0.5, 0.5

    desc_idx = np.argsort(-probs)
    sorted_labels = labels[desc_idx]
    n_pos = np.sum(sorted_labels == 1)
    n_neg = np.sum(sorted_labels == 0)

    if n_pos == 0 or n_neg == 0:
        return 0.5, 0.5

    tp_cumsum = np.cumsum(sorted_labels == 1)
    fp_cumsum = np.cumsum(sorted_labels == 0)
    tpr = np.concatenate([[0], tp_cumsum / n_pos])
    fpr = np.concatenate([[0], fp_cumsum / n_neg])
    roc_auc = _trapz(tpr, fpr)

    precisions = tp_cumsum / (tp_cumsum + fp_cumsum)
    recalls = tp_cumsum / n_pos
    pr_auc = _trapz(np.concatenate([[1.0], precisions]), np.concatenate([[0.0], recalls]))

    return round(abs(roc_auc), 4), round(abs(pr_auc), 4)


def sweep_thresholds(
    y_true: Union[List[int], np.ndarray],
    y_prob: Union[List[float], np.ndarray],
    step: float = 0.02,
) -> List[Dict[str, Any]]:
    """Evaluate performance metrics across probability thresholds 0.01–0.99."""
    labels = np.asarray(y_true)
    probs = np.asarray(y_prob)
    thresholds = np.arange(0.02, 0.99, step)

    total_pos = np.sum(labels == 1)
    total_neg = np.sum(labels == 0)
    curve = []

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

        curve.append({
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
        })

    return curve


def find_optimal_operating_points(
    threshold_curve: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Identify operational operating points (max F1, high recall, low FPR, balanced)."""
    if not threshold_curve:
        return {}

    max_f1_pt = max(threshold_curve, key=lambda x: x["f1"])
    high_recall = [pt for pt in threshold_curve if pt["recall"] >= 0.80]
    high_recall_pt = max(high_recall, key=lambda x: x["precision"]) if high_recall else max_f1_pt
    low_fpr = [pt for pt in threshold_curve if pt["fpr"] <= 0.05]
    low_fpr_pt = max(low_fpr, key=lambda x: x["recall"]) if low_fpr else min(threshold_curve, key=lambda x: x["fpr"])
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
    Find threshold that minimises expected cost: Loss = (FN * cost_fn) + (FP * cost_fp).
    """
    if not threshold_curve:
        return {"threshold": 0.5, "expected_cost": 0.0}

    scored = []
    for pt in threshold_curve:
        total_cost = (pt.get("fn", 0) * cost_fn) + (pt.get("fp", 0) * cost_fp)
        scored.append({**pt, "expected_cost": total_cost})

    return min(scored, key=lambda x: x["expected_cost"])


def compute_bootstrap_confidence_intervals(
    y_true: Union[List[int], np.ndarray],
    y_prob: Union[List[float], np.ndarray],
    threshold: float = DEFAULT_THRESHOLD,
    n_bootstraps: int = DEFAULT_N_BOOTSTRAPS,
    alpha: float = DEFAULT_ALPHA,
    seed: int = DEFAULT_SEED,
) -> Dict[str, Dict[str, float]]:
    """Bootstrap 95% confidence intervals for F1, Precision, Recall, and FPR."""
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
    y_true: Union[List[int], np.ndarray],
    y_pred_a: Union[List[int], np.ndarray],
    y_pred_b: Union[List[int], np.ndarray],
) -> Dict[str, Any]:
    """
    Paired McNemar's test comparing two classifiers on identical test instances.

    Statistic = (|b - c| - 1)^2 / (b + c) ~ Chi‑squared (1 df),
    where b = A correct & B wrong; c = B correct & A wrong.
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

    # Continuity‑corrected (Edwards) chi‑square statistic
    stat = ((abs(b - c) - 1.0) ** 2) / float(b + c) if abs(b - c) >= 1 else 0.0
    p_val = math.erfc(math.sqrt(stat / 2.0)) if stat > 0 else 1.0

    return {
        "statistic": round(float(stat), 4),
        "p_value": round(float(p_val), 4),
        "significant": bool(p_val < 0.05),
        "b_model_a_superior": b,
        "c_model_b_superior": c,
    }