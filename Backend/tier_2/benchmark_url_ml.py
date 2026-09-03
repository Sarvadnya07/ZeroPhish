# ================================
# FILE 2: ml/benchmark.py
# ================================

#!/usr/bin/env python3
"""
ZeroPhish URL ML Benchmark Suite.

Compares Heuristics, URLBERT‑tiny, ONNX baseline, and Hybrid Fusion
across standard evaluation metrics: Accuracy, Precision, Recall, F1, FPR, FNR, and Latency.

Supports:
- Configurable dataset size (--size)
- Warm‑up iterations (--warmup)
- Multiple runs for statistics (--runs)
- JSON output (--output)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.url_predictor import (
    MockURLPredictor,
    ONNXURLPredictor,
    URLBERTPredictor,
    URLPredictionResult,
)
from ml.url_preprocessor import URLPreprocessor
from tier_2.analyzer import ThreatAnalyzer

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------- Default Dataset ----------
DEFAULT_DATASET: List[Tuple[str, int]] = [
    ("https://www.google.com/search?q=cybersecurity", 0),
    ("https://github.com/ZeroPhish/security-core", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://aws.amazon.com/security/", 0),
    ("https://www.apple.com/support/", 0),
    ("https://learn.microsoft.com/en-us/azure/", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://developer.mozilla.org/en-US/docs/Web", 0),
    ("https://www.python.org/downloads/", 0),
    ("https://pypi.org/project/fastapi/", 0),
    ("http://paypa1-account-verification.com/login.php", 1),
    ("http://192.168.1.105/auth/bank-update", 1),
    ("http://xn--pypal-4ve.com/secure-signin", 1),
    ("http://apple-security-id.account-verify.xyz/login", 1),
    ("http://service-paypal.com.account-update.top/auth", 1),
    ("http://microsoft-support-alert.com/urgent-reset", 1),
    ("http://verify-bank-credentials.cc/secure/", 1),
    ("http://netflix-billing-alert.info/payment", 1),
    ("http://secure-chase-update.biz/login", 1),
    ("http://google-drive-shared-doc.xyz/verify", 1),
]


def load_dataset(file_path: Path) -> List[Tuple[str, int]]:
    """Load dataset from a CSV file (url,label)."""
    if not file_path.exists():
        return DEFAULT_DATASET
    dataset = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                url = parts[0].strip()
                try:
                    label = int(parts[1].strip())
                    dataset.append((url, label))
                except ValueError:
                    continue
    return dataset


def evaluate_predictions(
    y_true: List[int], y_pred: List[int], latencies: List[float]
) -> Dict[str, Any]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)

    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "avg_latency_ms": round(avg_latency, 2),
    }


async def evaluate_model(
    predictor: Any,
    urls: List[str],
    y_true: List[int],
    warmup: int = 0,
) -> Dict[str, Any]:
    """Evaluate a single predictor on the given dataset."""
    # Warm‑up
    for _ in range(warmup):
        await predictor.predict(urls[0]) if warmup > 0 else None

    y_pred = []
    latencies = []
    for u in urls:
        t0 = time.perf_counter()
        res = await predictor.predict(u)
        lat = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat)
        y_pred.append(1 if res.phishing_probability >= 0.5 else 0)
    return evaluate_predictions(y_true, y_pred, latencies)


async def run_benchmark(
    dataset: List[Tuple[str, int]],
    warmup: int = 0,
    runs: int = 1,
) -> Dict[str, Dict[str, Any]]:
    y_true = [label for _, label in dataset]
    urls = [url for url, _ in dataset]

    results = {}

    # 1. Heuristics Only
    logger.info("Running Heuristics Only...")
    h_preds = []
    h_latencies = []
    for u in urls:
        t0 = time.perf_counter()
        score, _ = await ThreatAnalyzer._analyze_links([u])
        lat = (time.perf_counter() - t0) * 1000.0
        h_latencies.append(lat)
        h_preds.append(1 if score >= 15 else 0)
    results["Heuristics_Only"] = evaluate_predictions(y_true, h_preds, h_latencies)

    # 2. Mock Predictor (fast baseline)
    logger.info("Running Mock Predictor...")
    mock = MockURLPredictor()
    results["Mock_URLPredictor"] = await evaluate_model(mock, urls, y_true, warmup)

    # 3. ONNX Predictor (if available)
    try:
        onnx = ONNXURLPredictor()
        logger.info("Running ONNX Predictor...")
        results["ONNX_Baseline"] = await evaluate_model(onnx, urls, y_true, warmup)
    except Exception as e:
        logger.warning("ONNX Predictor not available: %s", e)

    # 4. URLBERT Predictor (if available)
    try:
        bert = URLBERTPredictor()
        logger.info("Running URLBERT Predictor...")
        results["URLBERT_Tiny"] = await evaluate_model(bert, urls, y_true, warmup)
    except Exception as e:
        logger.warning("URLBERT Predictor not available: %s", e)

    # 5. Hybrid Heuristics + ML (simple vote)
    hybrid_preds = []
    hybrid_latencies = []
    # For simplicity, use mock as ML (since ONNX/URLBERT may not be available)
    for u in urls:
        t0 = time.perf_counter()
        h_score, _ = await ThreatAnalyzer._analyze_links([u])
        h_pred = 1 if h_score >= 15 else 0
        ml_res = await mock.predict(u)
        ml_pred = 1 if ml_res.phishing_probability >= 0.5 else 0
        combined = 1 if (h_pred == 1 or ml_pred == 1) else 0
        hybrid_preds.append(combined)
        lat = (time.perf_counter() - t0) * 1000.0
        hybrid_latencies.append(lat)

    results["Hybrid_Heuristics_ML"] = evaluate_predictions(
        y_true, hybrid_preds, hybrid_latencies
    )

    return results


def main():
    parser = argparse.ArgumentParser(description="ZeroPhish URL ML Benchmark")
    parser.add_argument("--dataset", type=Path, help="Path to CSV dataset file (url,label)")
    parser.add_argument("--size", type=int, default=None, help="Limit dataset size")
    parser.add_argument("--warmup", type=int, default=5, help="Warm‑up iterations")
    parser.add_argument("--runs", type=int, default=1, help="Number of runs (for statistics)")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    dataset = load_dataset(args.dataset) if args.dataset else DEFAULT_DATASET
    if args.size and args.size < len(dataset):
        dataset = dataset[:args.size]

    logger.info("Benchmarking with %d samples", len(dataset))

    # Run benchmark (one run by default)
    results = asyncio.run(run_benchmark(dataset, warmup=args.warmup, runs=args.runs))

    # Print summary
    print("\n" + "=" * 60)
    print("Benchmark Results")
    print("=" * 60)
    for model_name, metrics in results.items():
        print(f"\n--- {model_name} ---")
        for k, v in metrics.items():
            print(f"  {k}: {v}")

    # Save JSON if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()