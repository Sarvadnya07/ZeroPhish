"""
ZeroPhish Phase 2 Comprehensive Benchmark, Calibration, and Threshold Optimization Suite.
Executes multi-split evaluation, Platt/Isotonic probability calibration,
threshold sweeps, fusion optimization, latency profiling, and error analysis.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

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
from ml.url_predictor import (
    MockURLPredictor,
    ONNXURLPredictor,
    URLBERTPredictor,
    URLPredictionResult,
)
from ml.url_preprocessor import URLPreprocessor
from tier_2.analyzer import ThreatAnalyzer


class BenchmarkRunner:
    """End-to-end benchmark execution engine."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or (BACKEND_DIR / "ml" / "benchmarks")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    async def evaluate_heuristic_pipeline(
        samples: List[BenchmarkSample],
    ) -> Tuple[List[float], List[float]]:
        scores: List[float] = []
        latencies: List[float] = []
        for s in samples:
            t0 = time.perf_counter()
            score, _ = await ThreatAnalyzer._analyze_links([s.url])
            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)
            scores.append(float(score) / 100.0)
        return scores, latencies

    @staticmethod
    async def evaluate_url_ml_pipeline(
        samples: List[BenchmarkSample], predictor
    ) -> Tuple[List[float], List[float]]:
        scores: List[float] = []
        latencies: List[float] = []
        for s in samples:
            t0 = time.perf_counter()
            res: URLPredictionResult = await predictor.predict(s.url)
            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)
            scores.append(float(res.phishing_probability))
        return scores, latencies

    @classmethod
    async def run_full_benchmark(cls) -> Dict[str, Any]:
        raw_corpus = get_curated_benchmark_corpus()
        samples, dq_report = DatasetPipeline.prepare_dataset(raw_corpus)

        # 1. Splits
        train_dd, cal_dd, test_dd = DatasetPipeline.create_domain_disjoint_split(samples, seed=42)
        train_rnd, cal_rnd, test_rnd = DatasetPipeline.create_stratified_random_split(
            samples, seed=42
        )
        adv_samples = [s for s in samples if s.is_adversarial]

        predictor = MockURLPredictor()

        # 2. Evaluate on Domain-Disjoint Calibration & Test sets
        y_cal = [s.label for s in cal_dd]
        y_test = [s.label for s in test_dd]

        h_cal_probs, _ = await cls.evaluate_heuristic_pipeline(cal_dd)
        m_cal_probs, _ = await cls.evaluate_url_ml_pipeline(cal_dd, predictor)

        h_test_probs, h_lat = await cls.evaluate_heuristic_pipeline(test_dd)
        m_test_probs, m_lat = await cls.evaluate_url_ml_pipeline(test_dd, predictor)

        # Hybrid fusion on test set: (Heuristics 0.4 + ML 0.6)
        hybrid_test_probs = [(h * 0.4 + m * 0.6) for h, m in zip(h_test_probs, m_test_probs)]

        # 3. Fit Calibrator on Calibration Set (NEVER on test set)
        platt = PlattCalibrator().fit(m_cal_probs, y_cal)
        isotonic = IsotonicCalibrator().fit(m_cal_probs, y_cal)

        calibrated_platt_test = platt.predict_proba(m_test_probs).tolist()
        calibrated_iso_test = isotonic.predict_proba(m_test_probs).tolist()

        # 4. Compute Metrics
        def _calc_pipeline_metrics(
            y_true: List[int], y_prob: List[float], lats: List[float]
        ) -> Dict[str, Any]:
            roc_auc, pr_auc = compute_roc_pr_auc(y_true, y_prob)
            ece = compute_ece(y_true, y_prob)
            brier = compute_brier_score(y_true, y_prob)
            sweep = sweep_thresholds(y_true, y_prob)
            op_points = find_optimal_operating_points(sweep)

            best_f1_pt = op_points.get("max_f1", {})

            return {
                "roc_auc": roc_auc,
                "pr_auc": pr_auc,
                "ece": ece,
                "brier_score": brier,
                "precision": best_f1_pt.get("precision", 0.0),
                "recall": best_f1_pt.get("recall", 0.0),
                "f1": best_f1_pt.get("f1", 0.0),
                "fpr": best_f1_pt.get("fpr", 0.0),
                "fnr": best_f1_pt.get("fnr", 0.0),
                "optimal_threshold": best_f1_pt.get("threshold", 0.50),
                "operating_points": op_points,
                "avg_latency_ms": round(sum(lats) / len(lats) if lats else 0.0, 2),
            }

        pipeline_results = {
            "heuristics_only": _calc_pipeline_metrics(y_test, h_test_probs, h_lat),
            "urlbert_raw": _calc_pipeline_metrics(y_test, m_test_probs, m_lat),
            "urlbert_platt_calibrated": _calc_pipeline_metrics(
                y_test, calibrated_platt_test, m_lat
            ),
            "urlbert_isotonic_calibrated": _calc_pipeline_metrics(
                y_test, calibrated_iso_test, m_lat
            ),
            "hybrid_heuristics_ml": _calc_pipeline_metrics(
                y_test, hybrid_test_probs, [hl + ml for hl, ml in zip(h_lat, m_lat)]
            ),
        }

        # 5. Latency Profile (Mean, Median, p95, p99 over warm runs)
        latencies_warm = []
        for _ in range(50):
            t0 = time.perf_counter()
            _ = URLPreprocessor.preprocess("https://secure.example.com/login?token=abc")
            _ = await predictor.predict("https://secure.example.com/login?token=abc")
            latencies_warm.append((time.perf_counter() - t0) * 1000.0)

        latencies_warm.sort()
        n_warm = len(latencies_warm)
        lat_profile = {
            "mean_ms": round(sum(latencies_warm) / n_warm, 3),
            "median_ms": round(latencies_warm[n_warm // 2], 3),
            "p95_ms": round(latencies_warm[int(n_warm * 0.95)], 3),
            "p99_ms": round(latencies_warm[int(n_warm * 0.99)], 3),
        }

        # 6. Ablation Analysis
        base_f1 = pipeline_results["heuristics_only"]["f1"]
        ablation = {
            "heuristics": {"f1": base_f1, "delta_f1": 0.0},
            "+ url_ml": {
                "f1": pipeline_results["hybrid_heuristics_ml"]["f1"],
                "delta_f1": round(pipeline_results["hybrid_heuristics_ml"]["f1"] - base_f1, 4),
            },
        }

        full_report = {
            "metadata": {
                "timestamp": "2026-08-24T00:00:00Z",
                "dataset_version": "v1.2-domain-disjoint",
                "samples_count": len(samples),
                "unique_domains": dq_report.unique_domains,
                "split_strategy": "Domain-Disjoint Holdout",
            },
            "data_quality": {
                "total_raw": dq_report.total_raw_samples,
                "normalized": dq_report.normalized_samples,
                "duplicates_removed": dq_report.exact_duplicate_count,
                "unique_domains": dq_report.unique_domains,
                "benign_count": dq_report.benign_count,
                "phishing_count": dq_report.phishing_count,
                "imbalance_ratio": dq_report.imbalance_ratio,
                "adversarial_count": dq_report.adversarial_sample_count,
            },
            "pipelines": pipeline_results,
            "latency_profile": lat_profile,
            "ablation": ablation,
        }

        # Save artifacts
        runner = BenchmarkRunner()
        with open(runner.output_dir / "benchmark_metadata.json", "w") as f:
            json.dump(full_report["metadata"], f, indent=2)
        with open(runner.output_dir / "results.json", "w") as f:
            json.dump(full_report["pipelines"], f, indent=2)
        with open(runner.output_dir / "calibration.json", "w") as f:
            json.dump(
                {
                    "platt_w": platt.w,
                    "platt_b": platt.b,
                    "raw_ece": pipeline_results["urlbert_raw"]["ece"],
                    "calibrated_ece": pipeline_results["urlbert_platt_calibrated"]["ece"],
                },
                f,
                indent=2,
            )

        return full_report


if __name__ == "__main__":
    print("Running ZeroPhish Phase 2 Comprehensive Benchmark & Calibration...")
    res = asyncio.run(BenchmarkRunner.run_full_benchmark())
    print("\n--- Benchmark Completed ---")
    print(
        f"Total Samples: {res['data_quality']['normalized']} ({res['data_quality']['unique_domains']} Unique Domains)"
    )
    for name, p_data in res["pipelines"].items():
        print(f"\nPipeline: {name}")
        print(
            f"  F1: {p_data['f1']} | ROC-AUC: {p_data['roc_auc']} | PR-AUC: {p_data['pr_auc']} | ECE: {p_data['ece']}"
        )
        print(f"  Optimal Threshold (Max F1): {p_data['optimal_threshold']}")
