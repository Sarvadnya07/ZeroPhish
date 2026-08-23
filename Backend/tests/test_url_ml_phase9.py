"""
Unit tests for Phase 9 Large-Scale Benchmark v5, Frozen Holdout Generation,
Multi-Cohort Evaluation, and Registered-Domain Disjoint Partitioning.
"""

import json
from pathlib import Path

import pytest

from ml.benchmark.benchmark_v5 import (
    BenchmarkRecordV5,
    BenchmarkV5DatasetBuilder,
    BenchmarkV5Evaluator,
)
from ml.data.splitting.disjoint_splitter import DomainDisjointSplitter


def test_benchmark_record_v5_properties():
    rec = BenchmarkRecordV5(
        record_id="rec123",
        original_url="https://test.com/login",
        model_input="https://test.com/login",
        record_type="URL",
        label=1,
        source="openphish",
        source_record_id="op_123",
        registered_domain="test.com",
        hostname="test.com",
        tld="com",
        observed_at="2026-08-01",
        first_seen="2026-08-01",
        last_seen="2026-08-01",
    )
    assert rec.url_model_input == "https://test.com/login"
    assert rec.url_original == "https://test.com/login"
    assert rec.label_conflict is False
    d = rec.to_dict()
    assert d["record_id"] == "rec123"
    assert d["record_type"] == "URL"


def test_dataset_builder_v5_candidate():
    records, meta = BenchmarkV5DatasetBuilder.load_or_build_v5_candidate()
    assert len(records) > 0
    assert meta["total_records"] == len(records)
    assert meta["unique_registered_domains"] > 0
    assert meta["benign_count"] > 0
    assert meta["phishing_count"] > 0
    assert meta["hard_negative_count"] > 0
    assert meta["adversarial_count"] > 0


@pytest.mark.asyncio
async def test_benchmark_v5_evaluator_and_frozen_artifacts():
    res = await BenchmarkV5Evaluator.evaluate_v5_benchmark()
    assert "cohort_results" in res
    assert "CORE_BALANCED" in res["cohort_results"]
    assert "HARD_NEGATIVE" in res["cohort_results"]
    assert "ADVERSARIAL" in res["cohort_results"]
    assert "UNSEEN_DOMAIN" in res["cohort_results"]

    v5_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "url_benchmark_v5"
    assert (v5_dir / "dataset_manifest.json").exists()
    assert (v5_dir / "source_manifest.json").exists()
    assert (v5_dir / "split_manifest.json").exists()
    assert (v5_dir / "dataset_statistics.json").exists()
    assert (v5_dir / "final_test_manifest.json").exists()
    assert (v5_dir / "cohort_metrics.json").exists()
    assert (v5_dir / "evaluation_results.json").exists()
    assert (v5_dir / "error_analysis.json").exists()

    with open(v5_dir / "final_test_manifest.json", "r", encoding="utf-8") as f:
        ft_data = json.load(f)
    assert ft_data["final_test_frozen"] is True
    assert ft_data["record_count"] > 0


def test_historical_benchmarks_immutability():
    b_root = Path(__file__).resolve().parents[1] / "ml" / "benchmarks"
    assert (b_root / "dataset_manifest_v2.json").exists()
    assert (b_root / "dataset_manifest_v3.json").exists()
    assert (b_root / "url_benchmark_v4" / "dataset_manifest.json").exists()
