"""
Unit tests for Phase 4 Large-Scale Ingestion, Conflict Auditing, 4-Way Disjoint Splits,
Fine-Tuning Decision Logic, and Versioned v2 Benchmark Artifacts.
"""

from pathlib import Path

import pytest

from ml.benchmark.external_dataset import get_multi_source_benchmark_corpus
from ml.benchmark.finetune_evaluator import Phase4EvaluationEngine
from ml.data.pipeline import DataQualityPipeline, DatasetRecord, DatasetSplitter


def test_data_quality_pipeline_conflict_detection():
    # Two identical URLs with conflicting labels across feeds
    raw_entries = [
        {"url": "https://ambiguous-site.com/auth?ref=1", "label": 0, "source": "feed_a"},
        {"url": "https://ambiguous-site.com/auth?ref=2", "label": 1, "source": "feed_b"},
        {"url": "https://clear-site.com/home", "label": 0, "source": "feed_a"},
    ]
    records, stats = DataQualityPipeline.ingest_and_clean(raw_entries)

    assert stats.conflicting_labels_flagged == 1
    assert stats.cleaned_records == 2

    # Find the conflicting record
    conflict_rec = next(r for r in records if "ambiguous-site.com" in r.url)
    assert conflict_rec.label_conflict is True

    clear_rec = next(r for r in records if "clear-site.com" in r.url)
    assert clear_rec.label_conflict is False


def test_4way_domain_disjoint_split_guarantee():
    raw_tuples = get_multi_source_benchmark_corpus()
    raw_entries = [
        {
            "url": t[0],
            "label": t[1],
            "category": t[2],
            "source": t[3],
            "is_adversarial": t[4],
            "observed_at": t[5],
        }
        for t in raw_tuples
    ]
    records, _ = DataQualityPipeline.ingest_and_clean(raw_entries)
    splits = DatasetSplitter.create_4way_domain_disjoint_split(records, seed=42)

    train_doms = {r.registered_domain for r in splits["TRAIN"]}
    cal_doms = {r.registered_domain for r in splits["CALIBRATION"]}
    val_doms = {r.registered_domain for r in splits["VALIDATION"]}
    test_doms = {r.registered_domain for r in splits["FINAL_TEST"]}

    # Verify zero registered domain overlap between any pair of splits
    assert train_doms.isdisjoint(cal_doms)
    assert train_doms.isdisjoint(val_doms)
    assert train_doms.isdisjoint(test_doms)
    assert cal_doms.isdisjoint(val_doms)
    assert cal_doms.isdisjoint(test_doms)
    assert val_doms.isdisjoint(test_doms)


def test_split_hashes_deterministic():
    records = [
        DatasetRecord(
            url="https://alpha.com",
            label=0,
            domain="alpha.com",
            registered_domain="alpha.com",
            source="src",
            source_record_id="1",
            observed_at="2026-08-01",
            category="gen",
        ),
        DatasetRecord(
            url="https://beta.com",
            label=1,
            domain="beta.com",
            registered_domain="beta.com",
            source="src",
            source_record_id="2",
            observed_at="2026-08-01",
            category="gen",
        ),
    ]
    h1 = DatasetSplitter.compute_split_hash(records)
    h2 = DatasetSplitter.compute_split_hash(records)
    assert h1 == h2
    assert len(h1) == 64


def test_phase4_benchmark_v2_artifacts_exist():
    artifact_dir = Path(__file__).resolve().parents[1] / "ml" / "benchmarks"
    assert (artifact_dir / "dataset_manifest_v2.json").exists()
    assert (artifact_dir / "dataset_statistics_v2.json").exists()
    assert (artifact_dir / "split_manifest_v2.json").exists()
    assert (artifact_dir / "training_config_v1.json").exists()
    assert (artifact_dir / "training_metrics_v1.json").exists()
    assert (artifact_dir / "calibration_results_v2.json").exists()
    assert (artifact_dir / "final_evaluation_v2.json").exists()
    assert (artifact_dir / "model_card_v1.json").exists()
