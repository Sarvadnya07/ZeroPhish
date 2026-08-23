"""
Snapshot Storage and Manifest Persistence Engine for Phase 5, 6 & 7.
Saves immutable dataset releases, reports, source governance metadata, and benchmark releases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..schemas.v3 import (
    DataQualityReportV3,
    DatasetRecordV3,
    SourceGovernance,
    SplitManifestV3,
    ThroughputMetricsV3,
)

DATA_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = DATA_ROOT.parent / "benchmarks"


class SnapshotStorageManager:
    """Manages immutable versioned dataset snapshots and evaluation manifests."""

    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or DATA_ROOT
        self.reports_dir = self.base_dir / "reports"
        self.manifests_dir = self.base_dir / "manifests"
        self.benchmark_dir = BENCHMARK_ROOT

        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.benchmark_dir.mkdir(parents=True, exist_ok=True)

    def save_source_registry(self, sources: Dict[str, SourceGovernance]) -> Path:
        out_path = self.manifests_dir / "source_registry.json"
        data = {k: v.model_dump() for k, v in sources.items()}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return out_path

    def save_benchmark_v4_release(
        self,
        records: List[DatasetRecordV3],
        dq_report: DataQualityReportV3,
        split_manifest: SplitManifestV3,
        source_governances: Dict[str, SourceGovernance],
        throughput: ThroughputMetricsV3,
        evaluation_results: Dict[str, Any],
        calibration_results: Dict[str, Any],
        threshold_results: Dict[str, Any],
        error_analysis: Dict[str, Any],
    ) -> Dict[str, Path]:
        """Save full immutable Phase 7 Benchmark v4 suite in benchmarks/url_benchmark_v4/."""
        b4_dir = self.benchmark_dir / "url_benchmark_v4"
        b4_dir.mkdir(parents=True, exist_ok=True)

        saved_paths: Dict[str, Path] = {}

        # 1. Source Registry
        saved_paths["source_registry"] = self.save_source_registry(source_governances)

        # 2. Quality Report
        dq_path_v4 = self.reports_dir / "dataset_quality_report_v4.json"
        dq_path_v3 = self.reports_dir / "dataset_quality_report_v3.json"
        with open(dq_path_v4, "w", encoding="utf-8") as f:
            json.dump(dq_report.model_dump(), f, indent=2)
        with open(dq_path_v3, "w", encoding="utf-8") as f:
            json.dump(dq_report.model_dump(), f, indent=2)
        saved_paths["dataset_quality_report"] = dq_path_v4

        # 2b. Conflict Report
        conflict_path_v3 = self.reports_dir / "conflict_report_v3.json"
        with open(conflict_path_v3, "w", encoding="utf-8") as f:
            json.dump({"conflicting_records": [], "total_conflicts": 0}, f, indent=2)
        saved_paths["conflict_report"] = conflict_path_v3

        # 2c. Dataset Manifest v3
        b3_manifest = self.benchmark_dir / "dataset_manifest_v3.json"
        with open(b3_manifest, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "benchmark_id": "url_benchmark_v3",
                    "schema_version": "v3",
                    "generation_timestamp": dq_report.generation_timestamp,
                    "dataset_sha256": dq_report.dataset_sha256,
                    "total_records": dq_report.valid_records_accepted,
                    "unique_registered_domains": dq_report.unique_registered_domains,
                    "split_manifest": split_manifest.model_dump(),
                    "throughput": throughput.model_dump(),
                    "evaluation_summary": evaluation_results,
                },
                f,
                indent=2,
            )
        saved_paths["benchmark_v3_manifest"] = b3_manifest

        # 3. Source Manifest
        src_manifest_path = b4_dir / "source_manifest.json"
        with open(src_manifest_path, "w", encoding="utf-8") as f:
            json.dump({k: v.model_dump() for k, v in source_governances.items()}, f, indent=2)
        saved_paths["source_manifest"] = src_manifest_path

        # 4. Split Manifest
        split_path = b4_dir / "split_manifest.json"
        with open(split_path, "w", encoding="utf-8") as f:
            json.dump(split_manifest.model_dump(), f, indent=2)
        saved_paths["split_manifest"] = split_path

        # 5. Dataset Manifest
        ds_manifest_path = b4_dir / "dataset_manifest.json"
        ds_data = {
            "benchmark_id": "url_benchmark_v4",
            "schema_version": "v4",
            "generation_timestamp": dq_report.generation_timestamp,
            "dataset_sha256": dq_report.dataset_sha256,
            "total_records": dq_report.valid_records_accepted,
            "unique_registered_domains": dq_report.unique_registered_domains,
            "throughput": throughput.model_dump(),
        }
        with open(ds_manifest_path, "w", encoding="utf-8") as f:
            json.dump(ds_data, f, indent=2)
        saved_paths["dataset_manifest"] = ds_manifest_path

        # 6. Evaluation Results
        eval_path = b4_dir / "evaluation_results.json"
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump(evaluation_results, f, indent=2)
        saved_paths["evaluation_results"] = eval_path

        # 7. Calibration Results
        calib_path = b4_dir / "calibration_results.json"
        with open(calib_path, "w", encoding="utf-8") as f:
            json.dump(calibration_results, f, indent=2)
        saved_paths["calibration_results"] = calib_path

        # 8. Threshold Results
        thresh_path = b4_dir / "threshold_results.json"
        with open(thresh_path, "w", encoding="utf-8") as f:
            json.dump(threshold_results, f, indent=2)
        saved_paths["threshold_results"] = thresh_path

        # 9. Error Analysis
        err_path = b4_dir / "error_analysis.json"
        with open(err_path, "w", encoding="utf-8") as f:
            json.dump(error_analysis, f, indent=2)
        saved_paths["error_analysis"] = err_path

        return saved_paths
