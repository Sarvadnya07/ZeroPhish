"""
Snapshot Storage and Manifest Persistence Engine for Phase 5.
Saves immutable dataset releases, reports, and source governance metadata.
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

    def save_benchmark_v3_snapshot(
        self,
        records: List[DatasetRecordV3],
        dq_report: DataQualityReportV3,
        split_manifest: SplitManifestV3,
        source_governances: Dict[str, SourceGovernance],
        throughput: ThroughputMetricsV3,
        evaluation_results: Dict[str, Any],
        conflict_records: List[Dict[str, Any]],
    ) -> Dict[str, Path]:
        """Save full immutable Phase 5 Benchmark v3 suite."""
        saved_paths: Dict[str, Path] = {}

        # 1. Source Registry
        saved_paths["source_registry"] = self.save_source_registry(source_governances)

        # 2. Quality Report
        dq_path = self.reports_dir / "dataset_quality_report_v3.json"
        with open(dq_path, "w", encoding="utf-8") as f:
            json.dump(dq_report.model_dump(), f, indent=2)
        saved_paths["dataset_quality_report"] = dq_path

        # 3. Conflict Report
        conflict_path = self.reports_dir / "conflict_report_v3.json"
        with open(conflict_path, "w", encoding="utf-8") as f:
            json.dump(
                {"conflicting_records": conflict_records, "total_conflicts": len(conflict_records)},
                f,
                indent=2,
            )
        saved_paths["conflict_report"] = conflict_path

        # 4. Split Manifest
        split_path = self.manifests_dir / "split_manifest_v3.json"
        with open(split_path, "w", encoding="utf-8") as f:
            json.dump(split_manifest.model_dump(), f, indent=2)
        saved_paths["split_manifest"] = split_path

        # 5. Benchmark v3 manifest in ml/benchmarks/
        b3_manifest = self.benchmark_dir / "dataset_manifest_v3.json"
        b3_data = {
            "benchmark_id": "url_benchmark_v3",
            "schema_version": "v3",
            "generation_timestamp": dq_report.generation_timestamp,
            "dataset_sha256": dq_report.dataset_sha256,
            "total_records": dq_report.valid_records_accepted,
            "unique_registered_domains": dq_report.unique_registered_domains,
            "split_manifest": split_manifest.model_dump(),
            "throughput": throughput.model_dump(),
            "evaluation_summary": evaluation_results,
        }
        with open(b3_manifest, "w", encoding="utf-8") as f:
            json.dump(b3_data, f, indent=2)
        saved_paths["benchmark_v3_manifest"] = b3_manifest

        return saved_paths
