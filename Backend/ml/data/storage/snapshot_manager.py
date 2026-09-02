"""
Snapshot Storage and Manifest Persistence Engine for Phase 5, 6 & 7.

Saves immutable dataset releases, reports, source governance metadata,
and benchmark releases to the filesystem.

All outputs are stored in a structured directory hierarchy with versioned
JSON files for reproducibility.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..schemas.v3 import (
    DataQualityReportV3,
    DatasetRecordV3,
    SourceGovernance,
    SplitManifestV3,
    ThroughputMetricsV3,
)

logger = logging.getLogger(__name__)

# Default paths relative to this file's location
DATA_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = DATA_ROOT.parent / "benchmarks"


class SnapshotStorageManager:
    """
    Manages immutable versioned dataset snapshots and evaluation manifests.

    All files are stored as JSON with consistent formatting (indent=2) for
    human readability and version control friendliness.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        benchmark_root: Optional[Path] = None,
    ) -> None:
        """
        Initialize the storage manager.

        Args:
            base_dir: Base directory for reports and manifests.
                      Defaults to DATA_ROOT.
            benchmark_root: Root directory for benchmark releases.
                           Defaults to BENCHMARK_ROOT.
        """
        self.base_dir = Path(base_dir) if base_dir else DATA_ROOT
        self.benchmark_root = Path(benchmark_root) if benchmark_root else BENCHMARK_ROOT

        self.reports_dir = self.base_dir / "reports"
        self.manifests_dir = self.base_dir / "manifests"
        self.benchmark_dir = self.benchmark_root

        # Create directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.benchmark_dir.mkdir(parents=True, exist_ok=True)

        logger.info("SnapshotStorageManager initialized with base=%s, benchmark=%s",
                    self.base_dir, self.benchmark_root)

    def save_source_registry(self, sources: Dict[str, SourceGovernance]) -> Path:
        """
        Save the source governance registry to a JSON file.

        Args:
            sources: Mapping of source keys to SourceGovernance objects.

        Returns:
            Path to the saved file.
        """
        out_path = self.manifests_dir / "source_registry.json"
        data = {k: v.model_dump() for k, v in sources.items()}
        self._write_json(out_path, data)
        logger.info("Source registry saved to %s", out_path)
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
        """
        Save the full Phase 7 Benchmark v4 release suite.

        This creates a structured directory `url_benchmark_v4/` under the
        benchmark root containing all relevant manifests, reports, and results.

        Args:
            records: List of DatasetRecordV3 (only used for SHA, not stored directly).
            dq_report: Data quality report.
            split_manifest: Split manifest.
            source_governances: Source governance registry.
            throughput: Throughput metrics.
            evaluation_results: Evaluation results dictionary.
            calibration_results: Calibration results.
            threshold_results: Threshold results.
            error_analysis: Error analysis summary.

        Returns:
            Dictionary mapping logical names to saved paths.
        """
        b4_dir = self.benchmark_dir / "url_benchmark_v4"
        b4_dir.mkdir(parents=True, exist_ok=True)

        saved_paths: Dict[str, Path] = {}

        # 1. Source Registry (reuse the method)
        saved_paths["source_registry"] = self.save_source_registry(source_governances)

        # 2. Data Quality Report (v4 and v3)
        dq_path_v4 = self.reports_dir / "dataset_quality_report_v4.json"
        dq_path_v3 = self.reports_dir / "dataset_quality_report_v3.json"
        dq_data = dq_report.model_dump()
        self._write_json(dq_path_v4, dq_data)
        self._write_json(dq_path_v3, dq_data)
        saved_paths["dataset_quality_report"] = dq_path_v4

        # 3. Conflict Report (empty for v3, but we keep for compatibility)
        conflict_path_v3 = self.reports_dir / "conflict_report_v3.json"
        self._write_json(conflict_path_v3, {"conflicting_records": [], "total_conflicts": 0})
        saved_paths["conflict_report"] = conflict_path_v3

        # 4. Dataset Manifest v3 (legacy)
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
        self._write_json(b3_manifest, b3_data)
        saved_paths["benchmark_v3_manifest"] = b3_manifest

        # 5. Source Manifest (v4)
        src_manifest_path = b4_dir / "source_manifest.json"
        self._write_json(src_manifest_path, {k: v.model_dump() for k, v in source_governances.items()})
        saved_paths["source_manifest"] = src_manifest_path

        # 6. Split Manifest
        split_path = b4_dir / "split_manifest.json"
        self._write_json(split_path, split_manifest.model_dump())
        saved_paths["split_manifest"] = split_path

        # 7. Dataset Manifest (v4)
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
        self._write_json(ds_manifest_path, ds_data)
        saved_paths["dataset_manifest"] = ds_manifest_path

        # 8. Evaluation Results
        eval_path = b4_dir / "evaluation_results.json"
        self._write_json(eval_path, evaluation_results)
        saved_paths["evaluation_results"] = eval_path

        # 9. Calibration Results
        calib_path = b4_dir / "calibration_results.json"
        self._write_json(calib_path, calibration_results)
        saved_paths["calibration_results"] = calib_path

        # 10. Threshold Results
        thresh_path = b4_dir / "threshold_results.json"
        self._write_json(thresh_path, threshold_results)
        saved_paths["threshold_results"] = thresh_path

        # 11. Error Analysis
        err_path = b4_dir / "error_analysis.json"
        self._write_json(err_path, error_analysis)
        saved_paths["error_analysis"] = err_path

        logger.info("Benchmark v4 release saved to %s", b4_dir)
        return saved_paths

    @staticmethod
    def _write_json(path: Path, data: Union[dict, list]) -> None:
        """
        Write JSON data to a file with consistent formatting.

        Args:
            path: Destination file path.
            data: Serializable Python object (dict or list).
        """
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        logger.debug("Written JSON to %s", path)

    @classmethod
    def load_json(cls, path: Path) -> dict:
        """
        Load a JSON file.

        Args:
            path: Path to JSON file.

        Returns:
            Parsed dictionary.

        Raises:
            FileNotFoundError: If path does not exist.
            json.JSONDecodeError: If file is invalid JSON.
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)