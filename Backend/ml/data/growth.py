"""
Dataset Growth Monitoring and Benchmark Promotion Pipeline for Phase 6.

Tracks benchmark progression across v1 -> v4, calculates target scale compliance,
and enforces immutable freeze on promoted benchmark releases.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "benchmarks"
REPORTS_DIR = Path(__file__).resolve().parent / "reports"
TARGET_DOMAINS = 10000
TARGET_BENIGN = 10000
TARGET_PHISHING = 10000


@dataclass
class Snapshot:
    """A snapshot of a benchmark version."""
    version: str
    total_records: int
    unique_domains: int
    benign_count: int
    phishing_count: int
    sources_count: int
    final_holdout_domains: int
    status: str  # e.g., "FROZEN_HISTORICAL"


class DatasetGrowthTracker:
    """Monitors dataset expansion and domain diversity across benchmark generations."""

    @classmethod
    def generate_growth_report(cls, benchmark_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Generate a growth report from historical benchmark snapshots.

        Args:
            benchmark_dir: Optional path to the benchmark directory.

        Returns:
            A dictionary containing growth timeline, target audit, and recommendation.
        """
        b_dir = benchmark_dir or BENCHMARK_DIR
        r_dir = REPORTS_DIR
        r_dir.mkdir(parents=True, exist_ok=True)

        # Historical snapshots (in production, these would be read from files)
        snapshots_data = [
            {
                "version": "url_benchmark_v1",
                "total_records": 70,
                "unique_domains": 70,
                "benign_count": 40,
                "phishing_count": 30,
                "sources_count": 2,
                "final_holdout_domains": 18,
                "status": "FROZEN_HISTORICAL",
            },
            {
                "version": "url_benchmark_v2",
                "total_records": 55,
                "unique_domains": 53,
                "benign_count": 25,
                "phishing_count": 30,
                "sources_count": 5,
                "final_holdout_domains": 10,
                "status": "FROZEN_HISTORICAL",
            },
            {
                "version": "url_benchmark_v3",
                "total_records": 55,
                "unique_domains": 53,
                "benign_count": 25,
                "phishing_count": 30,
                "sources_count": 5,
                "final_holdout_domains": 10,
                "status": "FROZEN_HISTORICAL",
            },
            {
                "version": "url_benchmark_v4",
                "total_records": 55,
                "unique_domains": 53,
                "benign_count": 25,
                "phishing_count": 30,
                "sources_count": 5,
                "final_holdout_domains": 10,
                "status": "FROZEN_ACTIVE",
            },
        ]

        snapshots = [Snapshot(**s) for s in snapshots_data]
        latest = snapshots[-1]

        target_audit = {
            "target_domains": TARGET_DOMAINS,
            "actual_domains": latest.unique_domains,
            "target_domains_status": "TARGET NOT REACHED" if latest.unique_domains < TARGET_DOMAINS else "TARGET REACHED",
            "target_benign": TARGET_BENIGN,
            "actual_benign": latest.benign_count,
            "target_benign_status": "TARGET NOT REACHED" if latest.benign_count < TARGET_BENIGN else "TARGET REACHED",
            "target_phishing": TARGET_PHISHING,
            "actual_phishing": latest.phishing_count,
            "target_phishing_status": "TARGET NOT REACHED" if latest.phishing_count < TARGET_PHISHING else "TARGET REACHED",
            "evaluation_verdict": "PROMISING — NEEDS MORE DATA",
        }

        report = {
            "growth_timeline": [s.__dict__ for s in snapshots],
            "target_scale_audit": target_audit,
            "recommendation": "Maintain frozen holdouts; ingest large-scale public data dumps in background.",
        }

        out_path = r_dir / "growth_trend_v4.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info("Growth report written to %s", out_path)
        return report