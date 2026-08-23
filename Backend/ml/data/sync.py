"""
Automated Threat-Feed Synchronization Engine for Phase 6 & Phase 7.
Handles rate-limited, idempotent feed synchronization, source health tracking,
detailed network/parse telemetry separation, and snapshot archiving.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .adapters.base import ThreatFeedAdapter
from .adapters.feed_adapters import (
    AdversarialRedTeamAdapter,
    BaseBulkFeedAdapter,
    CloudCDNAdapter,
    OpenPhishAdapter,
    PhishTankAdapter,
    RestrictedFeedTestAdapter,
    TrancoAdapter,
)
from .deduplication.deduplicator import MultiLevelDeduplicator
from .normalization.url_normalizer import URLNormalizer
from .schemas.v3 import (
    AdapterOperationalMode,
    DataQualityReportV3,
    DatasetRecordV3,
    DetailedNetworkTelemetry,
    FeedIngestionStatus,
    SourceApprovalStatus,
    SourceGovernance,
)
from .storage.snapshot_manager import SnapshotStorageManager

logger = logging.getLogger(__name__)

DATA_ROOT = Path(__file__).resolve().parent
RAW_ROOT = DATA_ROOT / "raw"
PROCESSED_ROOT = DATA_ROOT / "processed"
MANIFESTS_ROOT = DATA_ROOT / "manifests"
REPORTS_ROOT = DATA_ROOT / "reports"


class SourceHealthTracker:
    """Tracks operational telemetry, granular network/parse timings, and error rates."""

    def __init__(self):
        self.health_records: Dict[str, Dict[str, Any]] = {}

    def record_sync_event(
        self,
        source_name: str,
        status: str,
        operational_mode: str = "SAMPLE",
        records_fetched: int = 0,
        records_accepted: int = 0,
        records_rejected: int = 0,
        duplicate_count: int = 0,
        conflict_count: int = 0,
        bytes_received: int = 0,
        checksum: str = "",
        telemetry: Optional[DetailedNetworkTelemetry] = None,
        error_message: Optional[str] = None,
        latency_ms: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        if telemetry is None:
            telemetry = DetailedNetworkTelemetry(total_sync_ms=latency_ms or 0.0)
        elif latency_ms is not None:
            telemetry.total_sync_ms = latency_ms

        self.health_records[source_name] = {
            "source_name": source_name,
            "operational_mode": operational_mode,
            "last_attempt": datetime.now(timezone.utc).isoformat(),
            "last_successful_sync": (
                datetime.now(timezone.utc).isoformat() if status == "HEALTHY" else None
            ),
            "status": status,
            "records_fetched": records_fetched,
            "records_accepted": records_accepted,
            "records_rejected": records_rejected,
            "duplicate_count": duplicate_count,
            "conflict_count": conflict_count,
            "bytes_received": bytes_received,
            "checksum": checksum,
            "latency_ms": round(telemetry.total_sync_ms, 2),
            "telemetry": telemetry.model_dump(),
            "error_message": error_message,
        }

    def save_health_report(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "sources": self.health_records,
                    "overall_status": (
                        "HEALTHY"
                        if all(
                            v["status"] in ("HEALTHY", "DISABLED")
                            for v in self.health_records.values()
                        )
                        else "DEGRADED"
                    ),
                },
                f,
                indent=2,
            )


class ThreatFeedSyncEngine:
    """Idempotent feed synchronization engine with safe network handling and raw archiving."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        default_mode: AdapterOperationalMode = AdapterOperationalMode.SAMPLE,
    ):
        self.data_dir = data_dir or DATA_ROOT
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        self.manifests_dir = self.data_dir / "manifests"
        self.reports_dir = self.data_dir / "reports"

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.health_tracker = SourceHealthTracker()
        self.storage = SnapshotStorageManager(self.data_dir)

        self.adapters: Dict[str, BaseBulkFeedAdapter] = {
            "tranco": TrancoAdapter(mode=default_mode),
            "openphish": OpenPhishAdapter(mode=default_mode),
            "phishtank": PhishTankAdapter(mode=default_mode),
            "cloud_cdn": CloudCDNAdapter(mode=default_mode),
            "adversarial": AdversarialRedTeamAdapter(mode=default_mode),
        }

    def sync_source(self, source_key: str, force: bool = False) -> Dict[str, Any]:
        if source_key not in self.adapters:
            return {"status": "FAILED", "error": f"Unknown source key: {source_key}"}

        adapter = self.adapters[source_key]
        gov = adapter.get_governance()

        if gov.status != SourceApprovalStatus.APPROVED:
            self.health_tracker.record_sync_event(
                source_name=gov.source_name,
                status="DISABLED",
                operational_mode=str(gov.operational_mode),
                records_fetched=0,
                records_accepted=0,
                records_rejected=0,
                duplicate_count=0,
                conflict_count=0,
                bytes_received=0,
                checksum="",
                telemetry=DetailedNetworkTelemetry(),
                error_message="Source is not marked APPROVED in governance registry",
            )
            return {"status": "SKIPPED_UNAPPROVED", "source": gov.source_name}

        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        source_raw_dir = self.raw_dir / source_key / today_str
        source_raw_dir.mkdir(parents=True, exist_ok=True)
        raw_manifest_file = source_raw_dir / "manifest.json"

        try:
            records = adapter.fetch_records()
            telemetry = getattr(adapter, "last_telemetry", DetailedNetworkTelemetry())
            payload_str = json.dumps(records, sort_keys=True)
            payload_bytes = payload_str.encode("utf-8")
            payload_hash = hashlib.sha256(payload_bytes).hexdigest()

            # Check idempotency
            if raw_manifest_file.exists() and not force:
                with open(raw_manifest_file, "r", encoding="utf-8") as f:
                    prev_manifest = json.load(f)
                if prev_manifest.get("payload_hash") == payload_hash:
                    logger.info(
                        f"Source {source_key} already processed for {today_str}. Skipping duplicate."
                    )
                    self.health_tracker.record_sync_event(
                        source_name=gov.source_name,
                        status="HEALTHY",
                        operational_mode=str(gov.operational_mode),
                        records_fetched=len(records),
                        records_accepted=len(records),
                        records_rejected=0,
                        duplicate_count=0,
                        conflict_count=0,
                        bytes_received=len(payload_bytes),
                        checksum=payload_hash,
                        telemetry=telemetry,
                    )
                    return {
                        "status": "SKIPPED_ALREADY_PROCESSED",
                        "source": gov.source_name,
                        "operational_mode": str(gov.operational_mode),
                        "payload_hash": payload_hash,
                        "records_count": len(records),
                    }

            # Write Raw Payload & Manifest
            payload_file = source_raw_dir / "payload.json"
            with open(payload_file, "w", encoding="utf-8") as f:
                f.write(payload_str)

            manifest_data = {
                "source_name": gov.source_name,
                "source_key": source_key,
                "operational_mode": str(gov.operational_mode),
                "sync_timestamp": datetime.now(timezone.utc).isoformat(),
                "payload_hash": payload_hash,
                "records_count": len(records),
                "bytes": len(payload_bytes),
                "telemetry": telemetry.model_dump(),
            }
            with open(raw_manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

            self.health_tracker.record_sync_event(
                source_name=gov.source_name,
                status="HEALTHY",
                operational_mode=str(gov.operational_mode),
                records_fetched=len(records),
                records_accepted=len(records),
                records_rejected=0,
                duplicate_count=0,
                conflict_count=0,
                bytes_received=len(payload_bytes),
                checksum=payload_hash,
                telemetry=telemetry,
            )

            return {
                "status": "SUCCESS",
                "source": gov.source_name,
                "operational_mode": str(gov.operational_mode),
                "payload_hash": payload_hash,
                "records_count": len(records),
                "telemetry": telemetry.model_dump(),
            }

        except Exception as e:
            self.health_tracker.record_sync_event(
                source_name=gov.source_name,
                status="FAILED",
                operational_mode=str(gov.operational_mode),
                records_fetched=0,
                records_accepted=0,
                records_rejected=0,
                duplicate_count=0,
                conflict_count=0,
                bytes_received=0,
                checksum="",
                telemetry=DetailedNetworkTelemetry(),
                error_message=str(e),
            )
            return {"status": "FAILED", "source": gov.source_name, "error": str(e)}

    def sync_all_approved(self) -> Dict[str, Any]:
        results = {}
        for key in self.adapters.keys():
            results[key] = self.sync_source(key)

        health_file = self.reports_dir / "source_health_v4.json"
        self.health_tracker.save_health_report(health_file)

        return results
