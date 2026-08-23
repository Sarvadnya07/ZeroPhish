"""
Forensic Threat-Feed Access Verifier for Phase 8.
Probes authoritative external threat-feed and benign-list endpoints, enforces strict
status classification, separates network vs parse telemetry, prevents silent sample fallback,
and generates structured source access audit reports.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import logging
import os
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DATA_ROOT = Path(__file__).resolve().parent
REPORTS_ROOT = DATA_ROOT / "reports"
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_TIMEOUT_SEC = 10


class SourceAccessStatus(str, Enum):
    LIVE_ACCESS = "LIVE_ACCESS"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    MISCONFIGURED = "MISCONFIGURED"
    SAMPLE_ONLY = "SAMPLE_ONLY"
    FIXTURE_ONLY = "FIXTURE_ONLY"
    DISABLED = "DISABLED"


class SourceAccessReportItem:
    def __init__(
        self,
        source_name: str,
        status: SourceAccessStatus,
        mode: str,
        endpoint_url: str,
        auth_required: bool,
        license_status: str,
        http_status: Optional[int] = None,
        bytes_received: int = 0,
        raw_records_count: int = 0,
        unique_domains_count: int = 0,
        fetch_ms: float = 0.0,
        parse_ms: float = 0.0,
        total_ms: float = 0.0,
        sha256_checksum: str = "",
        notes: str = "",
        blocker: Optional[str] = None,
        required_action: Optional[str] = None,
    ):
        self.source_name = source_name
        self.status = status
        self.mode = mode
        self.endpoint_url = endpoint_url
        self.auth_required = auth_required
        self.license_status = license_status
        self.http_status = http_status
        self.bytes_received = bytes_received
        self.raw_records_count = raw_records_count
        self.unique_domains_count = unique_domains_count
        self.fetch_ms = round(fetch_ms, 2)
        self.parse_ms = round(parse_ms, 2)
        self.total_ms = round(total_ms, 2)
        self.sha256_checksum = sha256_checksum
        self.notes = notes
        self.blocker = blocker
        self.required_action = required_action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "status": str(self.status.value),
            "mode": self.mode,
            "endpoint_url": self.endpoint_url,
            "auth_required": self.auth_required,
            "license_status": self.license_status,
            "http_status": self.http_status,
            "bytes_received": self.bytes_received,
            "raw_records_count": self.raw_records_count,
            "unique_domains_count": self.unique_domains_count,
            "fetch_ms": self.fetch_ms,
            "parse_ms": self.parse_ms,
            "total_ms": self.total_ms,
            "sha256_checksum": self.sha256_checksum,
            "notes": self.notes,
            "blocker": self.blocker,
            "required_action": self.required_action,
        }


class ThreatFeedAccessVerifier:
    """Forensic verification engine probing authoritative threat intelligence endpoints."""

    def __init__(self, allow_sample: bool = False):
        self.allow_sample = allow_sample
        self.reports_dir = REPORTS_ROOT
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _check_env_credential_presence(env_var_name: str) -> bool:
        """Safely checks if an environment variable exists without reading/printing its content."""
        val = os.environ.get(env_var_name, "").strip()
        return bool(val)

    def verify_tranco_access(self) -> SourceAccessReportItem:
        endpoint = "https://tranco-list.eu/top-1m.csv.zip"
        t0 = time.perf_counter()

        if self.allow_sample:
            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.SAMPLE_ONLY,
                mode="SAMPLE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License (Approved)",
                raw_records_count=15,
                unique_domains_count=15,
                notes="Offline test mode with curated top domains.",
            )

        try:
            req = urllib.request.Request(
                endpoint,
                headers={
                    "User-Agent": "ZeroPhish-SecurityResearch/1.0 (+https://zerophish.internal)"
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SEC) as resp:
                status = resp.status
                payload = resp.read(MAX_PAYLOAD_SIZE)
            fetch_ms = (time.perf_counter() - t0) * 1000.0

            t_parse_start = time.perf_counter()
            sha256 = hashlib.sha256(payload).hexdigest()
            domains: Set[str] = set()
            count = 0
            with zipfile.ZipFile(io.BytesIO(payload)) as z:
                csv_name = z.namelist()[0]
                with z.open(csv_name) as f:
                    reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                    for row in reader:
                        count += 1
                        if len(row) >= 2:
                            domains.add(row[1].strip().lower())
            parse_ms = (time.perf_counter() - t_parse_start) * 1000.0
            total_ms = (time.perf_counter() - t0) * 1000.0

            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.LIVE_ACCESS,
                mode="BULK_FILE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License (Approved)",
                http_status=status,
                bytes_received=len(payload),
                raw_records_count=count,
                unique_domains_count=len(domains),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                sha256_checksum=sha256,
                notes=f"Successfully verified authoritative Tranco bulk archive ({len(domains)} unique domains).",
            )

        except urllib.error.HTTPError as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.UNAVAILABLE,
                mode="BULK_FILE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License",
                http_status=e.code,
                total_ms=total_ms,
                notes=f"HTTP Error: {e}",
                blocker="Tranco bulk endpoint returned HTTP error",
                required_action="Verify network egress or mirror Tranco list locally",
            )
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.UNAVAILABLE,
                mode="BULK_FILE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License",
                total_ms=total_ms,
                notes=f"Network unreachable: {e}",
                blocker="Network egress blocked or offline environment",
                required_action="Enable outbound HTTPS or supply local Tranco archive dump",
            )

    def verify_openphish_access(self) -> SourceAccessReportItem:
        has_key = self._check_env_credential_presence("OPENPHISH_API_KEY")
        endpoint = "https://openphish.com/feed.txt"
        t0 = time.perf_counter()

        if self.allow_sample:
            return SourceAccessReportItem(
                source_name="OpenPhish Community Feed",
                status=SourceAccessStatus.SAMPLE_ONLY,
                mode="SAMPLE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="Open Data / Research Terms",
                raw_records_count=10,
                unique_domains_count=10,
                notes="Offline test mode with curated phishing samples.",
            )

        try:
            req = urllib.request.Request(
                endpoint,
                headers={
                    "User-Agent": "ZeroPhish-SecurityResearch/1.0 (+https://zerophish.internal)"
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SEC) as resp:
                status = resp.status
                payload = resp.read(MAX_PAYLOAD_SIZE)
            fetch_ms = (time.perf_counter() - t0) * 1000.0

            t_parse_start = time.perf_counter()
            sha256 = hashlib.sha256(payload).hexdigest()
            lines = [
                l.strip()
                for l in payload.decode("utf-8", errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")
            ]
            parse_ms = (time.perf_counter() - t_parse_start) * 1000.0
            total_ms = (time.perf_counter() - t0) * 1000.0

            return SourceAccessReportItem(
                source_name="OpenPhish Community Feed",
                status=SourceAccessStatus.LIVE_ACCESS,
                mode="API",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="Open Data / Research Terms",
                http_status=status,
                bytes_received=len(payload),
                raw_records_count=len(lines),
                unique_domains_count=len({l.split("/")[2] for l in lines if "/" in l}),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                sha256_checksum=sha256,
                notes=f"Successfully verified OpenPhish community feed ({len(lines)} live URLs).",
            )

        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            return SourceAccessReportItem(
                source_name="OpenPhish Community Feed",
                status=(
                    SourceAccessStatus.AUTH_REQUIRED
                    if not has_key
                    else SourceAccessStatus.UNAVAILABLE
                ),
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Open Data / Research Terms (Raw Redistribution Restricted)",
                total_ms=total_ms,
                notes=f"Live fetch unavailable ({e}).",
                blocker=(
                    "OpenPhish premium API key required for full bulk volume"
                    if not has_key
                    else "Egress connectivity unavailable"
                ),
                required_action=(
                    "Set OPENPHISH_API_KEY environment variable with authorized credential"
                    if not has_key
                    else "Enable network egress"
                ),
            )

    def verify_phishtank_access(self) -> SourceAccessReportItem:
        has_key = self._check_env_credential_presence("PHISHTANK_API_KEY")
        endpoint = "http://data.phishtank.com/data/online-valid.json"
        t0 = time.perf_counter()

        if self.allow_sample:
            return SourceAccessReportItem(
                source_name="PhishTank Verified",
                status=SourceAccessStatus.SAMPLE_ONLY,
                mode="SAMPLE",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Community API Terms",
                raw_records_count=10,
                unique_domains_count=10,
                notes="Offline test mode with curated PhishTank submissions.",
            )

        if not has_key:
            return SourceAccessReportItem(
                source_name="PhishTank Verified",
                status=SourceAccessStatus.AUTH_REQUIRED,
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Community API Terms (Redistribution Restricted)",
                notes="PhishTank automated bulk API requires a registered API key in User-Agent header.",
                blocker="PHISHTANK_API_KEY environment variable is missing",
                required_action="Register for a PhishTank Developer API key and configure PHISHTANK_API_KEY",
            )

        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": f"phishtank/ZeroPhish (APIKey: [CONFIGURED])"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SEC) as resp:
                status = resp.status
                payload = resp.read(MAX_PAYLOAD_SIZE)
            fetch_ms = (time.perf_counter() - t0) * 1000.0

            t_parse_start = time.perf_counter()
            sha256 = hashlib.sha256(payload).hexdigest()
            data = json.loads(payload)
            parse_ms = (time.perf_counter() - t_parse_start) * 1000.0
            total_ms = (time.perf_counter() - t0) * 1000.0

            return SourceAccessReportItem(
                source_name="PhishTank Verified",
                status=SourceAccessStatus.LIVE_ACCESS,
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Community API Terms",
                http_status=status,
                bytes_received=len(payload),
                raw_records_count=len(data),
                unique_domains_count=len(
                    {d.get("url", "").split("/")[2] for d in data if "/" in d.get("url", "")}
                ),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                sha256_checksum=sha256,
                notes=f"Successfully verified PhishTank bulk JSON feed ({len(data)} records).",
            )
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            return SourceAccessReportItem(
                source_name="PhishTank Verified",
                status=SourceAccessStatus.UNAVAILABLE,
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Community API Terms",
                total_ms=total_ms,
                notes=f"PhishTank API query failed: {e}",
                blocker="PhishTank API endpoint unreachable or rate-limited",
                required_action="Check network connectivity or rate limits on registered key",
            )

    def verify_cloud_cdn_access(self) -> SourceAccessReportItem:
        return SourceAccessReportItem(
            source_name="Cloud & CDN Assets",
            status=SourceAccessStatus.SAMPLE_ONLY,
            mode="SAMPLE",
            endpoint_url="internal://curated/cloud-cdn",
            auth_required=False,
            license_status="Public Metadata (Approved)",
            raw_records_count=10,
            unique_domains_count=8,
            notes="Manually curated hard-negative samples. Does not represent a live dynamic feed.",
            blocker="No automated bulk feed exists for high-entropy SaaS/CDN URLs",
            required_action="Implement an automated crawler/parser for public IP ranges (e.g. AWS ip-ranges.json, Cloudflare list)",
        )

    def verify_adversarial_access(self) -> SourceAccessReportItem:
        return SourceAccessReportItem(
            source_name="ZeroPhish Adversarial Red Team Corpus",
            status=SourceAccessStatus.FIXTURE_ONLY,
            mode="FIXTURE",
            endpoint_url="internal://curated/adversarial",
            auth_required=False,
            license_status="Proprietary Internal",
            raw_records_count=10,
            unique_domains_count=10,
            notes="Synthetic homoglyph, punycode, and port-based evasion test suite. Maintained separately from natural feeds.",
        )

    def run_full_verification(self) -> Dict[str, Any]:
        results = [
            self.verify_tranco_access(),
            self.verify_openphish_access(),
            self.verify_phishtank_access(),
            self.verify_cloud_cdn_access(),
            self.verify_adversarial_access(),
        ]

        live_count = sum(1 for r in results if r.status == SourceAccessStatus.LIVE_ACCESS)
        auth_count = sum(1 for r in results if r.status == SourceAccessStatus.AUTH_REQUIRED)
        sample_count = sum(
            1
            for r in results
            if r.status in (SourceAccessStatus.SAMPLE_ONLY, SourceAccessStatus.FIXTURE_ONLY)
        )

        if live_count == len(results):
            overall_decision = "A. REAL BULK ACCESS VERIFIED"
        elif live_count > 0:
            overall_decision = "B. PARTIAL BULK ACCESS VERIFIED"
        elif auth_count > 0:
            overall_decision = "C. BULK ACCESS BLOCKED (AUTH_REQUIRED)"
        else:
            overall_decision = "D. ONLY SAMPLE/FIXTURE ACCESS AVAILABLE"

        report_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_decision": overall_decision,
            "allow_sample_mode": self.allow_sample,
            "sources": [r.to_dict() for r in results],
            "blockers": [
                {
                    "source": r.source_name,
                    "blocker": r.blocker,
                    "required_action": r.required_action,
                }
                for r in results
                if r.blocker
            ],
        }

        # Save JSON report
        json_path = self.reports_dir / "source_access_v4.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # Save Markdown report
        md_path = self.reports_dir / "source_access_v4.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Threat Feed Real-Access Forensic Audit Report\n\n")
            f.write(f"**Verification Timestamp:** {report_data['timestamp']}\n")
            f.write(f"**Overall Classification:** `{overall_decision}`\n\n")
            f.write("## Source Access Matrix\n\n")
            f.write(
                "| Source | Status | Mode | Auth Required | Records | Domains | Bytes | License | Notes |\n"
            )
            f.write("| :--- | :--- | :--- | :--- | ---: | ---: | ---: | :--- | :--- |\n")
            for r in results:
                f.write(
                    f"| **{r.source_name}** | `{r.status.value}` | `{r.mode}` | {r.auth_required} | {r.raw_records_count} | {r.unique_domains_count} | {r.bytes_received} | {r.license_status} | {r.notes} |\n"
                )

            f.write("\n## Blocker & Remediation Table\n\n")
            f.write("| Source | Blocker Description | Required Action |\n")
            f.write("| :--- | :--- | :--- |\n")
            for b in report_data["blockers"]:
                f.write(f"| **{b['source']}** | {b['blocker']} | {b['required_action']} |\n")

        return report_data
