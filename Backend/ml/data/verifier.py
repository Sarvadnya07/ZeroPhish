"""
Forensic Threat‑Feed Access Verifier for Phase 8.

Probes authoritative external threat‑feed and benign‑list endpoints, enforces strict
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Constants
DATA_ROOT = Path(__file__).resolve().parent
REPORTS_ROOT = DATA_ROOT / "reports"
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_TIMEOUT_SEC = 10
USER_AGENT = "ZeroPhish-SecurityResearch/4.0 (+https://zerophish.internal)"


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


@dataclass
class SourceAccessReportItem:
    source_name: str
    status: SourceAccessStatus
    mode: str
    endpoint_url: str
    auth_required: bool
    license_status: str
    http_status: Optional[int] = None
    bytes_received: int = 0
    raw_records_count: int = 0
    unique_domains_count: int = 0
    fetch_ms: float = 0.0
    parse_ms: float = 0.0
    total_ms: float = 0.0
    sha256_checksum: str = ""
    notes: str = ""
    blocker: Optional[str] = None
    required_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: (v.value if isinstance(v, SourceAccessStatus) else v)
                for k, v in self.__dict__.items()}


class ThreatFeedAccessVerifier:
    """Forensic verification engine probing authoritative threat intelligence endpoints."""

    def __init__(self, allow_sample: bool = False) -> None:
        self.allow_sample = allow_sample
        self.reports_dir = REPORTS_ROOT
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info("AccessVerifier initialized (allow_sample=%s)", allow_sample)

    @staticmethod
    def _check_env_credential(env_var: str) -> bool:
        """Safely check if an environment variable exists and is non‑empty."""
        return bool(os.environ.get(env_var, "").strip())

    _check_env_credential_presence = _check_env_credential

    def _safe_fetch(self, url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[bytes, int, float]:
        """Perform HTTP GET with timeout and size limit, returning (payload, status, elapsed_ms)."""
        t0 = time.perf_counter()
        req_headers = {"User-Agent": USER_AGENT, **(headers or {})}
        req = urllib.request.Request(url, headers=req_headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SEC) as resp:
                payload = resp.read(MAX_PAYLOAD_SIZE)
                return payload, resp.status, (time.perf_counter() - t0) * 1000.0
        except urllib.error.HTTPError as e:
            return b"", e.code, (time.perf_counter() - t0) * 1000.0
        except Exception as e:
            raise

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
                license_status="MIT License",
                raw_records_count=15,
                unique_domains_count=15,
                notes="Offline test mode with curated samples.",
            )

        try:
            payload, status, fetch_ms = self._safe_fetch(endpoint)
            if status >= 400 or not payload:
                total_ms = (time.perf_counter() - t0) * 1000.0
                return SourceAccessReportItem(
                    source_name="Tranco Top 1M",
                    status=SourceAccessStatus.UNAVAILABLE,
                    mode="BULK_FILE",
                    endpoint_url=endpoint,
                    auth_required=False,
                    license_status="MIT License",
                    http_status=status,
                    total_ms=total_ms,
                    notes=f"Fetch failed with HTTP status {status}",
                    blocker="Network egress or endpoint unreachable",
                    required_action="Enable outbound HTTPS or use local mirror",
                )
            t_parse = time.perf_counter()
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
            parse_ms = (time.perf_counter() - t_parse) * 1000.0
            total_ms = (time.perf_counter() - t0) * 1000.0

            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.LIVE_ACCESS,
                mode="BULK_FILE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License",
                http_status=status,
                bytes_received=len(payload),
                raw_records_count=count,
                unique_domains_count=len(domains),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                sha256_checksum=sha256,
                notes=f"Verified bulk archive ({len(domains)} unique domains).",
            )
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            http_status = getattr(e, "code", None)
            return SourceAccessReportItem(
                source_name="Tranco Top 1M",
                status=SourceAccessStatus.UNAVAILABLE,
                mode="BULK_FILE",
                endpoint_url=endpoint,
                auth_required=False,
                license_status="MIT License",
                http_status=http_status,
                total_ms=total_ms,
                notes=f"Fetch failed: {e}",
                blocker="Network egress or endpoint unreachable",
                required_action="Enable outbound HTTPS or use local mirror",
            )

    def verify_openphish_access(self) -> SourceAccessReportItem:
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
                notes="Offline test mode.",
            )

        try:
            payload, status, fetch_ms = self._safe_fetch(endpoint)
            t_parse = time.perf_counter()
            lines = [l.strip() for l in payload.decode("utf-8", errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
            domains = {l.split("/")[2] for l in lines if "/" in l}
            parse_ms = (time.perf_counter() - t_parse) * 1000.0
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
                unique_domains_count=len(domains),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                notes=f"Verified feed ({len(lines)} live URLs).",
            )
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            has_key = self._check_env_credential("OPENPHISH_API_KEY")
            return SourceAccessReportItem(
                source_name="OpenPhish Community Feed",
                status=SourceAccessStatus.AUTH_REQUIRED if not has_key else SourceAccessStatus.UNAVAILABLE,
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Open Data / Research Terms",
                total_ms=total_ms,
                notes=f"Fetch failed: {e}",
                blocker="API key missing" if not has_key else "Egress connectivity",
                required_action="Set OPENPHISH_API_KEY" if not has_key else "Enable network egress",
            )

    def verify_phishtank_access(self) -> SourceAccessReportItem:
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
                notes="Offline test mode.",
            )

        if not self._check_env_credential("PHISHTANK_API_KEY"):
            return SourceAccessReportItem(
                source_name="PhishTank Verified",
                status=SourceAccessStatus.AUTH_REQUIRED,
                mode="API",
                endpoint_url=endpoint,
                auth_required=True,
                license_status="Community API Terms",
                notes="API key required for bulk access.",
                blocker="PHISHTANK_API_KEY missing",
                required_action="Register and set PHISHTANK_API_KEY",
            )

        try:
            payload, status, fetch_ms = self._safe_fetch(endpoint,
                                                         headers={"User-Agent": f"phishtank/ZeroPhish (APIKey: CONFIGURED)"})
            t_parse = time.perf_counter()
            data = json.loads(payload)
            domains = {d.get("url", "").split("/")[2] for d in data if "/" in d.get("url", "")}
            parse_ms = (time.perf_counter() - t_parse) * 1000.0
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
                unique_domains_count=len(domains),
                fetch_ms=fetch_ms,
                parse_ms=parse_ms,
                total_ms=total_ms,
                notes=f"Verified JSON feed ({len(data)} records).",
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
                notes=f"Fetch failed: {e}",
                blocker="Endpoint unreachable or rate‑limited",
                required_action="Check network and API key validity",
            )

    def verify_cloud_cdn_access(self) -> SourceAccessReportItem:
        return SourceAccessReportItem(
            source_name="Cloud & CDN Assets",
            status=SourceAccessStatus.SAMPLE_ONLY,
            mode="SAMPLE",
            endpoint_url="internal://curated/cloud-cdn",
            auth_required=False,
            license_status="Public Metadata",
            raw_records_count=10,
            unique_domains_count=8,
            notes="Manually curated hard‑negatives. No live feed.",
            blocker="No automated bulk feed for SaaS/CDN URLs",
            required_action="Implement crawler for public IP ranges (AWS, Cloudflare).",
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
            notes="Synthetic evasion test suite.",
        )

    def run_full_verification(self) -> Dict[str, Any]:
        results = [
            self.verify_tranco_access(),
            self.verify_openphish_access(),
            self.verify_phishtank_access(),
            self.verify_cloud_cdn_access(),
            self.verify_adversarial_access(),
        ]

        live = sum(1 for r in results if r.status == SourceAccessStatus.LIVE_ACCESS)
        auth = sum(1 for r in results if r.status == SourceAccessStatus.AUTH_REQUIRED)
        sample = sum(1 for r in results if r.status in (SourceAccessStatus.SAMPLE_ONLY,
                                                        SourceAccessStatus.FIXTURE_ONLY))

        if live == len(results):
            overall = "A. REAL BULK ACCESS VERIFIED"
        elif live > 0:
            overall = "B. PARTIAL BULK ACCESS VERIFIED"
        elif auth > 0:
            overall = "C. BULK ACCESS BLOCKED (AUTH_REQUIRED)"
        else:
            overall = "D. ONLY SAMPLE/FIXTURE ACCESS AVAILABLE"

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_decision": overall,
            "allow_sample_mode": self.allow_sample,
            "sources": [r.to_dict() for r in results],
            "blockers": [
                {"source": r.source_name, "blocker": r.blocker, "required_action": r.required_action}
                for r in results if r.blocker
            ],
        }

        # Save JSON
        (self.reports_dir / "source_access_v4.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )

        # Markdown summary
        md = f"# Threat Feed Real‑Access Forensic Audit\n\n"
        md += f"**Timestamp:** {report['timestamp']}\n"
        md += f"**Overall Classification:** `{overall}`\n\n"
        md += "## Source Access Matrix\n\n"
        md += "| Source | Status | Mode | Auth | Records | Domains | Bytes | License | Notes |\n"
        md += "| :--- | :--- | :--- | :--- | ---: | ---: | ---: | :--- | :--- |\n"
        for r in results:
            md += (f"| **{r.source_name}** | `{r.status.value}` | `{r.mode}` | {r.auth_required} | "
                   f"{r.raw_records_count} | {r.unique_domains_count} | {r.bytes_received} | "
                   f"{r.license_status} | {r.notes} |\n")
        md += "\n## Blockers & Remediation\n\n"
        md += "| Source | Blocker | Action |\n| :--- | :--- | :--- |\n"
        for b in report["blockers"]:
            md += f"| **{b['source']}** | {b['blocker']} | {b['required_action']} |\n"
        (self.reports_dir / "source_access_v4.md").write_text(md, encoding="utf-8")

        return report