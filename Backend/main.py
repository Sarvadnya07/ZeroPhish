"""
ZeroPhish Backend - Legacy Compatibility Shim.

DEPRECATION NOTICE:
`Backend/gateway.py` is the CANONICAL application entry point for ZeroPhish (Port 8001).
This module is preserved as a backwards-compatibility delegation shim for tests and existing tooling.
It will be removed in a future release.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from gateway import app as gateway_app

logger = logging.getLogger(__name__)
logger.warning(
    "⚠️ Backend/main.py is DEPRECATED. Please use `gateway.py` (Port 8001) instead. "
    "This shim will be removed in v3.0."
)

# Re-export canonical gateway app
app = gateway_app


# ── Legacy Models (Preserved for Tests) ──────────────────────────────────────
# These models are kept only for backward compatibility with existing tests.
# They are not used by the canonical gateway.

class BertRequest(BaseModel):
    """Legacy BERT request model (deprecated)."""
    text: str = Field(..., min_length=1, max_length=4000)


class BertResponse(BaseModel):
    """Legacy BERT response model (deprecated)."""
    threat_level: int = Field(..., ge=0, le=100)
    category: str = Field(..., pattern="^(safe|spam|phishing)$")
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    model: str
    reasoning: str


class LinkItem(BaseModel):
    """Legacy link item (deprecated)."""
    href: str
    text: Optional[str] = None


class HeuristicItem(BaseModel):
    """Legacy heuristic item (deprecated)."""
    check: str
    points: Optional[float] = None
    detail: Optional[str] = None
    kind: Optional[str] = None


class Tier1Result(BaseModel):
    """Legacy Tier 1 result (deprecated)."""
    score: int = Field(..., ge=0, le=100)
    category: str = Field(..., pattern="^(safe|spam|phishing)$")
    summary: str
    evidence: list[HeuristicItem] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    heuristics_score: Optional[int] = Field(None, ge=0, le=100)
    ml_enabled: bool = False
    ml_threat_level: Optional[int] = Field(None, ge=0, le=100)
    ml_category: Optional[str] = Field(None, pattern="^(safe|spam|phishing)$")
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    ml_label: Optional[str] = None
    ml_model: Optional[str] = None
    ml_reasoning: Optional[str] = None


class EmailMeta(BaseModel):
    """Legacy email metadata (deprecated)."""
    subject: Optional[str] = None
    senderEmail: Optional[str] = None
    senderName: Optional[str] = None


class Tier1Report(BaseModel):
    """Legacy Tier 1 report (deprecated)."""
    version: int = 1
    event_id: Optional[str] = None
    scan_id: str
    created_at: str
    source: str = "chrome_sidepanel"
    email: EmailMeta = Field(default_factory=EmailMeta)
    links: list[LinkItem] = Field(default_factory=list)
    tier1: Tier1Result
    layers_completed: int = 1


# ── Legacy Helper Functions ──────────────────────────────────────────────────
# These are preserved for test compatibility.

def _category_from_verdict(verdict: Optional[str]) -> str:
    """Convert verdict string to legacy category."""
    if verdict is None:
        return "safe"
    v = verdict.strip().upper()
    if v == "CRITICAL":
        return "phishing"
    if v == "SUSPICIOUS":
        return "spam"
    return "safe"


def _verdict_from_score(score: int) -> str:
    """Convert score to verdict string."""
    if score >= 70:
        return "CRITICAL"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def _coerce_extension_report(report: dict[str, Any]) -> Tier1Report:
    """
    Legacy coercion of extension report to Tier1Report.
    Preserved for test compatibility.
    """
    verdict = str(report.get("verdict", "SAFE")).strip().upper()
    if verdict not in {"SAFE", "SUSPICIOUS", "CRITICAL"}:
        verdict = "SAFE"

    evidence_raw = report.get("evidence", [])
    evidence_list: list[HeuristicItem] = []
    if isinstance(evidence_raw, list):
        for e in evidence_raw:
            if isinstance(e, dict):
                points = e.get("points")
                evidence_list.append(
                    HeuristicItem(
                        check=str(e.get("check") or "extension"),
                        detail=str(e.get("detail") or e.get("check") or "signal"),
                        kind=(str(e.get("kind")) if e.get("kind") is not None else None),
                        points=(float(points) if isinstance(points, (int, float)) else None),
                    )
                )
            else:
                evidence_list.append(HeuristicItem(check="extension", detail=str(e)))

    score_raw = report.get("final_score", 0)
    try:
        score = int(round(float(score_raw)))
    except Exception:
        score = 0
    score = max(0, min(100, score))
    verdict = _verdict_from_score(score)
    category = _category_from_verdict(verdict)

    return Tier1Report(
        scan_id=str(report.get("scan_id") or "ext_compat"),
        created_at=str(report.get("timestamp") or "2026-01-01T00:00:00Z"),
        email=EmailMeta(
            subject=str(report.get("subject") or "No Subject"),
            senderEmail=str(report.get("sender") or "unknown@unknown.com"),
        ),
        tier1=Tier1Result(
            score=score,
            category=category,
            summary=f"Scan update: {verdict}",
            evidence=evidence_list,
            heuristics_score=score,
            ml_enabled=False,
            ml_threat_level=None,
            ml_category=None,
            ml_confidence=None,
        ),
    )


if __name__ == "__main__":
    import uvicorn

    print(
        "⚠️  NOTICE: Backend/main.py is deprecated. Delegating to Backend/gateway.py on Port 8001..."
    )
    uvicorn.run(
        "gateway:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
    )