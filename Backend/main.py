from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

# Add Backend to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from tier_3.main import T3Result, analyze_email_intent

app = FastAPI(title="ZeroPhish Tier 1 (Local)", version="0.1.0")

# CORS Configuration - Environment-based for security
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,chrome-extension://*").split(
        ","
    )
    if origin.strip() and origin.strip() != "chrome-extension://*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=os.getenv("ALLOW_ORIGIN_REGEX") or None,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class BertRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000)


class BertResponse(BaseModel):
    threat_level: int = Field(..., ge=0, le=100)
    category: str = Field(..., pattern="^(safe|spam|phishing)$")
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    model: str
    reasoning: str


class LinkItem(BaseModel):
    href: str
    text: str | None = None


class HeuristicItem(BaseModel):
    check: str
    points: int | float | None = None
    detail: str | None = None
    kind: str | None = None


class Tier1Result(BaseModel):
    score: int = Field(..., ge=0, le=100)
    category: str = Field(..., pattern="^(safe|spam|phishing)$")
    summary: str
    evidence: list[HeuristicItem] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    heuristics_score: int | None = Field(default=None, ge=0, le=100)
    ml_enabled: bool = False
    ml_threat_level: int | None = Field(default=None, ge=0, le=100)
    ml_category: str | None = Field(default=None, pattern="^(safe|spam|phishing)$")
    ml_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ml_label: str | None = None
    ml_model: str | None = None
    ml_reasoning: str | None = None


class EmailMeta(BaseModel):
    subject: str | None = None
    senderEmail: str | None = None
    senderName: str | None = None


class Tier1Report(BaseModel):
    version: int = 1
    event_id: str | None = None
    scan_id: str
    created_at: str
    source: str = "chrome_sidepanel"
    email: EmailMeta = Field(default_factory=EmailMeta)
    links: list[LinkItem] = Field(default_factory=list)
    tier1: Tier1Result


def _category_from_verdict(verdict: str | None) -> str:
    v = (verdict or "").strip().upper()
    if v == "CRITICAL":
        return "phishing"
    if v == "SUSPICIOUS":
        return "spam"
    return "safe"


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def _coerce_extension_report(report: dict[str, Any]) -> Tier1Report:
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

    tier_details = (
        report.get("tier_details", {}) if isinstance(report.get("tier_details"), dict) else {}
    )
    tier1_details = (
        tier_details.get("tier1", {}) if isinstance(tier_details.get("tier1"), dict) else {}
    )
    tier2_details = (
        tier_details.get("tier2", {}) if isinstance(tier_details.get("tier2"), dict) else {}
    )
    nested_threat = (
        tier_details.get("threat_analysis", {})
        if isinstance(tier_details.get("threat_analysis"), dict)
        else {}
    )
    threat_analysis = (
        report.get("threat_analysis", {}) if isinstance(report.get("threat_analysis"), dict) else {}
    )
    heuristics_score = tier1_details.get("score")
    ml_threat_level = tier2_details.get("score")
    if ml_threat_level is None:
        ml_threat_level = nested_threat.get("score")

    reasons_raw = report.get("reasons")
    reasons = [str(r) for r in reasons_raw] if isinstance(reasons_raw, list) else []
    if not reasons:
        reasons = [e.detail for e in evidence_list if e.detail]

    links_raw = report.get("links", [])
    links: list[LinkItem] = []
    if isinstance(links_raw, list):
        for l in links_raw:
            if isinstance(l, dict):
                href = str(l.get("href") or "").strip()
                text = l.get("text")
                if href:
                    links.append(
                        LinkItem(href=href, text=str(text) if isinstance(text, str) else None)
                    )
            else:
                href = str(l).strip()
                if href:
                    links.append(LinkItem(href=href, text=None))

    score_raw = report.get("final_score", 0)
    try:
        score = int(round(float(score_raw)))
    except Exception:
        score = 0
    score = max(0, min(100, score))
    score_verdict = _verdict_from_score(score)
    # Keep category/verdict consistent with score for live UI severity.
    verdict = score_verdict
    category = _category_from_verdict(verdict)

    summary = str(
        (threat_analysis.get("reasoning") if isinstance(threat_analysis, dict) else None)
        or f"Scan update: {verdict}"
    )

    return Tier1Report(
        event_id=(str(report.get("event_id")) if report.get("event_id") is not None else None),
        scan_id=str(report.get("scan_id") or f"ext_{time.time()}"),
        created_at=str(report.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S")),
        source=str(report.get("source") or "extension"),
        email=EmailMeta(
            subject=str(report.get("subject") or "No Subject"),
            senderEmail=str(report.get("sender") or "unknown@unknown.com"),
            senderName=None,
        ),
        links=links,
        tier1=Tier1Result(
            score=score,
            category=category,
            summary=summary,
            evidence=evidence_list,
            reasons=reasons,
            heuristics_score=heuristics_score,
            ml_enabled=True,
            ml_threat_level=ml_threat_level,
            ml_category=category,
            ml_confidence=None,
            ml_label=verdict,
            ml_model="ZeroPhish 3-Tier",
            ml_reasoning=str(threat_analysis.get("reasoning") or ""),
        ),
    )


_pipeline: Any | None = None
_pipeline_model_id: str | None = None

_cache: "OrderedDict[str, tuple[float, BertResponse]]" = OrderedDict()
_CACHE_MAX = 256
_CACHE_TTL_SEC = 60 * 10  # 10 minutes


def _cache_get(key: str) -> BertResponse | None:
    """Retrieve cached BERT response if available and not expired."""
    item = _cache.get(key)
    if not item:
        return None
    ts, value = item
    if time.time() - ts > _CACHE_TTL_SEC:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return value


def _cache_put(key: str, value: BertResponse) -> None:
    """Store BERT response in cache with timestamp."""
    _cache[key] = (time.time(), value)
    _cache.move_to_end(key)
    while len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)


def _label_to_risk(label: str, confidence: float) -> float:
    """Convert model label and confidence to risk score (0-100)."""
    l = (label or "").strip().lower()
    if any(k in l for k in ("phish", "spam", "scam", "fraud", "malicious")):
        return confidence * 100.0
    if any(k in l for k in ("ham", "safe", "legit", "benign")):
        return (1.0 - confidence) * 100.0

    # Common binary label conventions
    if l in {"negative", "label_1"}:
        return confidence * 100.0
    if l in {"positive", "label_0"}:
        return (1.0 - confidence) * 100.0

    # Fallback: treat confidence as risk
    return confidence * 100.0


def _load_pipeline() -> tuple[Any, str]:
    """Load or retrieve cached HuggingFace pipeline for text classification."""
    global _pipeline, _pipeline_model_id

    if os.getenv("ZERO_PHISH_DISABLE_ML", "").strip() in {"1", "true", "yes"}:
        raise RuntimeError("Local ML disabled (ZERO_PHISH_DISABLE_ML).")

    model_id = os.getenv(
        "ZERO_PHISH_HF_MODEL",
        "distilbert-base-uncased-finetuned-sst-2-english",
    ).strip()

    if _pipeline is not None and _pipeline_model_id == model_id:
        return _pipeline, model_id

    try:
        from transformers import pipeline
    except Exception as e:  # pragma: no cover
        raise RuntimeError(f"transformers not installed: {e}") from e

    _pipeline = pipeline("text-classification", model=model_id)
    _pipeline_model_id = model_id
    return _pipeline, model_id


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


_latest_tier1_report: Tier1Report | None = None
_tier1_stream_queues: set["asyncio.Queue[Tier1Report]"] = set()


@app.get("/tier1/latest", response_model=Tier1Report | None)
def tier1_latest() -> Tier1Report | None:
    return _latest_tier1_report


@app.post("/tier1/report", response_model=Tier1Report)
async def tier1_report(report: Tier1Report | dict[str, Any]) -> Tier1Report:
    global _latest_tier1_report
    normalized = report if isinstance(report, Tier1Report) else _coerce_extension_report(report)
    _latest_tier1_report = normalized

    dead: list[asyncio.Queue[Tier1Report]] = []
    for q in list(_tier1_stream_queues):
        try:
            q.put_nowait(normalized)
        except Exception:
            dead.append(q)

    for q in dead:
        _tier1_stream_queues.discard(q)

    return normalized


@app.get("/tier1/stream")
async def tier1_stream(request: Request) -> StreamingResponse:
    q: "asyncio.Queue[Tier1Report]" = asyncio.Queue(maxsize=50)
    _tier1_stream_queues.add(q)

    async def gen():
        try:
            # Send last known report immediately (useful on refresh).
            if _latest_tier1_report is not None:
                yield f"data: {_latest_tier1_report.model_dump_json()}\n\n"

            # Keepalive + stream updates.
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {item.model_dump_json()}\n\n"
                except asyncio.TimeoutError:
                    yield "event: ping\ndata: {}\n\n"
        finally:
            _tier1_stream_queues.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/tier1/bert", response_model=BertResponse)
def tier1_bert(req: BertRequest) -> BertResponse:
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="text is required")

    key = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    cached = _cache_get(key)
    if cached:
        return cached

    try:
        clf, model_id = _load_pipeline()
        out = clf(text, truncation=True)
        if not out or not isinstance(out, list):
            raise RuntimeError("Unexpected model output")
        top = out[0]
        label = str(top.get("label", "unknown"))
        confidence = float(top.get("score", 0.0))
        risk = _label_to_risk(label, confidence)

        res = BertResponse(
            threat_level=int(round(max(0.0, min(100.0, risk)))),
            category=("phishing" if risk >= 60 else "spam" if risk >= 20 else "safe"),
            label=label,
            confidence=max(0.0, min(1.0, confidence)),
            model=model_id,
            reasoning="Local BERT-style classifier score (tune ZERO_PHISH_HF_MODEL for phishing/spam).",
        )
        _cache_put(key, res)
        return res
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML inference failed: {e}") from e
