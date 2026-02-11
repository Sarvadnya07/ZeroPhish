from __future__ import annotations

import hashlib
import os
import time
import asyncio
from collections import OrderedDict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from fastapi import Request
from pydantic import BaseModel, Field

from tier_3.main import T3Result, analyze_email_intent


app = FastAPI(title="ZeroPhish Tier 1 (Local)", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
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
    scan_id: str
    created_at: str
    source: str = "chrome_sidepanel"
    email: EmailMeta = Field(default_factory=EmailMeta)
    links: list[LinkItem] = Field(default_factory=list)
    tier1: Tier1Result


_pipeline: Any | None = None
_pipeline_model_id: str | None = None

_cache: "OrderedDict[str, tuple[float, BertResponse]]" = OrderedDict()
_CACHE_MAX = 256
_CACHE_TTL_SEC = 60 * 10  # 10 minutes


def _cache_get(key: str) -> BertResponse | None:
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
    _cache[key] = (time.time(), value)
    _cache.move_to_end(key)
    while len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)


def _label_to_risk(label: str, confidence: float) -> float:
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
        from transformers import pipeline  # type: ignore
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
async def tier1_report(report: Tier1Report) -> Tier1Report:
    global _latest_tier1_report
    _latest_tier1_report = report

    dead: list[asyncio.Queue[Tier1Report]] = []
    for q in list(_tier1_stream_queues):
        try:
            q.put_nowait(report)
        except Exception:
            dead.append(q)

    for q in dead:
        _tier1_stream_queues.discard(q)

    return report


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
