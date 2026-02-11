from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field


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
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    model: str
    reasoning: str


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
