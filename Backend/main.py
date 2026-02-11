from __future__ import annotations

import asyncio
import hashlib
import os
import time
from collections import OrderedDict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
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
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    model: str
    reasoning: str


class ScanRequest(BaseModel):
    """Full email scan request across all three Tiers."""
    sender: str = Field(..., min_length=1, max_length=500, description="Sender email address")
    subject: str = Field(default="", max_length=500, description="Email subject line")
    body: str = Field(..., min_length=1, max_length=10000, description="Full email body text")


class ScanResponse(BaseModel):
    """Unified response combining Tier 1 (Rules), Tier 2 (Metadata), Tier 3 (AI)."""
    final_score: float = Field(..., ge=0.0, le=100.0, description="Weighted composite threat score")
    tier1: dict[str, Any] = Field(default_factory=dict, description="Rule-based detection results")
    tier2: dict[str, Any] = Field(default_factory=dict, description="Domain reputation and metadata results")
    tier3: T3Result = Field(..., description="AI semantic analysis results")
    recommendation: str = Field(..., description="Safe/Review/Quarantine")
    timestamp: float = Field(..., description="Unix timestamp of scan")


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


@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest) -> ScanResponse:
    """
    Unified email security scan combining Tiers 1, 2, and 3.
    
    - Tier 1: Rule-based detection (text patterns)
    - Tier 2: Domain/metadata reputation (IP, SPF, DKIM, etc.)
    - Tier 3: AI semantic analysis for zero-day phishing
    
    All tiers run in parallel to minimize latency (<3s target).
    """
    start_time = time.time()
    
    # Tier 1: Local text classification
    t1_task = asyncio.create_task(_tier1_scan(request.body))
    
    # Tier 2: Domain reputation (placeholder - integrate with actual service)
    t2_task = asyncio.create_task(_tier2_scan(request.sender))
    
    # Tier 3: AI semantic analysis
    t3_task = asyncio.create_task(analyze_email_intent(request.body))
    
    # Wait for all with 2.8s timeout (leave 0.2s buffer)
    try:
        t1_result, t2_result, t3_result = await asyncio.wait_for(
            asyncio.gather(t1_task, t2_task, t3_task, return_exceptions=False),
            timeout=2.8
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timeout: one or more tiers exceeded time limit")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    
    # Sentinel Scoring Formula: T1 (20%) + T2 (30%) + T3 (50%)
    t1_score = t1_result.get("threat_level", 0)
    t2_score = t2_result.get("score", 50)
    t3_score = t3_result.threat_score
    
    final_score = (t1_score * 0.2) + (t2_score * 0.3) + (t3_score * 0.5)
    final_score = max(0.0, min(100.0, final_score))
    
    # Determine recommendation based on final score
    if final_score >= 75:
        recommendation = "Quarantine"
    elif final_score >= 50:
        recommendation = "Review"
    else:
        recommendation = "Safe"
    
    return ScanResponse(
        final_score=final_score,
        tier1=t1_result,
        tier2=t2_result,
        tier3=t3_result,
        recommendation=recommendation,
        timestamp=time.time()
    )


async def _tier1_scan(email_body: str) -> dict[str, Any]:
    """Tier 1: Local BERT text classification (synchronous wrapped in async)."""
    try:
        bert_req = BertRequest(text=email_body[:4000])  # Respect model limit
        result = tier1_bert(bert_req)
        return {
            "threat_level": result.threat_level,
            "label": result.label,
            "confidence": result.confidence,
            "model": result.model,
            "reasoning": result.reasoning
        }
    except HTTPException:
        return {"threat_level": 0, "label": "unknown", "confidence": 0.0, "error": "T1 unavailable"}
    except Exception as e:
        return {"threat_level": 0, "label": "error", "confidence": 0.0, "error": str(e)}


async def _tier2_scan(sender_email: str) -> dict[str, Any]:
    """Tier 2: Domain reputation and metadata (placeholder for future integration)."""
    try:
        # TODO: Integrate with real T2 service (speed_layer.py)
        # For now, return neutral assessment
        domain = sender_email.split("@")[-1] if "@" in sender_email else "unknown"
        return {
            "domain": domain,
            "score": 50,  # Neutral default
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "reputation": "neutral"
        }
    except Exception as e:
        return {"domain": "unknown", "score": 50, "error": str(e)}
