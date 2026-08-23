"""
ZeroPhish API Gateway & Central Application Server.
Orchestrates Tier 1 (client), Tier 2 (metadata), and Tier 3 (AI) analysis.
Final Score = (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.5)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.background import BackgroundTask

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from circuit_breaker import CircuitBreaker
from gateway_circuit_wrapper import execute_tier3_with_circuit_breaker
from models.gateway_models import (
    DomainAnalysis,
    GatewayScanRequest,
    GatewayScanResponse,
    ScanStatusResponse,
    ScoringWeights,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
)
from repositories.factory import get_scan_result_repository
from security.middleware import (
    InputValidator,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from tier_2 import ThreatAnalyzer, analyze_domain_age, get_domain_age

# ── New feature modules ────────────────────────────────────────────────────────
try:
    from analytics.router import router as analytics_router
    from analytics.service import AnalyticsService
    from auth.router import router as auth_router
    from awareness.router import router as awareness_router
    from email_scanner.router import router as email_router
    from incidents.router import router as incidents_router
    from vision.router import router as vision_router
    from webhooks.models import WebhookEventType
    from webhooks.router import router as webhooks_router
    from webhooks.service import WebhookService

    EXTENSIONS_AVAILABLE = True
except ImportError as _ext_err:
    _logging = logging.getLogger(__name__)
    _logging.warning("Extension modules not fully loaded: %s", _ext_err)
    EXTENSIONS_AVAILABLE = False

load_dotenv()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    expected_api_key = os.getenv("API_KEY")
    if not expected_api_key:
        return api_key
    if not api_key or api_key != expected_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate API key"
        )
    return api_key


TIER3_TIMEOUT = int(os.getenv("TIER3_TIMEOUT", "5"))
WEIGHTS = ScoringWeights()
SCAN_HISTORY_LIMIT = int(os.getenv("GATEWAY_SCAN_HISTORY_LIMIT", "500"))

CIRCUIT_BREAKER_ENABLED = os.getenv("CIRCUIT_BREAKER_ENABLED", "true").lower() == "true"
CIRCUIT_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
CIRCUIT_TIMEOUT = float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "30"))
CIRCUIT_WINDOW = float(os.getenv("CIRCUIT_BREAKER_WINDOW", "60"))

tier3_circuit_breaker = (
    CircuitBreaker(
        failure_threshold=CIRCUIT_FAILURE_THRESHOLD,
        timeout=CIRCUIT_TIMEOUT,
        window=CIRCUIT_WINDOW,
        name="tier3_ai_analysis",
    )
    if CIRCUIT_BREAKER_ENABLED
    else None
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("ZeroPhish API Gateway starting...")
    print("=" * 60)
    print(f"Scoring Formula: T1*{WEIGHTS.tier1} + T2*{WEIGHTS.tier2} + T3*{WEIGHTS.tier3}")
    print(f"Tier 3 Timeout: {TIER3_TIMEOUT}s")
    yield
    print("ZeroPhish API Gateway shutting down...")


app = FastAPI(
    title="ZeroPhish API Gateway",
    description="AI-powered phishing detection — 3-tier analysis + auth, webhooks, incidents, analytics.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=1_000_000)

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if o.strip() and o.strip() != "chrome-extension://*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=os.getenv("ALLOW_ORIGIN_REGEX"),
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Cookie", "X-API-Key", "X-Request-ID"],
    allow_credentials=True,
    expose_headers=["X-Request-ID"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: Exception) -> Response:
    if isinstance(exc, RateLimitExceeded):
        return _rate_limit_exceeded_handler(request, exc)
    raise exc


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# Register extension routers
if EXTENSIONS_AVAILABLE:
    app.include_router(auth_router)
    app.include_router(webhooks_router)
    app.include_router(incidents_router)
    app.include_router(email_router)
    app.include_router(analytics_router)
    app.include_router(awareness_router)
    app.include_router(vision_router)

# In-process scan time tracker and SSE broadcast queues
scan_started_at: Dict[str, float] = {}
scan_results_lock = asyncio.Lock()
_latest_tier1_report: Optional[Dict[str, Any]] = None
_sse_subscribers: Dict[str, asyncio.Queue] = {}


def _clamp_score(score: float) -> float:
    return max(0.0, min(100.0, float(score)))


def _round_score(score: float) -> float:
    return round(_clamp_score(score), 2)


def _determine_verdict(score: float) -> str:
    if score < 30:
        return "SAFE"
    if score < 70:
        return "SUSPICIOUS"
    return "CRITICAL"


def _determine_threat_status(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "SUSPICIOUS"
    return "OK"


def _calculate_weighted_score(scores: list[float], weights: list[float]) -> float:
    """
    Unified weighted score calculation with fallback to simple average.
    Ensures final score is clamped between 0 and 100.
    """
    if not scores:
        return 0.0

    if len(scores) != len(weights):
        raise ValueError("Scores and weights must have the same length")

    total_weight = sum(weights)
    if total_weight <= 0:
        return _clamp_score(sum(scores) / len(scores))

    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    return _clamp_score(weighted_sum / total_weight)


def _calculate_partial_score(tier1_score: float, tier2_score: float) -> float:
    return _calculate_weighted_score([tier1_score, tier2_score], [WEIGHTS.tier1, WEIGHTS.tier2])


def _calculate_final_score(tier1_score: float, tier2_score: float, tier3_score: float) -> float:
    return _calculate_weighted_score(
        [tier1_score, tier2_score, tier3_score],
        [WEIGHTS.tier1, WEIGHTS.tier2, WEIGHTS.tier3],
    )


def _merge_evidence(
    tier1_evidence: list[str], tier2_evidence: list[str], tier3_flagged_phrases: list[str] | None
) -> list[str]:
    merged: list[str] = []

    for item in tier1_evidence:
        text = str(item).strip()
        if text:
            merged.append(text)

    for item in tier2_evidence:
        text = str(item).strip()
        if text:
            merged.append(text)

    for phrase in tier3_flagged_phrases or []:
        text = str(phrase).strip()
        if text:
            merged.append(f"AI: {text}")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in merged:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


async def _notify_live_dashboard(res: GatewayScanResponse, sender: str, subject: str) -> None:
    """Broadcast scan update to in-process SSE queues and optional external dashboard."""
    global _latest_tier1_report

    payload = {
        "scan_id": res.scan_id,
        "timestamp": res.timestamp,
        "sender": sender,
        "subject": subject,
        "final_score": res.final_score if res.final_score is not None else res.partial_score,
        "verdict": res.verdict,
        "layers_completed": res.layers_completed,
        "evidence": res.combined_evidence,
        "threat_analysis": {
            "category": res.tier3.category if res.tier3 else "Processing",
            "reasoning": res.tier3.reasoning if res.tier3 else "Awaiting AI Analysis",
        },
        "tier_details": {
            "tier1": {"score": res.tier1.score},
            "tier2": {"score": res.tier2.score},
            "tier3": {"score": res.tier3.score if res.tier3 else 0},
        },
    }

    _latest_tier1_report = payload

    # Broadcast to all live SSE subscribers in-process
    dead_subscribers = []
    for sub_id, q in list(_sse_subscribers.items()):
        try:
            q.put_nowait(payload)
        except Exception:
            dead_subscribers.append(sub_id)

    for sub_id in dead_subscribers:
        _sse_subscribers.pop(sub_id, None)

    # Optional webhook/external URL notification
    live_url = os.getenv("LIVE_DASHBOARD_URL")
    if live_url and "8001" not in live_url:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                await client.post(live_url, json=payload, timeout=2.0)
        except Exception as e:
            logging.getLogger(__name__).debug(
                "External live dashboard notify skipped/failed: %s", str(e)[:200]
            )


async def execute_tier2(sender: str, body: str, links: list[str]) -> Tier2Result:
    start_time = time.perf_counter()
    evidence: list[str] = []

    try:
        domain = sender.split("@")[-1].strip().lower() if "@" in sender else ""
        if not domain:
            domain_score, domain_status = 70.0, "UNKNOWN"
            evidence.append("Could not parse sender domain.")
        else:
            age_days = await asyncio.to_thread(get_domain_age, domain)
            domain_score, domain_status, msg = analyze_domain_age(age_days)
            evidence.append(msg)

        threat_data = await ThreatAnalyzer.analyze_threat(
            email_body=body,
            sender=sender,
            links=links,
        )

        threat_score = _clamp_score(threat_data.threat_level)
        threat_status = _determine_threat_status(threat_score)
        tier2_score = _calculate_weighted_score([domain_score, threat_score], [0.3, 0.7])

        if threat_data.category != "Safe":
            evidence.append(f"Threat indicators detected: {threat_data.category}.")
        if threat_data.flagged_phrases:
            evidence.append(f"Flagged phrases: {', '.join(threat_data.flagged_phrases[:3])}")

        return Tier2Result(
            score=_round_score(tier2_score),
            domain_analysis=DomainAnalysis(
                status=domain_status,
                score=_round_score(domain_score),
                weight=0.3,
            ),
            threat_analysis=Tier2Analysis(
                status=threat_status,
                score=_round_score(threat_score),
                weight=0.7,
            ),
            threat_details=ThreatAnalysisDetail(
                threat_level=int(round(threat_score)),
                category=threat_data.category,
                reasoning=threat_data.reasoning,
                flagged_phrases=threat_data.flagged_phrases[:10],
            ),
            evidence=evidence,
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
        )
    except Exception as exc:
        return Tier2Result(
            score=50.0,
            domain_analysis=DomainAnalysis(status="ERROR", score=50.0),
            threat_analysis=Tier2Analysis(status="ERROR", score=50.0),
            threat_details=ThreatAnalysisDetail(
                threat_level=50,
                category="Error",
                reasoning=f"Tier 2 failed: {type(exc).__name__}",
                flagged_phrases=[],
            ),
            evidence=["Tier 2 processing error"],
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
        )


async def _finalize_tier3(
    scan_id: str, email_body: str, sender: Optional[str] = None, subject: Optional[str] = None
) -> None:
    try:
        tier3_result = await execute_tier3_with_circuit_breaker(
            body=email_body,
            circuit_breaker=tier3_circuit_breaker,
            tier3_timeout=TIER3_TIMEOUT,
        )
    except Exception as exc:  # pragma: no cover
        tier3_result = Tier3Result(
            score=50,
            category="Error",
            reasoning=f"Tier 3 failed: {type(exc).__name__}",
            flagged_phrases=[],
            status="failed",
        )

    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        existing = scan_repo.get(scan_id)
        if not existing:
            return

        final_score = _round_score(
            _calculate_final_score(existing.tier1.score, existing.tier2.score, tier3_result.score)
        )
        final_verdict = _determine_verdict(final_score)
        total_ms = None
        if scan_id in scan_started_at:
            total_ms = (time.perf_counter() - scan_started_at[scan_id]) * 1000

        sender_meta = existing.sender or sender or "unknown@unknown.com"
        subject_meta = existing.subject or subject or "No Subject"

        updated = existing.model_copy(
            update={
                "tier3": tier3_result,
                "tier3_status": tier3_result.status,
                "complete": True,
                "layers_completed": 3,
                "final_score": final_score,
                "verdict": final_verdict,
                "combined_evidence": _merge_evidence(
                    existing.tier1.evidence,
                    existing.tier2.evidence,
                    tier3_result.flagged_phrases,
                ),
                "total_execution_time_ms": total_ms,
                "sender": sender_meta,
                "subject": subject_meta,
            }
        )
        scan_repo.save(scan_id, updated)

        # Notify dashboard of final result (Level 3)
        asyncio.create_task(_notify_live_dashboard(updated, sender_meta, subject_meta))

    # Fire webhooks and record analytics (outside the lock)
    if EXTENSIONS_AVAILABLE:
        payload = updated.model_dump()
        await WebhookService.fire(WebhookEventType.SCAN_COMPLETE, payload)
        if final_verdict == "CRITICAL":
            await WebhookService.fire(WebhookEventType.SCAN_CRITICAL, payload)
        elif final_verdict == "SUSPICIOUS":
            await WebhookService.fire(WebhookEventType.SCAN_SUSPICIOUS, payload)

        # Record telemetry
        AnalyticsService.record_scan(
            scan_id=scan_id,
            sender=sender_meta,
            subject=subject_meta,
            final_score=final_score,
            verdict=final_verdict,
            category=updated.tier2.threat_details.category if updated.tier2 else "Unknown",
            tier1=float(existing.tier1.score),
            tier2=float(existing.tier2.score) if existing.tier2 else 0,
            tier3=float(tier3_result.score),
        )


@app.post("/gateway/scan", response_model=GatewayScanResponse)
@limiter.limit("20/minute")
async def gateway_scan(
    request: Request,
    scan_request: GatewayScanRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
) -> GatewayScanResponse:
    validation = InputValidator.validate_scan_request(
        sender=scan_request.sender,
        body=scan_request.body,
        links=scan_request.links,
        subject=scan_request.subject,
    )
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail={"errors": validation["errors"]})

    scan_id = str(uuid.uuid4())
    scan_started_at[scan_id] = time.perf_counter()

    tier1_score = int(round(_clamp_score(scan_request.tier1_score)))
    tier1 = Tier1Result(
        score=tier1_score,
        evidence=[str(e) for e in scan_request.tier1_evidence][:50],
        status="Suspicious" if tier1_score >= 20 else "Clean",
    )

    tier2 = await execute_tier2(
        sender=scan_request.sender,
        body=scan_request.body,
        links=scan_request.links,
    )

    partial_score = _round_score(_calculate_partial_score(tier1.score, tier2.score))
    verdict = _determine_verdict(partial_score)
    response = GatewayScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now().isoformat(),
        partial_score=partial_score,
        final_score=None,
        verdict=verdict,
        tier1=tier1,
        tier2=tier2,
        tier3=None,
        tier3_status="processing",
        complete=False,
        layers_completed=2,
        combined_evidence=_merge_evidence(tier1.evidence, tier2.evidence, None),
        weights=WEIGHTS,
        sender=scan_request.sender,
        subject=scan_request.subject or "No Subject",
        total_execution_time_ms=(time.perf_counter() - scan_started_at[scan_id]) * 1000,
    )

    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        scan_repo.save(scan_id, response)

    # Notify dashboard of partial result (Level 2)
    asyncio.create_task(
        _notify_live_dashboard(response, scan_request.sender, scan_request.subject or "No Subject")
    )

    background_tasks.add_task(
        _finalize_tier3, scan_id, scan_request.body, scan_request.sender, scan_request.subject
    )
    return response


@app.get("/gateway/status/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("120/minute")
async def gateway_status(
    request: Request, scan_id: str, api_key: str = Depends(verify_api_key)
) -> ScanStatusResponse:
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        result = scan_repo.get(scan_id)

    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")

    estimated_completion_ms = None
    if not result.complete and scan_id in scan_started_at:
        elapsed_ms = (time.perf_counter() - scan_started_at[scan_id]) * 1000
        estimated_completion_ms = max(0, int((TIER3_TIMEOUT * 1000) - elapsed_ms))

    return ScanStatusResponse(
        scan_id=scan_id,
        complete=result.complete,
        layers_completed=result.layers_completed,
        tier3_status=result.tier3_status,
        final_score=result.final_score,
        verdict=result.verdict,
        tier3=result.tier3,
        estimated_completion_ms=estimated_completion_ms,
    )


@app.get("/gateway/result/{scan_id}", response_model=GatewayScanResponse)
@limiter.limit("120/minute")
async def gateway_result(
    request: Request, scan_id: str, api_key: str = Depends(verify_api_key)
) -> GatewayScanResponse:
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        result = scan_repo.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    return result


@app.get("/gateway/health")
async def gateway_health() -> dict:
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        total_scans = scan_repo.count()
        pending_scans = scan_repo.count_pending()

    return {
        "status": "healthy",
        "service": "ZeroPhish API Gateway",
        "timestamp": datetime.now().isoformat(),
        "weights": WEIGHTS.model_dump(),
        "tier3_timeout_sec": TIER3_TIMEOUT,
        "scans": {
            "total_cached": total_scans,
            "pending": pending_scans,
            "history_limit": SCAN_HISTORY_LIMIT,
        },
        "circuit_breaker": tier3_circuit_breaker.get_status() if tier3_circuit_breaker else None,
    }


@app.get("/gateway/circuit/status")
async def gateway_circuit_status() -> dict:
    if not tier3_circuit_breaker:
        return {"enabled": False, "status": "disabled"}
    return {"enabled": True, **tier3_circuit_breaker.get_status()}


@app.get("/gateway/circuit/reset")
@app.post("/gateway/circuit/reset")
async def gateway_circuit_reset() -> dict:
    if not tier3_circuit_breaker:
        return {"enabled": False, "status": "disabled"}
    tier3_circuit_breaker.reset()
    return {"enabled": True, "status": "reset", **tier3_circuit_breaker.get_status()}


# ── Direct Live SSE Stream Endpoints (Unified Gateway) ──────────────────────────


@app.get("/tier1/latest")
async def get_latest_tier1_scan() -> Optional[Dict[str, Any]]:
    """Return the most recent scan report for dashboard refresh."""
    return _latest_tier1_report


@app.post("/tier1/report")
async def receive_tier1_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Receive scan report from Chrome Extension or internal pipeline."""
    global _latest_tier1_report
    _latest_tier1_report = report

    dead = []
    for sub_id, q in list(_sse_subscribers.items()):
        try:
            q.put_nowait(report)
        except Exception:
            dead.append(sub_id)

    for sub_id in dead:
        _sse_subscribers.pop(sub_id, None)

    return {"status": "success", "message": "Report received"}


@app.get("/tier1/stream")
async def stream_tier1_scans(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for real-time frontend scan updates."""
    sub_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_subscribers[sub_id] = q

    async def event_generator():
        yield f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
        if _latest_tier1_report:
            yield f"data: {json.dumps(_latest_tier1_report)}\n\n"

        while True:
            if await request.is_disconnected():
                break
            try:
                item = await asyncio.wait_for(q.get(), timeout=10.0)
                yield f"data: {json.dumps(item)}\n\n"
            except asyncio.TimeoutError:
                yield f"event: ping\ndata: {json.dumps({'status': 'alive'})}\n\n"
            except Exception:
                break

    async def cleanup():
        _sse_subscribers.pop(sub_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
        background=BackgroundTask(cleanup),
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("GATEWAY_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
