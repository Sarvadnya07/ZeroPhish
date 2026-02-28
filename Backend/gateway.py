"""
ZeroPhish API Gateway
Orchestrates Tier 1 (client), Tier 2 (metadata), and Tier 3 (AI) analysis.
Final Score = (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.5)
"""

import asyncio
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

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
from security.middleware import (
    InputValidator,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from tier_2.main import ThreatAnalyzer, get_domain_age

load_dotenv()

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
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=1_000_000)

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip() and o.strip() != "chrome-extension://*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=os.getenv("ALLOW_ORIGIN_REGEX") or None,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: Exception) -> Response:
    if isinstance(exc, RateLimitExceeded):
        return _rate_limit_exceeded_handler(request, exc)
    raise exc


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

scan_results: Dict[str, GatewayScanResponse] = {}
scan_started_at: Dict[str, float] = {}
scan_results_lock = asyncio.Lock()


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


def _calculate_partial_score(tier1_score: float, tier2_score: float) -> float:
    partial_weight = WEIGHTS.tier1 + WEIGHTS.tier2
    if partial_weight <= 0:
        return _clamp_score((tier1_score + tier2_score) / 2.0)
    partial = (tier1_score * WEIGHTS.tier1) + (tier2_score * WEIGHTS.tier2)
    return _clamp_score(partial / partial_weight)


def _calculate_final_score(tier1_score: float, tier2_score: float, tier3_score: float) -> float:
    total_weight = WEIGHTS.tier1 + WEIGHTS.tier2 + WEIGHTS.tier3
    if total_weight <= 0:
        return _clamp_score((tier1_score + tier2_score + tier3_score) / 3.0)
    total = (
        (tier1_score * WEIGHTS.tier1)
        + (tier2_score * WEIGHTS.tier2)
        + (tier3_score * WEIGHTS.tier3)
    )
    return _clamp_score(total / total_weight)


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
    return deduped[:50]


def _trim_scan_history() -> None:
    while len(scan_results) > SCAN_HISTORY_LIMIT:
        oldest_scan_id = next(iter(scan_results))
        scan_results.pop(oldest_scan_id, None)
        scan_started_at.pop(oldest_scan_id, None)


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
            if age_days == 0:
                domain_score, domain_status = 70.0, "UNKNOWN"
                evidence.append("Could not verify domain age.")
            elif age_days < 30:
                domain_score, domain_status = 100.0, "CRITICAL"
                evidence.append(f"Domain is very new ({age_days} days old).")
            elif age_days < 365:
                domain_score, domain_status = 60.0, "SUSPICIOUS"
                evidence.append(f"Domain is relatively new ({age_days} days old).")
            else:
                domain_score, domain_status = 10.0, "OK"
                evidence.append(f"Domain is established ({age_days} days old).")

        threat_data = await ThreatAnalyzer.analyze_threat(
            email_body=body,
            sender=sender,
            links=links,
        )

        threat_score = _clamp_score(threat_data.threat_level)
        threat_status = _determine_threat_status(threat_score)
        tier2_score = (domain_score * 0.3) + (threat_score * 0.7)

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


async def _finalize_tier3(scan_id: str, email_body: str) -> None:
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

    async with scan_results_lock:
        existing = scan_results.get(scan_id)
        if not existing:
            return

        final_score = _round_score(
            _calculate_final_score(existing.tier1.score, existing.tier2.score, tier3_result.score)
        )
        final_verdict = _determine_verdict(final_score)
        total_ms = None
        if scan_id in scan_started_at:
            total_ms = (time.perf_counter() - scan_started_at[scan_id]) * 1000

        updated = existing.model_copy(
            update={
                "tier3": tier3_result,
                "tier3_status": tier3_result.status,
                "complete": True,
                "final_score": final_score,
                "verdict": final_verdict,
                "combined_evidence": _merge_evidence(
                    existing.tier1.evidence,
                    existing.tier2.evidence,
                    tier3_result.flagged_phrases,
                ),
                "total_execution_time_ms": total_ms,
            }
        )
        scan_results[scan_id] = updated


@app.post("/gateway/scan", response_model=GatewayScanResponse)
@limiter.limit("20/minute")
async def gateway_scan(
    request: Request,
    scan_request: GatewayScanRequest,
    background_tasks: BackgroundTasks,
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
        combined_evidence=_merge_evidence(tier1.evidence, tier2.evidence, None),
        weights=WEIGHTS,
        total_execution_time_ms=(time.perf_counter() - scan_started_at[scan_id]) * 1000,
    )

    async with scan_results_lock:
        scan_results[scan_id] = response
        _trim_scan_history()

    background_tasks.add_task(_finalize_tier3, scan_id, scan_request.body)
    return response


@app.get("/gateway/status/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("120/minute")
async def gateway_status(request: Request, scan_id: str) -> ScanStatusResponse:
    async with scan_results_lock:
        result = scan_results.get(scan_id)

    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")

    estimated_completion_ms = None
    if not result.complete and scan_id in scan_started_at:
        elapsed_ms = (time.perf_counter() - scan_started_at[scan_id]) * 1000
        estimated_completion_ms = max(0, int((TIER3_TIMEOUT * 1000) - elapsed_ms))

    return ScanStatusResponse(
        scan_id=scan_id,
        complete=result.complete,
        tier3_status=result.tier3_status,
        final_score=result.final_score,
        verdict=result.verdict,
        tier3=result.tier3,
        estimated_completion_ms=estimated_completion_ms,
    )


@app.get("/gateway/result/{scan_id}", response_model=GatewayScanResponse)
@limiter.limit("120/minute")
async def gateway_result(request: Request, scan_id: str) -> GatewayScanResponse:
    async with scan_results_lock:
        result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    return result


@app.get("/gateway/health")
async def gateway_health() -> dict:
    async with scan_results_lock:
        total_scans = len(scan_results)
        pending_scans = sum(1 for v in scan_results.values() if not v.complete)

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


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("GATEWAY_PORT", "8001"))
