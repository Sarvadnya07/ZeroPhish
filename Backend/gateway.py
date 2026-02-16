"""
ZeroPhish API Gateway
Orchestrates Tier 1 (client), Tier 2 (metadata), and Tier 3 (AI) analysis
with weighted scoring: Final Score = (T1 × 0.2) + (T2 × 0.3) + (T3 × 0.5)
"""

import asyncio
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ----------------------------------------------------------------------------
# Security imports
# ----------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from security.middleware import (
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
)

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
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

# ----------------------------------------------------------------------------
# Circuit Breaker + Tier Imports
# ----------------------------------------------------------------------------
from circuit_breaker import CircuitBreaker
from tier_2.main import ThreatAnalyzer, get_domain_age
from tier_3.main import analyze_email_intent

# ----------------------------------------------------------------------------
# Environment
# ----------------------------------------------------------------------------
load_dotenv()

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
TIER3_TIMEOUT = int(os.getenv("TIER3_TIMEOUT", "5"))
WEIGHTS = ScoringWeights()

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

# ----------------------------------------------------------------------------
# Lifespan
# ----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("🚀 ZeroPhish API Gateway Starting...")
    print("=" * 60)
    print(f"📊 Scoring Formula: T1×{WEIGHTS.tier1} + T2×{WEIGHTS.tier2} + T3×{WEIGHTS.tier3}")
    print(f"⏱️ Tier 3 Timeout: {TIER3_TIMEOUT}s")
    yield
    print("\n🛑 ZeroPhish API Gateway shutting down...")


app = FastAPI(
    title="ZeroPhish API Gateway",
    version="1.0.0",
    lifespan=lifespan,
)

# ----------------------------------------------------------------------------
# Middleware
# ----------------------------------------------------------------------------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=1_000_000)

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

# ----------------------------------------------------------------------------
# Rate Limiting (FINAL CORRECT VERSION)
# ----------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: Exception) -> Response:
    """
    Proper wrapper compatible with both sync and async slowapi handlers.
    """
    if isinstance(exc, RateLimitExceeded):
        result = _rate_limit_exceeded_handler(request, exc)
        return result
    raise exc



app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# ----------------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------------
scan_results: Dict[str, GatewayScanResponse] = {}
scan_results_lock = asyncio.Lock()

# ----------------------------------------------------------------------------
# Tier 2
# ----------------------------------------------------------------------------
async def execute_tier2(sender: str, body: str, links: list) -> Tier2Result:
    start_time = time.time()
    try:
        domain = sender.split("@")[-1]
        age_days = await asyncio.to_thread(get_domain_age, domain)

        if age_days == 0:
            domain_score, domain_status = 70, "UNKNOWN"
        elif age_days < 30:
            domain_score, domain_status = 100, "CRITICAL"
        elif age_days < 365:
            domain_score, domain_status = 60, "SUSPICIOUS"
        else:
            domain_score, domain_status = 10, "OK"

        threat_data = await ThreatAnalyzer.analyze_threat(
            email_body=body, sender=sender, links=links
        )

        threat_score = threat_data.threat_level
        tier2_score = (domain_score * 0.3) + (threat_score * 0.7)

        return Tier2Result(
            score=tier2_score,
            domain_analysis=DomainAnalysis(status=domain_status, score=domain_score, weight=0.3),
            threat_analysis=Tier2Analysis(status="OK", score=threat_score, weight=0.7),
            threat_details=ThreatAnalysisDetail(
                threat_level=threat_score,
                category=threat_data.category,
                reasoning=threat_data.reasoning,
                flagged_phrases=threat_data.flagged_phrases,
            ),
            evidence=[],
            execution_time_ms=(time.time() - start_time) * 1000,
        )
    except Exception:
        return Tier2Result(
            score=50,
            domain_analysis=DomainAnalysis(status="ERROR", score=50),
            threat_analysis=Tier2Analysis(status="ERROR", score=50),
            threat_details=ThreatAnalysisDetail(
                threat_level=50,
                category="Error",
                reasoning="Tier 2 failed",
                flagged_phrases=[],
            ),
            evidence=["Tier 2 error"],
            execution_time_ms=(time.time() - start_time) * 1000,
        )

# ----------------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------------
def calculate_partial_score(t1: int, t2: float) -> float:
    return (t1 * 0.33) + (t2 * 0.67)

def determine_verdict(score: float) -> str:
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    return "CRITICAL"

# ----------------------------------------------------------------------------
# Endpoint
# ----------------------------------------------------------------------------
@app.post("/gateway/scan", response_model=GatewayScanResponse)
@limiter.limit("20/minute")
async def gateway_scan(
    request: Request,
    scan_request: GatewayScanRequest,
    background_tasks: BackgroundTasks,
):
    scan_id = str(uuid.uuid4())

    tier1 = Tier1Result(
        score=scan_request.tier1_score,
        evidence=scan_request.tier1_evidence,
        status="Suspicious" if scan_request.tier1_score > 0 else "Clean",
    )

    tier2 = await execute_tier2(
        scan_request.sender,
        scan_request.body,
        scan_request.links,
    )

    partial_score = calculate_partial_score(tier1.score, tier2.score)
    verdict = determine_verdict(partial_score)

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
        combined_evidence=[],
        weights=WEIGHTS,
        total_execution_time_ms=0,
    )

    async with scan_results_lock:
        scan_results[scan_id] = response

    return response

# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("GATEWAY_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
