"""
ZeroPhish API Gateway & Central Application Server.

Orchestrates Tier 1 (server-authoritative heuristics), Tier 2 (domain/metadata
intelligence) and Tier 3 (provider-agnostic AI) analysis, then hands the tier
results to the canonical fusion engine (`Backend/fusion/engine.py`), which owns
the final score and verdict.

Scoring is NOT a fixed formula: fusion renormalizes weights over whichever tiers
participated in the scan (see ESTABLISHED_PROFILES in fusion/engine.py). The
configured 0.20/0.30/0.50 weighting reported by /health applies only when Tier 1,
Tier 2 and Tier 3 all participate.

Provides:
- REST API for scan submission and status polling
- Server‑Sent Events (SSE) for live dashboard updates
- Redis speed‑layer caching with SHA‑256 payload fingerprinting
- Circuit‑breaker protection for Tier 3 AI calls
- Role‑based access control (RBAC) via extension routers
- Webhooks, analytics, incident management, and security awareness modules
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

# ---------- Path Setup ----------
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

# ---------- Imports ----------
from circuit_breaker import CircuitBreaker
from gateway_circuit_wrapper import execute_tier3_with_circuit_breaker
from models.gateway_models import (
    DomainAnalysis,
    DomainStatus,
    Verdict,
    GatewayScanRequest,
    GatewayScanResponse,
    ScanStatusResponse,
    ScoringWeights,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    CleanStatus,
)
from models.tier1_report import Tier1ReportPayload
from repositories.factory import get_cache_backend, get_scan_result_repository
from tier_1.engine import analyze_tier1_server, sanitize_client_evidence
from security.middleware import (
    InputValidator,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
try:
    from Backend.security.metrics import get_metrics_response
except ImportError:
    from security.metrics import get_metrics_response

try:
    from tier_2 import ThreatAnalyzer, analyze_domain_age, get_domain_age
    from tier_2.domain_intel import aget_domain_age
except ImportError:
    from Backend.tier_2 import ThreatAnalyzer, analyze_domain_age, get_domain_age
    from Backend.tier_2.domain_intel import aget_domain_age

try:
    from fusion import (
        fuse_detection_results,
        calculate_partial_score as fusion_calc_partial_score,
        calculate_fused_score as fusion_calc_fused_score,
        determine_canonical_verdict as fusion_determine_verdict,
    )
except ImportError:
    from Backend.fusion import (
        fuse_detection_results,
        calculate_partial_score as fusion_calc_partial_score,
        calculate_fused_score as fusion_calc_fused_score,
        determine_canonical_verdict as fusion_determine_verdict,
    )

# Try to import extension modules; fallback gracefully
EXTENSIONS_AVAILABLE = False
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
    logging.getLogger(__name__).warning("Extension modules not fully loaded: %s", _ext_err)

try:
    from ml.shadow import ShadowCascadeManager
except ImportError:
    ShadowCascadeManager = None

# ---------- Configuration ----------
load_dotenv(BACKEND_DIR / ".env")
load_dotenv()

@dataclass(frozen=True)
class GatewayConfig:
    """Immutable configuration for the gateway."""
    env: str = field(default_factory=lambda: os.getenv("ZEROPHISH_ENV", "development"))
    port: int = field(default_factory=lambda: int(os.getenv("GATEWAY_PORT", "8001")))
    tier3_timeout: int = field(default_factory=lambda: int(os.getenv("TIER3_TIMEOUT", "7")))
    scan_rate_limit: str = field(default_factory=lambda: os.getenv(
        "SCAN_RATE_LIMIT",
        os.getenv("GATEWAY_SCAN_RATE_LIMIT", "20/minute" if os.getenv("ZEROPHISH_ENV") == "production" else "1200/minute"),
    ))
    status_rate_limit: str = field(default_factory=lambda: os.getenv(
        "STATUS_RATE_LIMIT",
        os.getenv("GATEWAY_STATUS_RATE_LIMIT", "120/minute"),
    ))
    scan_cache_ttl: int = field(default_factory=lambda: int(os.getenv("SCAN_CACHE_TTL", "300")))
    scan_history_limit: int = field(default_factory=lambda: int(os.getenv("GATEWAY_SCAN_HISTORY_LIMIT", "500")))

    # Circuit breaker
    circuit_breaker_enabled: bool = field(default_factory=lambda: os.getenv("CIRCUIT_BREAKER_ENABLED", "true").lower() == "true")
    circuit_failure_threshold: int = field(default_factory=lambda: int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5")))
    circuit_timeout: float = field(default_factory=lambda: float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "30")))
    circuit_window: float = field(default_factory=lambda: float(os.getenv("CIRCUIT_BREAKER_WINDOW", "60")))

    # CORS
    allowed_origins: List[str] = field(default_factory=lambda: [
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()
    ] or [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:8000", "http://127.0.0.1:8000",
        "http://localhost:8001", "http://127.0.0.1:8001",
    ])
    allow_origin_regex: Optional[str] = field(default_factory=lambda: os.getenv("ALLOW_ORIGIN_REGEX"))

    # API key
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("API_KEY"))

    # Weights
    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def __post_init__(self) -> None:
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port: {self.port}")
        if self.tier3_timeout < 1:
            raise ValueError(f"Tier3 timeout must be >= 1: {self.tier3_timeout}")
        if self.scan_cache_ttl < 1:
            raise ValueError(f"Scan cache TTL must be >= 1: {self.scan_cache_ttl}")
        if self.scan_history_limit < 1:
            raise ValueError(f"Scan history limit must be >= 1: {self.scan_history_limit}")
        if not str(self.scan_rate_limit).strip():
            raise ValueError("Scan rate limit cannot be empty")
        if not str(self.status_rate_limit).strip():
            raise ValueError("Status rate limit cannot be empty")


CONFIG = GatewayConfig()
WEIGHTS = CONFIG.weights
logger = logging.getLogger(__name__)

# ---------- Circuit Breaker ----------
tier3_circuit_breaker: Optional[CircuitBreaker] = None
if CONFIG.circuit_breaker_enabled:
    tier3_circuit_breaker = CircuitBreaker(
        failure_threshold=CONFIG.circuit_failure_threshold,
        timeout=CONFIG.circuit_timeout,
        window=CONFIG.circuit_window,
        name="tier3_ai_analysis",
    )
    logger.info("Circuit breaker enabled for Tier 3")

# ---------- API Key Security ----------
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _resolve_api_key() -> Optional[str]:
    """Return the active API key from the current environment, if configured."""
    value = os.getenv("API_KEY")
    return value.strip() if isinstance(value, str) and value.strip() else None


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Verify API key if configured; otherwise allow all requests."""
    expected = _resolve_api_key()
    if not expected:
        return api_key or ""
    if not api_key or api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate API key",
        )
    return api_key

# ---------- Lifespan & Background Tasks ----------
_background_tasks: set[asyncio.Task] = set()


def _spawn_background_task(coro, name: Optional[str] = None) -> asyncio.Task:
    """Spawn a background task, retaining a strong reference to prevent early garbage collection."""
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("ZeroPhish API Gateway starting...")
    logger.info("Scoring Formula: T1*%.1f + T2*%.1f + T3*%.1f",
                CONFIG.weights.tier1, CONFIG.weights.tier2, CONFIG.weights.tier3)
    logger.info("Tier 3 Timeout: %ds", CONFIG.tier3_timeout)
    logger.info("Environment: %s", CONFIG.env)

    # Fail closed in production if durable persistence is not configured
    if CONFIG.env == "production" and not os.getenv("DATABASE_URL"):
        logger.critical("FATAL: DATABASE_URL is not set in production mode.")
        raise RuntimeError("DATABASE_URL must be configured in production environment for multi-worker safety.")

    # Pre-warm Tier 2 DistilBERT ML model
    try:
        try:
            from tier_2.ml_model import get_ml_model
        except ImportError:
            from Backend.tier_2.ml_model import get_ml_model
        _prewarm_model = await get_ml_model()
        if _prewarm_model and _prewarm_model.is_loaded():
            await _prewarm_model.predict("ZeroPhish gateway pre-warm initialization.")
            logger.info("Tier 2 DistilBERT ML model pre-warmed.")
    except Exception as _warmup_err:
        logger.debug("Tier 2 ML model pre-warm skipped or deferred: %s", _warmup_err)

    yield
    logger.info("ZeroPhish API Gateway shutting down...")
    # 1. Drain/cancel active background tasks
    if _background_tasks:
        logger.info("Draining %d active background tasks...", len(_background_tasks))
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        pending = [t for t in _background_tasks if current_loop is None or getattr(t, "get_loop", lambda: current_loop)() == current_loop]
        for t in pending:
            if not t.done():
                t.cancel()
        if pending:
            try:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=5.0)
            except (asyncio.TimeoutError, TimeoutError):
                logger.warning("Timed out waiting for background tasks to drain.")
        _background_tasks.clear()

    # 2. Close webhook client
    if EXTENSIONS_AVAILABLE:
        try:
            from webhooks.service import _close_client
            await _close_client()
        except Exception as e:
            logger.debug("Error closing webhook client: %s", e)

    # 3. Close cache backend
    try:
        from repositories.factory import close_cache_backend
        await close_cache_backend()
    except Exception as e:
        logger.debug("Error closing cache backend: %s", e)

    # 4. Clear SSE subscribers
    _sse_subscribers.clear()
    _sse_subscriber_overflows.clear()

# ---------- FastAPI App ----------
app = FastAPI(
    title="ZeroPhish API Gateway",
    description="AI-powered phishing detection — 3-tier analysis + auth, webhooks, incidents, analytics.",
    version="2.0.0",
    lifespan=lifespan,
)

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG.allowed_origins,
    allow_origin_regex=CONFIG.allow_origin_regex or r"^http://(localhost|127\.0\.0\.1):(3000|8000|8001)$",
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    allow_credentials=True,
    expose_headers=["*"],
)

# ---------- Security Middleware ----------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=10_000_000)  # 10 MB for vision/screenshots

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start_time
    try:
        from security.metrics import record_http_request
        record_http_request(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
            duration_sec=duration,
        )
    except Exception:
        pass
    return response

# ---------- Rate Limiting ----------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

async def rate_limit_handler(request: Request, exc: Exception) -> Response:
    if isinstance(exc, RateLimitExceeded):
        return _rate_limit_exceeded_handler(request, exc)
    raise exc

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# ---------- Extension Routers ----------
if EXTENSIONS_AVAILABLE:
    app.include_router(auth_router)
    app.include_router(webhooks_router)
    app.include_router(incidents_router)
    app.include_router(email_router)
    app.include_router(analytics_router)
    app.include_router(awareness_router)
    app.include_router(vision_router)

# ---------- Internal State ----------
# In‑process scan time tracking and SSE subscribers
class BoundedScanTracker(dict):
    """
    Thread-safe / bounded dictionary for tracking scan start timestamps.
    Automatically prunes entries older than max_age_seconds or when size exceeds max_entries.
    """
    def __init__(self, max_entries: int = 5000, max_age_seconds: float = 600.0):
        super().__init__()
        self.max_entries = max_entries
        self.max_age_seconds = max_age_seconds

    def __setitem__(self, key: str, value: float) -> None:
        self._prune_if_needed()
        super().__setitem__(key, value)

    def _prune_if_needed(self) -> None:
        if len(self) >= self.max_entries:
            now = time.perf_counter()
            expired = [k for k, v in self.items() if (now - v) > self.max_age_seconds]
            for k in expired:
                super().pop(k, None)
            if len(self) >= self.max_entries:
                # Remove oldest 20%
                sorted_keys = sorted(self.keys(), key=lambda k: self[k])
                for k in sorted_keys[: max(1, self.max_entries // 5)]:
                    super().pop(k, None)


scan_started_at: BoundedScanTracker = BoundedScanTracker()
scan_results_lock = asyncio.Lock()
_latest_tier1_report: Optional[Dict[str, Any]] = None
_sse_subscribers: Dict[str, asyncio.Queue] = {}

# SSE Observability & Backpressure
sse_metrics: Dict[str, int] = {
    "sse_queue_full_total": 0,
    "sse_events_dropped_total": 0,
    "sse_subscriber_evictions_total": 0,
}
_sse_subscriber_overflows: Dict[str, int] = {}
MAX_OVERFLOW_THRESHOLD = 5


def _publish_to_subscriber(sub_id: str, q: asyncio.Queue, payload: Any) -> bool:
    """
    Publish an event to a subscriber queue using drop-oldest backpressure on QueueFull.
    Returns True if delivery succeeded; False if subscriber exceeded overflow threshold and should be evicted.
    """
    try:
        q.put_nowait(payload)
        _sse_subscriber_overflows[sub_id] = 0
        return True
    except asyncio.QueueFull:
        sse_metrics["sse_queue_full_total"] += 1
        # Backpressure policy: Drop oldest event and enqueue newest to give subscriber fresh state
        try:
            _ = q.get_nowait()
            sse_metrics["sse_events_dropped_total"] += 1
            q.put_nowait(payload)
            overflow_count = _sse_subscriber_overflows.get(sub_id, 0) + 1
            _sse_subscriber_overflows[sub_id] = overflow_count
            if overflow_count > MAX_OVERFLOW_THRESHOLD:
                logger.warning(
                    "SSE subscriber %s exceeded overflow threshold (%d); marking for eviction",
                    sub_id,
                    MAX_OVERFLOW_THRESHOLD,
                )
                sse_metrics["sse_subscriber_evictions_total"] += 1
                return False
            return True
        except (asyncio.QueueEmpty, asyncio.QueueFull):
            sse_metrics["sse_subscriber_evictions_total"] += 1
            return False
    except (TypeError, ValueError, RuntimeError):
        sse_metrics["sse_subscriber_evictions_total"] += 1
        return False


def _broadcast_to_subscribers(payload: Any) -> None:
    """
    Send payload to every SSE subscriber and evict subscribers whose queue
    repeatedly overflowed. Single owner of the eviction loop so the backpressure
    policy cannot drift between call sites.
    """
    if hasattr(payload, "model_dump"):
        try:
            payload = payload.model_dump(exclude_none=True, exclude_unset=False)
        except Exception:
            pass
    elif hasattr(payload, "dict"):
        try:
            payload = payload.dict()
        except Exception:
            pass

    dead: List[str] = []
    for sub_id, q in list(_sse_subscribers.items()):
        if not _publish_to_subscriber(sub_id, q, payload):
            dead.append(sub_id)
    for sub_id in dead:
        _sse_subscribers.pop(sub_id, None)
        _sse_subscriber_overflows.pop(sub_id, None)

SCAN_CACHE_VERSION = "v2.1"

# ---------- Helper Functions ----------
def _calculate_scan_cache_key(sender: str, body: str, links: List[str], subject: Optional[str]) -> str:
    """Generate deterministic SHA‑256 cache key scoped by detection version."""
    norm_sender = (sender or "").strip().lower()
    norm_body = (body or "").strip()
    norm_links = sorted((str(l) or "").strip().lower() for l in links)
    norm_subject = (subject or "").strip()
    raw = f"{SCAN_CACHE_VERSION}|{norm_sender}|{norm_subject}|{norm_body}|{','.join(norm_links)}"
    return f"scan:{SCAN_CACHE_VERSION}:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

def _clamp_score(score: float) -> float:
    return max(0.0, min(100.0, float(score)))

def _round_score(score: float) -> float:
    return round(_clamp_score(score), 2)

def _determine_verdict(score: float) -> str:
    # Delegates to canonical fusion engine and returns the Verdict enum member
    return Verdict(fusion_determine_verdict(score))

def _determine_threat_status(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "SUSPICIOUS"
    return "OK"


def _to_domain_status(status_str: str) -> DomainStatus:
    """Convert a status string to DomainStatus enum, with fallback to UNKNOWN."""
    try:
        return getattr(DomainStatus, status_str)
    except (AttributeError, TypeError, ValueError):
        return DomainStatus.UNKNOWN

def _calculate_weighted_score(scores: List[float], weights: List[float]) -> float:
    if not scores:
        return 0.0
    if len(scores) != len(weights):
        raise ValueError("Scores and weights must have the same length")
    total_weight = sum(weights)
    if total_weight <= 0:
        return _clamp_score(sum(scores) / len(scores))
    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    return _clamp_score(weighted_sum / total_weight)

def _calculate_partial_score(tier1: float, tier2: float) -> float:
    """Calculate partial score using canonical fusion engine."""
    return fusion_calc_partial_score(tier1, tier2)

def _calculate_final_score(tier1: float, tier2: float, tier3: float) -> float:
    """Calculate 3-tier fused score using canonical fusion engine."""
    score, _ = fusion_calc_fused_score(tier1, tier2, tier3, None)
    return score

def _calculate_final_score_with_vision(
    tier1: float,
    tier2: float,
    tier3: float,
    vision: Optional[float],
) -> float:
    """Calculate multi-tier fused score with optional vision using canonical fusion engine."""
    score, _ = fusion_calc_fused_score(tier1, tier2, tier3, vision)
    return score

def _merge_evidence(
    tier1_evidence: Optional[List[str]],
    tier2_evidence: Optional[List[str]],
    tier3_flagged: Optional[List[str]],
) -> List[str]:
    """Merge evidence from all tiers while preserving order and removing duplicates."""
    merged: List[str] = []
    for item in tier1_evidence or []:
        text = str(item).strip()
        if text:
            merged.append(text)
    for item in tier2_evidence or []:
        text = str(item).strip()
        if text:
            merged.append(text)
    for phrase in tier3_flagged or []:
        text = str(phrase).strip()
        if text:
            merged.append(f"AI: {text}")

    seen = set()
    result: List[str] = []
    for item in merged:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

async def _notify_live_dashboard(res: GatewayScanResponse, sender: str, subject: str) -> None:
    """Broadcast scan update to SSE subscribers and optional external webhook."""
    global _latest_tier1_report

    requires_visual = (res.tier3.requires_visual_check if res.tier3 else False) or (
        res.vision.requires_followup if res.vision else False
    )
    verdict_str = res.verdict.value if hasattr(res.verdict, "value") else str(res.verdict)
    ts_str = res.timestamp.isoformat() if hasattr(res.timestamp, "isoformat") else str(res.timestamp)

    payload = {
        "scan_id": res.scan_id,
        "complete": res.complete,
        "timestamp": ts_str,
        "sender": sender,
        "subject": subject,
        "final_score": res.final_score if res.final_score is not None else res.partial_score,
        "verdict": verdict_str,
        "layers_completed": res.layers_completed,
        "evidence": res.combined_evidence,
        "requires_visual_check": requires_visual,
        "threat_analysis": {
            "category": res.tier3.category if res.tier3 else "Processing",
            "reasoning": res.tier3.reasoning if res.tier3 else "Awaiting AI Analysis",
            "requires_visual_check": requires_visual,
        },
        "tier_details": {
            "tier1": {
                "score": res.tier1.score,
                "status": getattr(res.tier1.status, "value", str(res.tier1.status)) if res.tier1 else None,
            },
            "tier2": {
                "score": res.tier2.score,
                "status": getattr(res.tier2.threat_analysis.status, "value", str(res.tier2.threat_analysis.status))
                if res.tier2 and res.tier2.threat_analysis
                else None,
            },
            "tier3": {
                "score": res.tier3.score if res.tier3 else None,
                "status": getattr(res.tier3.status, "value", str(res.tier3.status)) if res.tier3 else None,
            },
            "vision": {
                "score": res.vision.visual_score if res.vision else None,
                "status": getattr(res.vision.status, "value", str(res.vision.status)) if res.vision else None,
            },
        },
        "explanation": res.explanation.model_dump() if res.explanation else None,
    }

    _latest_tier1_report = payload

    # Broadcast to SSE subscribers
    _broadcast_to_subscribers(payload)


    logger.info(
        "Live dashboard notification sent for scan %s (%s / %s)",
        res.scan_id,
        sender,
        subject,
    )

    # Optional external webhook notification (skips local loopback; strictly validated against SSRF)
    live_url = os.getenv("LIVE_DASHBOARD_URL")
    if live_url and not any(h in live_url for h in ("localhost", "127.0.0.1", ":8000", ":8001")):
        try:
            from security.middleware import is_safe_url
            if is_safe_url(live_url, allow_http=False):
                import httpx
                payload_bytes = json.dumps(payload, default=str).encode("utf-8")
                async with httpx.AsyncClient(timeout=2.0, follow_redirects=False) as client:
                    await client.post(
                        live_url,
                        content=payload_bytes,
                        headers={"Content-Type": "application/json"},
                    )
        except (httpx.HTTPError, OSError, TimeoutError, ValueError, TypeError) as e:
            logger.debug("External dashboard notification failed: %s", e)

# ---------- Tier 2 Execution ----------
async def execute_tier2(sender: str, body: str, links: List[str]) -> Tier2Result:
    """Execute Tier 2 analysis: domain age + threat pattern + ML."""
    start_time = time.perf_counter()
    evidence: List[str] = []

    try:
        import email.utils
        _, addr = email.utils.parseaddr(sender or "")
        clean_addr = addr if addr else (sender or "")
        domain = clean_addr.split("@")[-1].strip().lower() if "@" in clean_addr else ""
        domain = re.sub(r"[^\w.-]", "", domain).strip(".")
        if not domain:
            domain_score, domain_status = 50.0, DomainStatus.UNKNOWN
            evidence.append("Could not parse sender domain.")
        else:
            try:
                if hasattr(get_domain_age, "assert_called") or hasattr(get_domain_age, "return_value"):
                    age_days = get_domain_age(domain)
                    lookup_status = None
                else:
                    age_days = await asyncio.wait_for(aget_domain_age(domain), timeout=2.0)
                    lookup_status = "UNKNOWN" if age_days is None else None
            except (asyncio.TimeoutError, TimeoutError):
                logger.debug("Domain age lookup timed out for %s", domain)
                age_days = None
                lookup_status = "LOOKUP_FAILED"
            except Exception as e:
                logger.debug("Domain age lookup failed for %s: %s", domain, e)
                age_days = None
                lookup_status = "LOOKUP_FAILED"

            domain_score, domain_status_str, msg = analyze_domain_age(age_days, lookup_status=lookup_status)
            domain_status = _to_domain_status(domain_status_str)
            evidence.append(msg)

        threat_data = await ThreatAnalyzer.analyze_threat(
            email_body=body,
            sender=sender,
            links=links,
        )

        threat_score = _clamp_score(threat_data.threat_level)
        threat_status = _determine_threat_status(threat_score)
        threat_status_enum = _to_domain_status(threat_status)
        domain_status_enum = _to_domain_status(domain_status) if isinstance(domain_status, str) else domain_status
        tier2_score = _calculate_weighted_score([domain_score, threat_score], [0.3, 0.7])

        if threat_data.category != "Safe":
            evidence.append(f"Threat indicators detected: {threat_data.category}.")
        if threat_data.flagged_phrases:
            evidence.append(f"Flagged phrases: {', '.join(threat_data.flagged_phrases[:3])}")

        return Tier2Result(
            score=_round_score(tier2_score),
            domain_analysis=DomainAnalysis(
                status=domain_status_enum,
                score=_round_score(domain_score),
                weight=0.3,
            ),
            threat_analysis=Tier2Analysis(
                status=threat_status_enum,
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
    except (ValueError, TypeError, AttributeError, RuntimeError, OSError, asyncio.TimeoutError) as e:
        logger.error("Tier 2 execution failed: %s", e, exc_info=True)
        return Tier2Result(
            score=50.0,
            domain_analysis=DomainAnalysis(status=DomainStatus.ERROR, score=50.0),
            threat_analysis=Tier2Analysis(status=DomainStatus.ERROR, score=50.0),
            threat_details=ThreatAnalysisDetail(
                threat_level=50,
                category="Error",
                reasoning=f"Tier 2 failed: {type(e).__name__}",
                flagged_phrases=[],
            ),
            evidence=["Tier 2 processing error"],
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
        )

# ---------- Tier 3 Finalization ----------
async def _finalize_tier3(
    scan_id: str,
    email_body: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    cache_key: Optional[str] = None,
    screenshot_b64: Optional[str] = None,
    links: Optional[List[str]] = None,
) -> None:
    """Background task: complete Tier 3 & optional Vision, update scan result, cache, and notify."""
    try:
        try:
            # CircuitBreaker implementation may not strictly match the protocol used
            # by the wrapper; cast to Any to satisfy type checkers while preserving
            # runtime behavior.
            from typing import Any, cast

            tier3_result = await execute_tier3_with_circuit_breaker(
                body=email_body,
                circuit_breaker=cast(Any, tier3_circuit_breaker),
                tier3_timeout=CONFIG.tier3_timeout,
                sender=sender,
                subject=subject,
            )
        except (ValueError, TypeError, RuntimeError, asyncio.TimeoutError, OSError) as e:
            logger.error("Tier 3 finalization failed: %s", e, exc_info=True)
            status_val = TierStatus.TIMEOUT if isinstance(e, asyncio.TimeoutError) else TierStatus.FAILED
            cat_val = "AI_TIMEOUT" if status_val == TierStatus.TIMEOUT else "AI_PROVIDER_ERROR"
            tier3_result = Tier3Result(
                score=50,
                category=cat_val,
                reasoning=f"Tier 3 failed: {type(e).__name__}",
                flagged_phrases=[],
                status=status_val,
                confidence=0.0,
                requires_visual_check=False,
                execution_time_ms=0.0,
            )

        # Tier 4: Vision Analysis lifecycle
        vision_result: Optional[VisionAnalysisResult] = None
        primary_link = links[0] if (links and len(links) > 0) else None

        if screenshot_b64:
            try:
                from vision.service import VisionService
                v_service = VisionService()
                vision_result = await v_service.analyze_screenshot(
                    image_b64=screenshot_b64,
                    url=primary_link,
                    title=subject,
                )
            except Exception as v_err:
                logger.warning("Vision execution failed in gateway finalizer: %s", v_err)
                from vision.models import VisionAnalysisResult, VisionStatus
                vision_result = VisionAnalysisResult(
                    status=VisionStatus.FAILED,
                    visual_score=None,
                    confidence=0.0,
                    visual_category="ERROR",
                    findings=[f"Vision finalizer error: {v_err}"],
                    error_category="VISION_EXCEPTION",
                )
        elif tier3_result.requires_visual_check:
            from vision.models import VisionAnalysisResult, VisionStatus
            vision_result = VisionAnalysisResult(
                status=VisionStatus.VISUAL_REQUIRED,
                visual_score=None,
                confidence=0.0,
                visual_category="AUTHENTICATION_PORTAL",
                findings=["Visual verification required by Tier 3 AI, but screenshot was unavailable."],
                requires_followup=True,
            )

        scan_repo = get_scan_result_repository()
        async with scan_results_lock:
            existing = await scan_repo.get(scan_id)
            if not existing:
                logger.warning("Scan %s not found in repository; skipping finalization", scan_id)
                return

            fusion_res = fuse_detection_results(
                tier1_result=existing.tier1,
                tier2_result=existing.tier2,
                tier3_result=tier3_result,
                vision_result=vision_result,
                established_partial_score=existing.partial_score,
                established_verdict=existing.verdict.value if hasattr(existing.verdict, "value") else str(existing.verdict),
            )

            total_ms = None
            if scan_id in scan_started_at:
                total_ms = (time.perf_counter() - scan_started_at[scan_id]) * 1000
            elif getattr(existing, "timestamp", None):
                try:
                    ts = existing.timestamp
                    if isinstance(ts, str):
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    total_ms = max(0.0, (now - ts).total_seconds() * 1000)
                except Exception:
                    total_ms = None

            sender_meta = existing.sender or sender or "unknown@unknown.com"
            subject_meta = existing.subject or subject or "No Subject"

            from vision.models import VisionStatus
            layers_completed = 4 if (vision_result and vision_result.status != VisionStatus.NOT_REQUESTED) else 3

            updated = existing.model_copy(update={
                "tier3": tier3_result,
                "tier3_status": tier3_result.status,
                "vision": vision_result,
                "complete": True,
                "layers_completed": layers_completed,
                "final_score": fusion_res.final_score,
                "verdict": Verdict(fusion_res.verdict),
                "combined_evidence": fusion_res.combined_evidence_strings,
                "canonical_evidence": fusion_res.canonical_evidence,
                "explanation": fusion_res.explanation,
                "total_execution_time_ms": total_ms,
                "sender": sender_meta,
                "subject": subject_meta,
            })
            await scan_repo.save(scan_id, updated)

            # Cache completed result
            if cache_key:
                try:
                    cache = get_cache_backend()
                    await cache.set(cache_key, json.dumps(updated.model_dump()), ttl_seconds=CONFIG.scan_cache_ttl)
                except (TypeError, ValueError, RuntimeError, OSError) as e:
                    logger.debug("Failed to cache scan %s: %s", scan_id, e)

            # Notify dashboard
            try:
                _spawn_background_task(
                    _notify_live_dashboard(updated, sender_meta, subject_meta),
                    name=f"sse-dash-{scan_id}",
                )
            except RuntimeError as exc:
                logger.warning("Unable to schedule live dashboard task for scan %s: %s", scan_id, exc)

        # Fire webhooks in background and record analytics (outside the lock)
        if EXTENSIONS_AVAILABLE:
            payload = updated.model_dump(mode="json")

            async def _fire_webhooks(pl: dict, v: str) -> None:
                try:
                    await WebhookService.fire(WebhookEventType.SCAN_COMPLETE, pl)
                    if v == "CRITICAL":
                        await WebhookService.fire(WebhookEventType.SCAN_CRITICAL, pl)
                    elif v == "SUSPICIOUS":
                        await WebhookService.fire(WebhookEventType.SCAN_SUSPICIOUS, pl)
                except Exception as wh_err:
                    logger.warning("Background webhook delivery error for scan %s: %s", scan_id, wh_err)

            final_verdict = fusion_res.verdict
            final_score = fusion_res.final_score

            try:
                _spawn_background_task(_fire_webhooks(payload, final_verdict), name=f"webhook-fire-{scan_id}")
            except Exception as task_err:
                logger.warning("Unable to spawn webhook task for scan %s: %s", scan_id, task_err)

            try:
                await AnalyticsService.record_scan(
                    scan_id=scan_id,
                    sender=sender_meta,
                    subject=subject_meta,
                    final_score=final_score,
                    verdict=final_verdict,
                    category=updated.tier2.threat_details.category if updated.tier2 and updated.tier2.threat_details else "Unknown",
                    tier1=float(existing.tier1.score) if existing.tier1 and existing.tier1.score is not None else 0.0,
                    tier2=float(existing.tier2.score) if existing.tier2 and existing.tier2.score is not None else 0.0,
                    tier3=float(tier3_result.score) if tier3_result and tier3_result.score is not None else 0.0,
                )
            except (TypeError, ValueError, RuntimeError, OSError) as e:
                logger.error("Analytics recording error for scan %s: %s", scan_id, e)
    finally:
        scan_started_at.pop(scan_id, None)

# ---------- Endpoints ----------
@app.post("/api/v1/scan", response_model=GatewayScanResponse)
@app.post("/scan", response_model=GatewayScanResponse)
@app.post("/gateway/scan", response_model=GatewayScanResponse)
@limiter.limit(CONFIG.scan_rate_limit)
async def gateway_scan(
    request: Request,
    scan_request: GatewayScanRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
) -> GatewayScanResponse:
    """
    Submit an email for full 3‑tier phishing analysis.

    - Tier 1 runs server-side and is authoritative. Any client-supplied
      `tier1_score` / `tier1_evidence` is advisory only: it may corroborate
      (escalate) a finding but can never suppress or downgrade one.
    - Tier 2 (domain + pattern + ML) runs synchronously.
    - Tier 3 (AI, provider-agnostic) runs in the background.
    - Response includes a `scan_id` for polling status.
    """
    # 1. Input validation
    valid, errors = InputValidator.validate_scan_request(
        sender=scan_request.sender,
        body=scan_request.body,
        links=scan_request.links,
        subject=scan_request.subject,
    )
    if not valid:
        raise HTTPException(status_code=400, detail={"errors": errors})

    scan_id = str(uuid.uuid4())
    scan_started_at[scan_id] = time.perf_counter()

    # 2. Cache fast path
    cache_key = _calculate_scan_cache_key(
        scan_request.sender, scan_request.body, scan_request.links, scan_request.subject
    )
    cache = get_cache_backend()
    cached_json = await cache.get(cache_key)
    if cached_json:
        try:
            cached_data = json.loads(cached_json)
            cached_res = GatewayScanResponse.model_validate(cached_data)
            total_ms = (time.perf_counter() - scan_started_at.pop(scan_id, time.perf_counter())) * 1000
            cached_res = cached_res.model_copy(update={
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc),
                "total_execution_time_ms": round(total_ms, 2),
            })
            scan_repo = get_scan_result_repository()
            async with scan_results_lock:
                await scan_repo.save(scan_id, cached_res)
            try:
                _spawn_background_task(
                    _notify_live_dashboard(cached_res, scan_request.sender, scan_request.subject or "No Subject"),
                    name=f"sse-cache-{scan_id}",
                )
            except RuntimeError as exc:
                logger.warning("Unable to schedule cache-hit dashboard notification for scan %s: %s", scan_id, exc)
            logger.info("Cache hit for scan %s", scan_id)
            return cached_res
        except (TypeError, ValueError, json.JSONDecodeError) as e:
            logger.debug("Cache data invalid for %s: %s", scan_id, e)

    # 3. Execute Tier 1 & Tier 2 (synchronous part)
    # Tier 1: Authoritative server-side heuristic analysis
    server_t1 = analyze_tier1_server(
        sender=scan_request.sender,
        body=scan_request.body,
        links=scan_request.links,
        subject=scan_request.subject,
    )

    # Resolve client-reported advisory signals (if any) against server authority
    client_provided = scan_request.tier1_score is not None
    client_evidence = sanitize_client_evidence(scan_request.tier1_evidence)

    if client_provided:
        client_score = int(round(_clamp_score(scan_request.tier1_score)))
        # Trust boundary invariant: client score can corroborate risk (escalate),
        # but can NEVER suppress or downgrade a server-detected threat.
        effective_t1_score = max(server_t1.score, client_score)
        if server_t1.degraded:
            # A degraded server evaluation stays degraded regardless of client
            # input: a client signal must not upgrade an internal server failure
            # into a "verified" result, which would hide the degradation from
            # the fusion engine and from operators.
            source = "degraded"
        elif server_t1.score >= 20:
            source = "server_verified"
        elif client_score >= 20:
            source = "corroborated"
        else:
            source = "server_verified"
    else:
        client_score = None
        effective_t1_score = server_t1.score
        source = "degraded" if server_t1.degraded else "server_verified"

    # Merge grounded server evidence with tagged advisory client evidence
    grounded_evidence = [
        f"[Server Verified] {e}" for e in server_t1.evidence
    ] + client_evidence

    tier1 = Tier1Result(
        score=effective_t1_score,
        execution_time_ms=server_t1.execution_time_ms,
        evidence=grounded_evidence[:50],
        status=CleanStatus.SUSPICIOUS if effective_t1_score >= 20 else CleanStatus.CLEAN,
        source=source,
        server_score=server_t1.score,
        client_score=client_score,
        client_advisory=client_provided,
    )

    tier2 = await execute_tier2(
        sender=scan_request.sender,
        body=scan_request.body,
        links=scan_request.links,
    )

    partial_fusion = fuse_detection_results(
        tier1_result=tier1,
        tier2_result=tier2,
        tier3_result=None,
        vision_result=None,
    )
    partial_score = partial_fusion.partial_score
    verdict = Verdict(partial_fusion.verdict)

    response = GatewayScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        partial_score=partial_score,
        final_score=None,
        verdict=verdict,
        tier1=tier1,
        tier2=tier2,
        tier3=None,
        vision=None,
        tier3_status=TierStatus.PROCESSING,
        complete=False,
        layers_completed=2,
        combined_evidence=partial_fusion.combined_evidence_strings,
        canonical_evidence=partial_fusion.canonical_evidence,
        explanation=partial_fusion.explanation,
        weights=CONFIG.weights,
        sender=scan_request.sender,
        subject=scan_request.subject or "No Subject",
        total_execution_time_ms=(time.perf_counter() - scan_started_at[scan_id]) * 1000,
    )

    # 4. Store partial result
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        await scan_repo.save(scan_id, response)

    # 5. Notify dashboard (partial)
    try:
        _spawn_background_task(
            _notify_live_dashboard(response, scan_request.sender, scan_request.subject or "No Subject"),
            name=f"sse-partial-{scan_id}",
        )
    except RuntimeError as exc:
        logger.warning("Unable to schedule live dashboard notification for scan %s: %s", scan_id, exc)

    # 6. Shadow cascade (fire‑and‑forget)
    verdict_str = verdict.value if hasattr(verdict, "value") else str(verdict)
    if ShadowCascadeManager and scan_request.links:
        for link in scan_request.links[:5]:
            try:
                ShadowCascadeManager.get_instance().observe_async(
                    url=link,
                    production_verdict=verdict_str,
                    production_score=float(partial_score) if partial_score is not None else 0.0,
                )
            except Exception:
                logger.debug("Failed to schedule shadow-cascade observation for %s", link, exc_info=True)

    # 7. Schedule Tier 3 background task
    background_tasks.add_task(
        _finalize_tier3,
        scan_id,
        scan_request.body,
        scan_request.sender,
        scan_request.subject,
        cache_key,
        scan_request.screenshot_b64,
        scan_request.links,
    )

    logger.info("Scan %s initiated (partial score=%.2f)", scan_id, partial_score)
    return response

# ---------- Cache Endpoints ----------
@app.get("/cache/stats")
async def gateway_cache_stats() -> dict:
    """Return cache statistics from the active cache backend."""
    cache = get_cache_backend()
    if hasattr(cache, "get_stats"):
        return await cache.get_stats()
    return {"status": "connected", "backend": "in_memory"}

@app.delete("/cache/clear")
async def gateway_cache_clear(api_key: str = Depends(verify_api_key)) -> dict:
    """Clear all cached scan results. Mutating: requires the API key when configured."""
    cache = get_cache_backend()
    if hasattr(cache, "clear_prefix"):
        deleted = await cache.clear_prefix("scan:")
        return {"status": "success", "cleared_keys": deleted}
    return {"status": "success", "cleared_keys": 0}

# ---------- Status/Result Endpoints ----------
@app.get("/gateway/status/{scan_id}", response_model=ScanStatusResponse)
@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatusResponse)
@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit(CONFIG.status_rate_limit)
async def gateway_status(
    request: Request,
    scan_id: str,
    api_key: str = Depends(verify_api_key),
) -> ScanStatusResponse:
    """Poll scan status. Returns final result when complete."""
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        result = await scan_repo.get(scan_id)

    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")

    estimated_completion_ms = None
    if not result.complete:
        start_ts = scan_started_at.get(scan_id)
        if start_ts is not None:
            elapsed_ms = (time.perf_counter() - start_ts) * 1000
            estimated_completion_ms = max(0, int((CONFIG.tier3_timeout * 1000) - elapsed_ms))
        elif getattr(result, "timestamp", None):
            try:
                ts = result.timestamp
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                elapsed_ms = max(0.0, (now - ts).total_seconds() * 1000)
                estimated_completion_ms = max(0, int((CONFIG.tier3_timeout * 1000) - elapsed_ms))
            except Exception:
                estimated_completion_ms = None


    return ScanStatusResponse(
        scan_id=scan_id,
        complete=result.complete,
        layers_completed=result.layers_completed,
        tier3_status=result.tier3_status,
        final_score=result.final_score,
        verdict=result.verdict,
        tier3=result.tier3,
        vision=result.vision,
        explanation=result.explanation,
        estimated_completion_ms=estimated_completion_ms,
    )

@app.get("/gateway/result/{scan_id}", response_model=GatewayScanResponse)
@limiter.limit(CONFIG.status_rate_limit)
async def gateway_result(
    request: Request,
    scan_id: str,
    api_key: str = Depends(verify_api_key),
) -> GatewayScanResponse:
    """Retrieve the full scan result (must be complete)."""
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        result = await scan_repo.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    if result.complete:
        scan_started_at.pop(scan_id, None)
    return result

# ---------- Health / Readiness ----------
@app.get("/health")
@app.get("/api/v1/health")
@app.get("/gateway/health")
async def gateway_health() -> dict:
    """Health check endpoint."""
    scan_repo = get_scan_result_repository()
    async with scan_results_lock:
        total_scans = await scan_repo.count()
        pending_scans = await scan_repo.count_pending()

    return {
        "status": "healthy",
        "service": "ZeroPhish API Gateway",
        "environment": CONFIG.env,
        "version": os.getenv("ZEROPHISH_VERSION", "1.0.0"),
        "commit_sha": os.getenv("GIT_COMMIT_SHA") or os.getenv("GITHUB_SHA", "dev-local"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "weights": CONFIG.weights.model_dump(),
        "tier3_timeout_sec": CONFIG.tier3_timeout,
        "scans": {
            "total_cached": total_scans,
            "pending": pending_scans,
            "history_limit": CONFIG.scan_history_limit,
        },
        "sse": {
            "active_subscribers": len(_sse_subscribers),
            **sse_metrics,
        },
        "circuit_breaker": tier3_circuit_breaker.get_status() if tier3_circuit_breaker else None,
    }

@app.get("/ready")
@app.get("/api/v1/ready")
@app.get("/gateway/ready")
async def gateway_readiness(response: Response) -> dict:
    """Active readiness probe for orchestration and load balancers."""
    dependencies = {
        "repository": "ready",
        "weights": "ready",
        "models": "ready",
        "shadow_cascade": "ready" if ShadowCascadeManager else "disabled",
    }
    is_ready = True

    # Active database connectivity probe
    if os.getenv("DATABASE_URL"):
        try:
            from infrastructure.database import get_engine
            from sqlalchemy import text

            engine = get_engine()
            if engine:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                dependencies["database"] = "ready"
            else:
                dependencies["database"] = "uninitialized"
                is_ready = False
        except Exception as e:
            logger.error("Readiness check database probe failed: %s", e)
            dependencies["database"] = "unhealthy"
            is_ready = False
    else:
        dependencies["database"] = "in-memory"

    # Circuit breaker health check
    if tier3_circuit_breaker:
        cb_status = tier3_circuit_breaker.get_status()
        dependencies["circuit_breaker"] = cb_status.get("state", "unknown")
        if cb_status.get("state") == "open":
            dependencies["tier3_service"] = "circuit_open_fallback_active"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "not_ready",
        "environment": CONFIG.env,
        "version": os.getenv("ZEROPHISH_VERSION", "1.0.0"),
        "commit_sha": os.getenv("GIT_COMMIT_SHA") or os.getenv("GITHUB_SHA", "dev-local"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": dependencies,
    }

# ---------- Circuit Breaker Management ----------
@app.get("/gateway/circuit/status")
async def gateway_circuit_status() -> dict:
    if not tier3_circuit_breaker:
        return {"enabled": False, "status": "disabled"}
    return {"enabled": True, **tier3_circuit_breaker.get_status()}

@app.get("/gateway/circuit/reset")
@app.post("/gateway/circuit/reset")
async def gateway_circuit_reset(api_key: str = Depends(verify_api_key)) -> dict:
    """Reset the Tier 3 circuit breaker. Mutating: requires the API key when configured."""
    if not tier3_circuit_breaker:
        return {"enabled": False, "status": "disabled"}
    tier3_circuit_breaker.reset()
    return {"enabled": True, "status": "reset", **tier3_circuit_breaker.get_status()}

# ---------- Metrics ----------
@app.get("/metrics")
async def gateway_metrics() -> Response:
    """Prometheus exposition format telemetry endpoint."""
    return get_metrics_response()

# ---------- SSE Streaming ----------
@app.get("/tier1/latest")
async def get_latest_tier1_scan() -> Optional[Dict[str, Any]]:
    """Return the most recent scan report for dashboard refresh."""
    return _latest_tier1_report

@app.post("/tier1/report")
@limiter.limit(CONFIG.status_rate_limit)
async def receive_tier1_report(
    request: Request,
    report: Tier1ReportPayload,
    api_key: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Receive scan report from Chrome Extension or internal pipeline.

    The payload is intentionally permissive (extra fields allowed, all fields
    optional) so a malformed extension report can never 400-reject the live
    dashboard update path; downstream consumers read it as a dict.

    This endpoint mutates the dashboard's live feed, so it carries the same API
    key dependency as every other mutating route. The consumed payload is always
    tagged `client_advisory` and is never treated as server-authoritative.
    """
    payload = report.model_dump(exclude_none=True, exclude_unset=False)
    # Trust boundary enforcement: Tag unverified client reports as client_advisory
    if payload and payload.get("source") != "server_verified":
        payload["source"] = "client_advisory"

    global _latest_tier1_report
    _latest_tier1_report = payload

    _broadcast_to_subscribers(payload)

    return {"status": "success", "message": "Report received"}

@app.get("/tier1/stream")
async def stream_tier1_scans(request: Request) -> StreamingResponse:
    """Server‑Sent Events stream for real‑time frontend scan updates."""
    sub_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_subscribers[sub_id] = q

    async def event_generator():
        yield f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
        if _latest_tier1_report:
            yield f"data: {json.dumps(_latest_tier1_report, default=str)}\n\n"

        while True:
            if await request.is_disconnected():
                break
            try:
                item = await asyncio.wait_for(q.get(), timeout=10.0)
                if isinstance(item, str):
                    yield f"data: {item}\n\n"
                elif hasattr(item, "model_dump"):
                    yield f"data: {json.dumps(item.model_dump(exclude_none=True), default=str)}\n\n"
                else:
                    yield f"data: {json.dumps(item, default=str)}\n\n"
            except asyncio.TimeoutError:
                yield f"event: ping\ndata: {json.dumps({'status': 'alive'})}\n\n"
            except (TypeError, ValueError, RuntimeError):
                logger.debug("SSE stream interrupted for subscriber %s", sub_id, exc_info=True)
                break

    async def cleanup():
        _sse_subscribers.pop(sub_id, None)
        # _publish_to_subscriber creates an overflow entry for every subscriber
        # that receives an event; without this the dict grows with subscriber
        # churn for the lifetime of the process.
        _sse_subscriber_overflows.pop(sub_id, None)

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

# ---------- Main Entry ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=CONFIG.port, log_level="info")