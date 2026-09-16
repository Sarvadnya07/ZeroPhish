"""
P1 Reliability & Production Hardening Test Suite.

Verifies:
1. Database transaction rollback on simulated errors across all SQL repositories.
2. Cache degradation fallback and graceful shutdown.
3. Circuit breaker state machine transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
4. SSE queue backpressure, drop-oldest policy, and subscriber eviction.
5. Background task reference tracking and lifespan shutdown draining.
6. Webhook decoupling (failure isolation during scan finalization).
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth.models import UserInDB, UserRole, UserStatus
from circuit_breaker import CircuitBreaker, CircuitBreakerOpenError, CircuitState
from gateway import (
    MAX_OVERFLOW_THRESHOLD,
    _background_tasks,
    _finalize_tier3,
    _publish_to_subscriber,
    _spawn_background_task,
    _sse_subscriber_overflows,
    _sse_subscribers,
    lifespan,
    sse_metrics,
)
from incidents.models import Incident, IncidentSeverity, IncidentStatus
from infrastructure.database import Base
from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    GatewayScanResponse,
    ScoringWeights,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    Verdict,
)
from repositories.factory import close_cache_backend, get_cache_backend
from repositories.sql_repositories import (
    SQLAnalyticsRepository,
    SQLIncidentRepository,
    SQLScanResultRepository,
    SQLUserRepository,
    SQLWebhookRepository,
)
from webhooks.models import WebhookSubscription


@pytest.fixture
def sqlite_session_factory(tmp_path):
    """Create an isolated SQLite database with fresh schema for testing."""
    db_file = tmp_path / "test_p1_reliability.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    yield factory
    engine.dispose()


# ============================================================================
# 1. Database Transaction Rollback on Failure
# ============================================================================

def test_user_repository_rollback_on_error(sqlite_session_factory):
    repo = SQLUserRepository(sqlite_session_factory)
    user = UserInDB(
        id="u1",
        clerk_user_id="clerk_u1",
        email="test@zerophish.org",
        full_name="Test User",
        role=UserRole.ANALYST,
        status=UserStatus.ACTIVE,
        scan_count=0,
        risk_score=0.0,
        created_at=datetime.now(timezone.utc),
    )

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated DB Write Error")):
        with pytest.raises(RuntimeError, match="Simulated DB Write Error"):
            repo.save(user)

    fetched = repo.get_by_id("u1")
    assert fetched is None


def test_incident_repository_rollback_on_error(sqlite_session_factory):
    repo = SQLIncidentRepository(sqlite_session_factory)
    incident = Incident(
        id="inc-1",
        title="Phishing Alert",
        description="Test incident description",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated DB Incident Error")):
        with pytest.raises(RuntimeError, match="Simulated DB Incident Error"):
            repo.save(incident)

    fetched = repo.get_by_id("inc-1")
    assert fetched is None


@pytest.mark.asyncio
async def test_scan_result_repository_rollback_on_error(sqlite_session_factory):
    repo = SQLScanResultRepository(sqlite_session_factory)
    scan_resp = GatewayScanResponse(
        scan_id="scan-fail-1",
        timestamp=datetime.now(timezone.utc),
        partial_score=50.0,
        final_score=None,
        verdict=Verdict.SUSPICIOUS,
        tier1=Tier1Result(score=50, execution_time_ms=1.0, evidence=[], status=CleanStatus.SUSPICIOUS),
        tier2=Tier2Result(
            score=50.0,
            status=TierStatus.COMPLETE,
            domain_analysis=DomainAnalysis(status=DomainStatus.SUSPICIOUS, score=50.0),
            threat_analysis=Tier2Analysis(status=DomainStatus.SUSPICIOUS, score=50.0),
            threat_details=ThreatAnalysisDetail(threat_level=50, category="Phishing", reasoning="Test finding"),
        ),
        tier3=None,
        tier3_status=TierStatus.PROCESSING,
        complete=False,
        layers_completed=1,
        combined_evidence=[],
        weights=ScoringWeights(),
        sender="attacker@fake.com",
        subject="Urgent",
        total_execution_time_ms=10.0,
    )

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated Scan DB Error")):
        with pytest.raises(RuntimeError, match="Simulated Scan DB Error"):
            await repo.save("scan-fail-1", scan_resp)

    fetched = await repo.get("scan-fail-1")
    assert fetched is None


def test_analytics_repository_rollback_on_error(sqlite_session_factory):
    repo = SQLAnalyticsRepository(sqlite_session_factory)
    event_data = {
        "scan_id": "scan-anal-1",
        "timestamp": time.time(),
        "final_score": 85.0,
        "verdict": "CRITICAL",
        "category": "Credential Harvesting",
        "sender": "bad@phish.com",
        "subject": "Reset Password",
        "tier1_score": 20.0,
        "tier2_score": 30.0,
        "tier3_score": 50.0,
    }

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated Analytics DB Error")):
        with pytest.raises(RuntimeError, match="Simulated Analytics DB Error"):
            repo.record_scan_event(event_data)

    summary = repo.get_dashboard_summary()
    assert summary.total_scans_today == 0


def test_webhook_repository_rollback_on_error(sqlite_session_factory):
    repo = SQLWebhookRepository(sqlite_session_factory)
    sub = WebhookSubscription(
        id="sub-p1-1",
        url="https://hooks.example.com/alert",
        events=["scan.complete"],
        secret="a" * 32,
        enabled=True,
    )

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated Webhook DB Error")):
        with pytest.raises(RuntimeError, match="Simulated Webhook DB Error"):
            repo.save_subscription(sub)

    fetched = repo.get_subscription("sub-p1-1")
    assert fetched is None


# ============================================================================
# 2. Cache Degradation & Graceful Shutdown
# ============================================================================

@pytest.mark.asyncio
async def test_redis_cache_fallback_on_client_error():
    """Verify _RedisCache falls back transparently to in-memory on redis errors."""
    mock_redis_client = MagicMock()
    mock_redis_client.get = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
    mock_redis_client.set = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
    mock_redis_client.delete = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
    mock_redis_client.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis_client):
        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
            from repositories.factory import get_cache_backend, reset_repositories
            reset_repositories()
            cache = get_cache_backend()

            # Set should succeed by falling back to in-memory
            await cache.set("test-key", "test-val", ttl_seconds=60)

            # Get should succeed by falling back to in-memory
            val = await cache.get("test-key")
            assert val == "test-val"

            # Clean shutdown test
            await close_cache_backend()
            mock_redis_client.aclose.assert_awaited_once()

            reset_repositories()


# ============================================================================
# 3. Circuit Breaker Deterministic State Transitions
# ============================================================================

@pytest.mark.asyncio
async def test_circuit_breaker_state_machine():
    """Verify CLOSED -> OPEN -> HALF_OPEN -> CLOSED state transitions."""
    with patch.dict(os.environ, {"REDIS_URL": ""}):
        breaker = CircuitBreaker(
            failure_threshold=2,
            timeout=0.3,  # 300ms recovery window
            window=60.0,
            name="test_breaker",
        )

    assert breaker.state == CircuitState.CLOSED

    call_count = 0

    async def failing_call():
        nonlocal call_count
        call_count += 1
        raise ValueError("Service down")

    async def successful_call():
        nonlocal call_count
        call_count += 1
        return "success"

    # 1. First failure -> Still CLOSED
    with pytest.raises(ValueError):
        await breaker.call(failing_call)
    assert breaker.state == CircuitState.CLOSED

    # 2. Second failure -> Reaches threshold -> Transitions to OPEN
    with pytest.raises(ValueError):
        await breaker.call(failing_call)
    assert breaker.state == CircuitState.OPEN

    # 3. In OPEN state (within 500ms), calls must be rejected immediately
    prev_count = call_count
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(successful_call)
    assert call_count == prev_count  # Function was not called

    # 4. Wait for recovery timeout (300ms + buffer)
    await asyncio.sleep(0.4)

    # 5. Successful call in HALF_OPEN resets breaker to CLOSED
    res = await breaker.call(successful_call)
    assert res == "success"
    assert breaker.state == CircuitState.CLOSED


# ============================================================================
# 4. SSE Backpressure, Drop-Oldest Policy & Eviction
# ============================================================================

@pytest.mark.asyncio
async def test_sse_backpressure_and_subscriber_eviction():
    """Verify drop-oldest policy on QueueFull and eviction after exceeding overflow threshold."""
    sub_id = "test-slow-subscriber"
    # Small queue with maxsize=2
    queue = asyncio.Queue(maxsize=2)
    _sse_subscribers[sub_id] = queue
    _sse_subscriber_overflows[sub_id] = 0

    init_full = sse_metrics["sse_queue_full_total"]
    init_dropped = sse_metrics["sse_events_dropped_total"]
    init_evictions = sse_metrics["sse_subscriber_evictions_total"]

    # Fill queue to capacity
    ok1 = _publish_to_subscriber(sub_id, queue, {"event": 1})
    ok2 = _publish_to_subscriber(sub_id, queue, {"event": 2})
    assert ok1 is True
    assert ok2 is True
    assert queue.full()

    # Next publish triggers QueueFull, drops oldest (event 1), and enqueues event 3
    ok3 = _publish_to_subscriber(sub_id, queue, {"event": 3})
    assert ok3 is True
    assert sse_metrics["sse_queue_full_total"] == init_full + 1
    assert sse_metrics["sse_events_dropped_total"] == init_dropped + 1

    # Verify event 1 was dropped and event 2 is at head
    assert queue.get_nowait() == {"event": 2}
    assert queue.get_nowait() == {"event": 3}

    # Now simulate a dead subscriber overflowing repeatedly past MAX_OVERFLOW_THRESHOLD
    queue.put_nowait({"fill": 1})
    queue.put_nowait({"fill": 2})
    _sse_subscriber_overflows[sub_id] = MAX_OVERFLOW_THRESHOLD

    # Next overflow should trigger eviction recommendation (return False)
    deliver_res = _publish_to_subscriber(sub_id, queue, {"event": "final_overflow"})
    assert deliver_res is False
    assert sse_metrics["sse_subscriber_evictions_total"] == init_evictions + 1

    # Clean up test subscriber
    _sse_subscribers.pop(sub_id, None)
    _sse_subscriber_overflows.pop(sub_id, None)


# ============================================================================
# 5. Background Task Tracking & Lifespan Shutdown
# ============================================================================

@pytest.mark.asyncio
async def test_background_task_lifecycle_and_shutdown():
    """Verify _spawn_background_task retains reference and lifespan drains tasks on shutdown."""
    task_completed = asyncio.Event()

    async def sample_task():
        await asyncio.sleep(0.05)
        task_completed.set()

    task = _spawn_background_task(sample_task(), name="test-p1-task")
    assert task in _background_tasks
    await task_completed.wait()

    # Small yield to let done callback fire
    await asyncio.sleep(0.01)
    assert task not in _background_tasks


@pytest.mark.asyncio
async def test_lifespan_graceful_shutdown_drains_tasks():
    """Verify lifespan context manager drains tasks when app shuts down."""
    mock_app = MagicMock()
    app_lifespan = lifespan(mock_app)

    async def lingering_task():
        try:
            await asyncio.sleep(10.0)
        except asyncio.CancelledError:
            pass

    # Enter lifespan
    await app_lifespan.__aenter__()

    # Spawn lingering task
    t = _spawn_background_task(lingering_task(), name="lingering-task")
    assert t in _background_tasks

    # Exit lifespan (shutdown)
    await app_lifespan.__aexit__(None, None, None)

    # Task should be cancelled and background tasks emptied
    assert len(_background_tasks) == 0
    assert t.cancelled() or t.done()


# ============================================================================
# 6. Webhook Decoupling (Non-blocking scan finalization)
# ============================================================================

@pytest.mark.asyncio
async def test_finalize_tier3_non_blocking_on_webhook_failure():
    """Verify that slow or failing webhooks do not block scan finalization or analytics."""
    from repositories.factory import set_scan_result_repository
    from repositories.in_memory import InMemoryScanResultRepository

    scan_repo = InMemoryScanResultRepository()
    set_scan_result_repository(scan_repo)

    scan_id = "test-wh-decoupled"
    initial_res = GatewayScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        partial_score=80.0,
        final_score=None,
        verdict=Verdict.CRITICAL,
        tier1=Tier1Result(score=80, execution_time_ms=1.0, evidence=[], status=CleanStatus.SUSPICIOUS),
        tier2=Tier2Result(
            score=85.0,
            status=TierStatus.COMPLETE,
            domain_analysis=DomainAnalysis(status=DomainStatus.CRITICAL, score=85.0),
            threat_analysis=Tier2Analysis(status=DomainStatus.CRITICAL, score=85.0),
            threat_details=ThreatAnalysisDetail(threat_level=85, category="Phishing", reasoning="Critical test finding"),
        ),
        tier3=None,
        tier3_status=TierStatus.PROCESSING,
        complete=False,
        layers_completed=2,
        combined_evidence=[],
        weights=ScoringWeights(),
        sender="ceo-fraud@phish.net",
        subject="Wire Transfer",
        total_execution_time_ms=5.0,
    )
    await scan_repo.save(scan_id, initial_res)

    mock_fire = AsyncMock(side_effect=Exception("Webhook Receiver Offline / Timeout"))
    mock_record_scan = AsyncMock()

    with patch("webhooks.service.WebhookService.fire", mock_fire):
        with patch("analytics.service.AnalyticsService.record_scan", mock_record_scan):
            mock_t3_result = Tier3Result(
                score=90,
                category="Phishing",
                reasoning="Urgent financial request with spoofed identity",
                flagged_phrases=["Wire Transfer"],
                model_used="gemini-2.5-flash",
                confidence=0.95,
                execution_time_ms=10.0,
            )
            with patch("gateway.execute_tier3_with_circuit_breaker", AsyncMock(return_value=mock_t3_result)):
                await _finalize_tier3(
                    scan_id=scan_id,
                    email_body="Transfer $50,000 immediately.",
                    sender="ceo-fraud@phish.net",
                    subject="Wire Transfer",
                    cache_key=None,
                )

    # Verify scan completed successfully in repository despite webhook failure
    final_scan = await scan_repo.get(scan_id)
    assert final_scan is not None
    assert final_scan.complete is True
    assert final_scan.tier3_status == TierStatus.COMPLETE
    assert final_scan.verdict == Verdict.CRITICAL
    assert final_scan.final_score is not None
    assert final_scan.final_score >= 80

    # Verify analytics was still safely recorded
    mock_record_scan.assert_awaited_once()
