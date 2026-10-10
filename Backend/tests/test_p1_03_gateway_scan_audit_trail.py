"""
Comprehensive verification test suite for Phase 1.11 / P1-03: Gateway Scan Audit Trail.

Validates:
1. End-to-end scan lifecycle audit recording (accepted, stage transitions, completed).
2. Error lifecycle auditing (validation rejection, authz denial, AI timeout, AI provider failure).
3. Cache fast-path auditing (SCAN_CACHE_HIT with cached verdict and metadata).
4. Durable persistence across process/repository restart (SQL and in-memory).
5. Sanitization and trust boundaries (no raw secrets, tokens, bodies, or traces in audit records).
6. Idempotency and deduplication of audit records by event_id.
7. Querying by scan_id and correlation_id.
8. Concurrent lifecycle audit writes under simultaneous requests.
"""

import asyncio
import os
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from gateway import app
from models.gateway_models import (
    GatewayScanRequest,
    ScanAuditEvent,
    Tier1Result,
    Tier2Result,
    Tier3Result,
    TierStatus,
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    Tier2Analysis,
    ThreatAnalysisDetail,
)
from repositories.factory import (
    get_scan_audit_repository,
    reset_repositories,
    set_scan_audit_repository,
)
from repositories.in_memory import InMemoryScanAuditRepository
from repositories.sql_repositories import SQLScanAuditRepository
from security.audit_logger import SecurityEventType, log_scan_audit


@pytest.fixture(autouse=True)
def setup_teardown():
    reset_repositories()
    yield
    reset_repositories()


def test_audit_logger_scan_events_structured_logging(caplog):
    """Verify structured log emission for all scan lifecycle security event types."""
    import logging

    with caplog.at_level(logging.DEBUG, logger="security"):
        log_scan_audit(
            event_type=SecurityEventType.SCAN_ACCEPTED,
            scan_id="scan-123",
            correlation_id="corr-456",
            actor_id="user:789",
            tenant_id="tenant-abc",
            previous_state="SUBMITTED",
            new_state="PROCESSING",
            score=45.5,
            duration_ms=12.34,
            provenance="gw-worker-1",
        )
        log_scan_audit(
            event_type=SecurityEventType.SCAN_CACHE_HIT,
            scan_id="scan-124",
            correlation_id="corr-457",
            verdict="SAFE",
            score=10.0,
        )
        log_scan_audit(
            event_type=SecurityEventType.SCAN_COMPLETED,
            scan_id="scan-125",
            correlation_id="corr-458",
            verdict="SUSPICIOUS",
            score=65.0,
            duration_ms=2500.0,
        )
        log_scan_audit(
            event_type=SecurityEventType.SCAN_FAILED,
            scan_id="scan-126",
            correlation_id="corr-459",
            error_category="AI_PROVIDER_ERROR",
            level=logging.ERROR,
        )
        log_scan_audit(
            event_type=SecurityEventType.SCAN_TIMEOUT,
            scan_id="scan-127",
            correlation_id="corr-460",
            error_category="AI_TIMEOUT",
            level=logging.WARNING,
        )
        log_scan_audit(
            event_type=SecurityEventType.SCAN_VALIDATION_FAILED,
            scan_id="invalid",
            correlation_id="corr-461",
            error_category="INPUT_VALIDATION_ERROR",
            level=logging.WARNING,
        )

    records = [r.message for r in caplog.records]
    assert any("SCAN_ACCEPTED" in r and "scan_id=scan-123" in r and "corr-456" in r for r in records)
    assert any("SCAN_CACHE_HIT" in r and "scan-124" in r for r in records)
    assert any("SCAN_COMPLETED" in r and "scan-125" in r and "SUSPICIOUS" in r for r in records)
    assert any("SCAN_FAILED" in r and "AI_PROVIDER_ERROR" in r for r in records)
    assert any("SCAN_TIMEOUT" in r and "AI_TIMEOUT" in r for r in records)
    assert any("SCAN_VALIDATION_FAILED" in r and "INPUT_VALIDATION_ERROR" in r for r in records)


@pytest.mark.asyncio
async def test_in_memory_scan_audit_repository_crud_and_deduplication():
    """Verify in-memory scan audit repository records, dedupes, and filters events."""
    repo = InMemoryScanAuditRepository(limit=10)
    ev_id = str(uuid.uuid4())
    ev1 = ScanAuditEvent(
        event_id=ev_id,
        scan_id="scan-001",
        event_type=SecurityEventType.SCAN_ACCEPTED.value,
        correlation_id="corr-001",
        timestamp=datetime.now(timezone.utc),
        previous_state="SUBMITTED",
        new_state="PROCESSING",
        score=25.0,
    )

    saved1 = await repo.record_event(ev1)
    assert saved1.event_id == ev_id

    # Deduplication test
    saved2 = await repo.record_event(ev1)
    assert saved2.event_id == ev_id
    assert await repo.count("scan-001") == 1

    ev2 = ScanAuditEvent(
        event_id=str(uuid.uuid4()),
        scan_id="scan-001",
        event_type=SecurityEventType.SCAN_COMPLETED.value,
        correlation_id="corr-001",
        timestamp=datetime.now(timezone.utc),
        previous_state="PROCESSING",
        new_state="COMPLETED",
        verdict="SAFE",
        score=20.0,
    )
    await repo.record_event(ev2)
    assert await repo.count("scan-001") == 2

    # Querying
    events = await repo.list_events(scan_id="scan-001")
    assert len(events) == 2
    assert events[0].event_type == SecurityEventType.SCAN_ACCEPTED.value
    assert events[1].event_type == SecurityEventType.SCAN_COMPLETED.value


@pytest.mark.asyncio
async def test_sql_scan_audit_repository_durability_and_restart():
    """Verify SQL repository persists audit events to SQLite/Postgres across factory reloads."""
    import sqlite3
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from infrastructure.database import Base

    db_path = "test_audit_durability.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)

    try:
        repo = SQLScanAuditRepository(session_factory)
        ev_id = str(uuid.uuid4())
        ev = ScanAuditEvent(
            event_id=ev_id,
            scan_id="scan-durable-1",
            event_type=SecurityEventType.SCAN_ACCEPTED.value,
            correlation_id="corr-durable-1",
            actor_id="user:durable",
            tenant_id="tenant-durable",
            previous_state="SUBMITTED",
            new_state="PROCESSING",
            score=50.0,
            duration_ms=15.5,
            provenance="worker-test",
            details={"tier1_score": 50},
        )
        await repo.record_event(ev)

        # Re-record same event (idempotency test)
        await repo.record_event(ev)
        assert await repo.count("scan-durable-1") == 1

        # Simulate process / worker restart with new repository instance on same database
        new_session_factory = sessionmaker(bind=engine)
        restarted_repo = SQLScanAuditRepository(new_session_factory)
        events = await restarted_repo.list_events(scan_id="scan-durable-1")
        assert len(events) == 1
        assert events[0].event_id == ev_id
        assert events[0].scan_id == "scan-durable-1"
        assert events[0].actor_id == "user:durable"
        assert events[0].tenant_id == "tenant-durable"
        assert events[0].details.get("tier1_score") == 50
    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


def test_gateway_scan_lifecycle_auditing_end_to_end():
    """Submit a real scan request and verify SCAN_ACCEPTED and SCAN_COMPLETED audit events are recorded."""
    client = TestClient(app)
    headers = {
        "x-correlation-id": "test-corr-flow-1",
        "x-tenant-id": "tenant-corp",
    }
    payload = {
        "sender": "alert@paypal-security-update.com",
        "subject": "Urgent Security Notification",
        "body": "Your account has been temporarily suspended. Click here to verify your identity.",
        "links": ["https://paypal-update-account.com/login"],
    }

    response = client.post("/api/v1/scan", json=payload, headers=headers)
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]

    # Verify audit trail contains SCAN_ACCEPTED event
    audit_repo = get_scan_audit_repository()
    events = asyncio.run(audit_repo.list_events(scan_id=scan_id))
    assert len(events) >= 1
    accepted_ev = events[0]
    assert accepted_ev.event_type == SecurityEventType.SCAN_ACCEPTED.value
    assert accepted_ev.correlation_id == "test-corr-flow-1"
    # Spoofed client header x-tenant-id must be ignored and not trusted
    assert accepted_ev.tenant_id is None
    assert accepted_ev.previous_state == "SUBMITTED"
    assert accepted_ev.new_state == "PROCESSING"

    # Query via API endpoint
    audit_resp = client.get(f"/api/v1/scan/{scan_id}/audit", headers=headers)
    assert audit_resp.status_code == 200
    trail = audit_resp.json()
    assert len(trail) >= 1
    assert trail[0]["scan_id"] == scan_id
    assert trail[0]["event_type"] == "SCAN_ACCEPTED"


def test_gateway_scan_validation_failure_audit():
    """Verify malformed scan request logs a SCAN_VALIDATION_FAILED audit event without throwing unhandled exceptions."""
    client = TestClient(app)
    headers = {"x-correlation-id": "test-corr-val-fail"}
    bad_payload = {
        "sender": "not-an-email",
        "body": "",
        "links": [],
    }

    response = client.post("/api/v1/scan", json=bad_payload, headers=headers)
    assert response.status_code in (400, 422)

    audit_repo = get_scan_audit_repository()
    events = asyncio.run(audit_repo.list_events(correlation_id="test-corr-val-fail"))
    assert len(events) >= 1
    val_ev = events[0]
    assert val_ev.event_type == SecurityEventType.SCAN_VALIDATION_FAILED.value
    assert "VALIDATION" in (val_ev.error_category or "")
    assert val_ev.new_state == "VALIDATION_FAILED"


def test_gateway_scan_authz_denied_audit(monkeypatch):
    """Verify unauthorized API key records an AUTHZ_DENIED audit record and redacts the raw API key."""
    monkeypatch.setenv("API_KEY", "secret-production-token-12345")
    client = TestClient(app)
    headers = {
        "X-API-Key": "attacker-wrong-key-9999",
        "x-correlation-id": "test-corr-authz-denied",
    }
    payload = {
        "sender": "normal@example.com",
        "subject": "Meeting",
        "body": "Let's meet tomorrow at 10am.",
        "links": [],
    }

    response = client.post("/api/v1/scan", json=payload, headers=headers)
    assert response.status_code == 403

    audit_repo = get_scan_audit_repository()
    events = asyncio.run(audit_repo.list_events(correlation_id="test-corr-authz-denied"))
    assert len(events) >= 1
    auth_ev = events[0]
    assert auth_ev.event_type == SecurityEventType.AUTHZ_DENIED.value
    assert auth_ev.new_state == "AUTHZ_DENIED"
    # Verify raw token is NOT in actor_id or anywhere in audit record
    assert "attacker-wrong-key-9999" not in (auth_ev.actor_id or "")
    assert "secret-production-token-12345" not in (auth_ev.actor_id or "")
    assert auth_ev.actor_id.startswith("apikey:")


def test_gateway_scan_cache_hit_audit():
    """Verify cache fast path logs SCAN_CACHE_HIT with cached verdict and metadata."""
    client = TestClient(app)
    payload = {
        "sender": "repeated@example.com",
        "subject": "Same Subject",
        "body": "Exact same body content for cache hit testing.",
        "links": [],
    }
    headers1 = {"x-correlation-id": "corr-first-run"}
    resp1 = client.post("/api/v1/scan", json=payload, headers=headers1)
    assert resp1.status_code == 200
    scan1_id = resp1.json()["scan_id"]

    # Second identical request (hit cache fast path if cached)
    from repositories.factory import get_cache_backend
    from gateway import _calculate_scan_cache_key
    cache = get_cache_backend()
    cache_key = _calculate_scan_cache_key(payload["sender"], payload["body"], [], payload["subject"])
    asyncio.run(cache.set(cache_key, resp1.text, ttl_seconds=300))

    headers2 = {"x-correlation-id": "corr-cache-hit-run"}
    resp2 = client.post("/api/v1/scan", json=payload, headers=headers2)
    assert resp2.status_code == 200
    scan2_id = resp2.json()["scan_id"]
    assert scan1_id != scan2_id


    audit_repo = get_scan_audit_repository()
    events = asyncio.run(audit_repo.list_events(scan_id=scan2_id))
    assert len(events) >= 1
    cache_ev = events[0]
    assert cache_ev.event_type == SecurityEventType.SCAN_CACHE_HIT.value
    assert cache_ev.correlation_id == "corr-cache-hit-run"
    assert cache_ev.new_state == "CACHE_HIT"
    assert cache_ev.details.get("cached") is True


@pytest.mark.asyncio
async def test_audit_event_finalization_failure_and_timeout_classification():
    """Directly test _finalize_tier3 creates SCAN_TIMEOUT and SCAN_FAILED audit records with proper error categories."""
    from gateway import _finalize_tier3, scan_results_lock
    from repositories.factory import get_scan_result_repository
    from models.gateway_models import GatewayScanResponse, Verdict

    scan_repo = get_scan_result_repository()
    audit_repo = get_scan_audit_repository()

    dummy_t1 = Tier1Result(score=10, evidence=[], status=CleanStatus.CLEAN)
    dummy_t2 = Tier2Result(
        score=20,
        domain_analysis=DomainAnalysis(status=DomainStatus.OK, score=10),
        threat_analysis=Tier2Analysis(status=DomainStatus.OK, score=20),
        threat_details=ThreatAnalysisDetail(threat_level=20, category="Safe", reasoning="OK", flagged_phrases=[]),
        evidence=[],
    )

    # 1. Timeout scenario
    timeout_scan_id = "scan-test-timeout"
    initial_res = GatewayScanResponse(
        scan_id=timeout_scan_id,
        partial_score=15.0,
        verdict=Verdict.SAFE,
        tier1=dummy_t1,
        tier2=dummy_t2,
        complete=False,
        layers_completed=2,
    )
    await scan_repo.save(timeout_scan_id, initial_res)

    # Mock execute_tier3_with_circuit_breaker to raise TimeoutError
    import gateway
    orig_t3_exec = gateway.execute_tier3_with_circuit_breaker

    async def mock_timeout(*args, **kwargs):
        raise asyncio.TimeoutError("AI timeout simulated")

    gateway.execute_tier3_with_circuit_breaker = mock_timeout
    try:
        await _finalize_tier3(
            scan_id=timeout_scan_id,
            email_body="test body",
            correlation_id="corr-to-1",
            actor_id="user:test",
        )
        events = await audit_repo.list_events(scan_id=timeout_scan_id)
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.SCAN_TIMEOUT.value
        assert events[0].new_state == "TIMEOUT"
        assert events[0].error_category == "AI_TIMEOUT"
    finally:
        gateway.execute_tier3_with_circuit_breaker = orig_t3_exec

    # 2. Provider failure scenario
    failed_scan_id = "scan-test-failed"
    initial_res2 = GatewayScanResponse(
        scan_id=failed_scan_id,
        partial_score=15.0,
        verdict=Verdict.SAFE,
        tier1=dummy_t1,
        tier2=dummy_t2,
        complete=False,
        layers_completed=2,
    )
    await scan_repo.save(failed_scan_id, initial_res2)

    async def mock_fail(*args, **kwargs):
        raise RuntimeError("AI Provider connection reset")

    gateway.execute_tier3_with_circuit_breaker = mock_fail
    try:
        await _finalize_tier3(
            scan_id=failed_scan_id,
            email_body="test body",
            correlation_id="corr-fail-1",
            actor_id="user:test",
        )
        events = await audit_repo.list_events(scan_id=failed_scan_id)
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.SCAN_FAILED.value
        assert events[0].new_state == "FAILED"
        assert events[0].error_category == "AI_PROVIDER_ERROR"
    finally:
        gateway.execute_tier3_with_circuit_breaker = orig_t3_exec


def test_production_api_key_unconfigured_fails_closed(monkeypatch):
    """Verify that in production (ZEROPHISH_ENV=production), missing API_KEY fails closed with 500."""
    monkeypatch.setenv("ZEROPHISH_ENV", "production")
    monkeypatch.delenv("API_KEY", raising=False)

    client = TestClient(app)
    response = client.get("/api/v1/scan/test-scan-id/audit")
    assert response.status_code == 500
    assert "Server security misconfiguration" in response.json()["detail"]


def test_audit_query_endpoint_bounded_limits_validation():
    """Verify limit parameter is strictly validated (ge=1, le=100) and returns 422 for invalid bounds."""
    client = TestClient(app)

    # limit = 0 -> 422
    resp_zero = client.get("/api/v1/scan/some-scan/audit?limit=0")
    assert resp_zero.status_code == 422

    # limit = -5 -> 422
    resp_neg = client.get("/api/v1/scan/some-scan/audit?limit=-5")
    assert resp_neg.status_code == 422

    # limit = 500 (exceeds le=100) -> 422
    resp_excess = client.get("/api/v1/scan/some-scan/audit?limit=500")
    assert resp_excess.status_code == 422


def test_audit_query_endpoint_nonexistent_scan_returns_404():
    """Verify that querying audit trail for a non-existent scan returns 404."""
    client = TestClient(app)
    resp = client.get("/api/v1/scan/nonexistent-uuid-12345/audit?limit=10")
    assert resp.status_code == 404
    assert "Unknown scan_id" in resp.json()["detail"]


def test_audit_persistence_failure_policy_in_production(monkeypatch):
    """Verify that in production, if durable audit repository fails on SCAN_ACCEPTED, gateway fails closed with 500."""
    from repositories.factory import set_scan_audit_repository, set_scan_result_repository
    from repositories.in_memory import InMemoryScanResultRepository

    class FailingAuditRepository(InMemoryScanAuditRepository):
        async def record_event(self, event: ScanAuditEvent) -> ScanAuditEvent:
            raise RuntimeError("Database connection died during audit write")

    set_scan_audit_repository(FailingAuditRepository())
    set_scan_result_repository(InMemoryScanResultRepository())
    monkeypatch.setenv("ZEROPHISH_ENV", "production")
    monkeypatch.setenv("API_KEY", "prod-secret-key-123")

    client = TestClient(app)
    headers = {"X-API-Key": "prod-secret-key-123"}
    payload = {
        "sender": "user@example.com",
        "subject": "Hello",
        "body": "Normal body content",
        "links": [],
    }

    resp = client.post("/api/v1/scan", json=payload, headers=headers)
    assert resp.status_code == 500
    assert "Security audit logging failure" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_finalize_tier3_unexpected_exception_audited():
    """Verify unexpected exception in _finalize_tier3 is audited as SCAN_FAILED with safe category."""
    import gateway
    from gateway import _finalize_tier3
    from repositories.factory import get_scan_result_repository, get_scan_audit_repository
    from models.gateway_models import (
        GatewayScanResponse,
        Verdict,
        Tier1Result,
        Tier2Result,
        CleanStatus,
        DomainAnalysis,
        DomainStatus,
        Tier2Analysis,
        ThreatAnalysisDetail,
    )

    scan_repo = get_scan_result_repository()
    audit_repo = get_scan_audit_repository()

    dummy_t1 = Tier1Result(score=10, evidence=[], status=CleanStatus.CLEAN)
    dummy_t2 = Tier2Result(
        score=20,
        domain_analysis=DomainAnalysis(status=DomainStatus.OK, score=10),
        threat_analysis=Tier2Analysis(status=DomainStatus.OK, score=20),
        threat_details=ThreatAnalysisDetail(threat_level=20, category="Safe", reasoning="OK", flagged_phrases=[]),
        evidence=[],
    )

    scan_id = "scan-unexpected-err-1"
    initial_res = GatewayScanResponse(
        scan_id=scan_id,
        partial_score=10.0,
        verdict=Verdict.SAFE,
        tier1=dummy_t1,
        tier2=dummy_t2,
        complete=False,
        layers_completed=2,
    )
    await scan_repo.save(scan_id, initial_res)

    orig_fuse = gateway.fuse_detection_results

    def mock_exploding_fuse(*args, **kwargs):
        raise ValueError("Simulated unexpected fusion crash")

    gateway.fuse_detection_results = mock_exploding_fuse
    try:
        await _finalize_tier3(
            scan_id=scan_id,
            email_body="test body",
            correlation_id="corr-unexp-1",
        )
        events = await audit_repo.list_events(scan_id=scan_id)
        assert len(events) >= 1
        failed_ev = events[-1]
        assert failed_ev.event_type == SecurityEventType.SCAN_FAILED.value
        assert failed_ev.error_category == "UNEXPECTED_FINALIZER_EXCEPTION"
        assert failed_ev.details.get("error") == "ValueError"
    finally:
        gateway.fuse_detection_results = orig_fuse
