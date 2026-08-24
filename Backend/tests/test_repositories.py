"""
Comprehensive repository tests for InMemory and SQLAlchemy adapters.
Ensures identical behavioral parity across data storage implementations.
"""

import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from analytics.models import FalsePositiveReport, PolicyRule
from auth.models import UserInDB, UserRole, UserStatus, UserUpdate
from incidents.models import (
    Incident,
    IncidentComment,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from infrastructure.database import Base
from repositories.factory import (
    get_incident_repository,
    get_user_repository,
    reset_repositories,
    set_user_repository,
)
from repositories.in_memory import (
    InMemoryAnalyticsRepository,
    InMemoryCacheBackend,
    InMemoryIncidentRepository,
    InMemoryScanResultRepository,
    InMemoryUserRepository,
    InMemoryWebhookRepository,
)
from repositories.sql_repositories import SQLIncidentRepository, SQLUserRepository
from webhooks.models import WebhookDelivery, WebhookEventType, WebhookSubscription


@pytest.fixture
def sqlite_session_factory():
    """In-memory SQLite database for testing SQL repository adapters."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return factory


# ── User Repository Parity Tests ───────────────────────────────────────────────


@pytest.mark.parametrize("repo_type", ["in_memory", "sql"])
def test_user_repository_crud_and_tokens(repo_type, sqlite_session_factory):
    if repo_type == "in_memory":
        repo = InMemoryUserRepository()
    else:
        repo = SQLUserRepository(sqlite_session_factory)

    u = UserInDB(
        id="u-100",
        clerk_user_id="user_clerk_100",
        email="test@domain.com",
        full_name="Test User",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
        created_at="2026-01-01T00:00:00Z",
    )
    repo.save(u)

    # Fetch by ID & Email & Clerk ID
    assert repo.get_by_id("u-100") is not None
    assert repo.get_by_clerk_id("user_clerk_100") is not None
    assert repo.get_by_email("test@domain.com") is not None
    assert repo.get_by_email("nonexistent@domain.com") is None

    # Update
    updated = repo.update("u-100", UserUpdate(full_name="Updated Name", role=UserRole.ANALYST))
    assert updated.full_name == "Updated Name"
    assert updated.role == UserRole.ANALYST

    # Scan count and risk score increment
    repo.increment_scan("u-100", 80.0)
    u_after = repo.get_by_id("u-100")
    assert u_after.scan_count == 1
    assert u_after.risk_score == 80.0

    # Delete
    assert repo.delete("u-100") is True
    assert repo.get_by_id("u-100") is None


# ── Incident Repository Parity Tests ──────────────────────────────────────────


@pytest.mark.parametrize("repo_type", ["in_memory", "sql"])
def test_incident_repository_crud(repo_type, sqlite_session_factory):
    if repo_type == "in_memory":
        repo = InMemoryIncidentRepository()
    else:
        repo = SQLIncidentRepository(sqlite_session_factory)

    inc = Incident(
        id="inc-1",
        title="Phishing Attempt Detected",
        description="High risk email from spoofed domain",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    repo.save(inc)

    assert repo.get_by_id("inc-1") is not None
    assert len(repo.list_all(status=IncidentStatus.OPEN)) == 1
    assert len(repo.list_all(severity=IncidentSeverity.LOW)) == 0

    # Add comment
    c = IncidentComment(
        id="comm-1",
        author_id="u-1",
        author_name="Security Analyst",
        body="Triaged and confirmed malicious.",
        created_at="2026-01-01T01:00:00Z",
    )
    repo.add_comment("inc-1", c)
    inc_with_comm = repo.get_by_id("inc-1")
    assert len(inc_with_comm.comments) == 1
    assert inc_with_comm.comments[0].body == "Triaged and confirmed malicious."

    # Update status to resolved
    repo.update("inc-1", IncidentUpdate(status=IncidentStatus.RESOLVED))
    assert repo.get_by_id("inc-1").status == IncidentStatus.RESOLVED

    # Stats
    stats = repo.stats()
    assert stats["total"] == 1
    assert stats["resolved"] == 1

    # Delete
    assert repo.delete("inc-1") is True
    assert repo.get_by_id("inc-1") is None


# ── Analytics Repository Tests ────────────────────────────────────────────────


def test_analytics_repository_full_flow():
    repo = InMemoryAnalyticsRepository()

    # Record scan event
    repo.record_scan_event(
        {
            "scan_id": "s-1",
            "timestamp": "2026-01-01T12:00:00Z",
            "ts": time.time(),
            "hour": 12,
            "day": 2,
            "sender_domain": "spoofed.com",
            "subject": "Urgent payroll",
            "final_score": 88.0,
            "verdict": "CRITICAL",
            "category": "Credential",
        }
    )

    events = repo.get_scan_events()
    assert len(events) == 1
    assert events[0]["scan_id"] == "s-1"

    summary = repo.get_dashboard_summary()
    assert summary.total_scans_today == 1
    assert summary.critical_today == 1

    feed = repo.get_threat_feed()
    assert len(feed) == 1
    assert feed[0].id == "s-1"

    heatmap = repo.get_threat_heatmap()
    assert len(heatmap) == 7 * 24  # 168 hours total

    # False positive reporting and review
    fp = FalsePositiveReport(
        id="fp-1",
        scan_id="s-1",
        reporter_id="u-2",
        reason="Legitimate partner email",
        original_score=88.0,
        original_verdict="CRITICAL",
        created_at="2026-01-01T13:00:00Z",
    )
    repo.save_false_positive(fp)
    assert len(repo.list_false_positives(reviewed=False)) == 1

    reviewed = repo.review_false_positive("fp-1", "admin-1", "Whitelisted partner domain")
    assert reviewed.reviewed is True
    assert len(repo.list_false_positives(reviewed=False)) == 0

    # Policy rules
    rule = PolicyRule(
        id="pr-1",
        name="Auto quarantine suspicious tlds",
        description="Block zip/mov links",
        enabled=True,
        condition_type="tld",
        condition_value="zip",
        action="block",
        created_by="admin-1",
        created_at="2026-01-01T00:00:00Z",
    )
    repo.save_policy_rule(rule)
    assert len(repo.list_policy_rules()) == 1
    assert repo.delete_policy_rule("pr-1") is True


# ── Webhook Repository Tests ──────────────────────────────────────────────────


def test_webhook_repository():
    repo = InMemoryWebhookRepository()

    sub = WebhookSubscription(
        id="w-1",
        url="https://siem.corp.internal/hooks",
        events=[WebhookEventType.SCAN_CRITICAL],
        secret="secret123",
        created_at="2026-01-01T00:00:00Z",
    )
    repo.save_subscription(sub)
    assert repo.get_subscription("w-1") is not None
    assert len(repo.list_subscriptions()) == 1

    delivery = WebhookDelivery(
        id="d-1",
        subscription_id="w-1",
        event_type=WebhookEventType.SCAN_CRITICAL,
        payload={"scan_id": "s-1"},
        status="success",
        attempted_at="2026-01-01T00:00:01Z",
    )
    repo.record_delivery(delivery)
    assert len(repo.get_delivery_log()) == 1

    assert repo.delete_subscription("w-1") is True
    assert repo.get_subscription("w-1") is None


# ── Cache Backend Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cache_backend_ttl_and_prefix():
    cache = InMemoryCacheBackend(default_ttl=3600)
    await cache.set("whois:domain1", "90")
    await cache.set("whois:domain2", "180")
    await cache.set("other:key", "value")

    assert await cache.get("whois:domain1") == "90"
    stats = await cache.get_stats()
    assert stats["keys_count"] == 3

    cleared = await cache.clear_prefix("whois:")
    assert cleared == 2
    assert await cache.get("whois:domain1") is None
    assert await cache.get("other:key") == "value"


def test_factory_reset_and_dependency_injection():
    reset_repositories()
    mock_repo = InMemoryUserRepository()
    set_user_repository(mock_repo)
    assert get_user_repository() is mock_repo
    reset_repositories()


def test_factory_production_missing_database_url_fails(monkeypatch):
    """Verify that in production mode, missing DATABASE_URL raises a hard error."""
    reset_repositories()
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="DATABASE_URL must be configured"):
        get_user_repository()
    reset_repositories()
