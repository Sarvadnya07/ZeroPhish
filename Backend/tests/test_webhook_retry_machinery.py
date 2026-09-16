"""
Webhook retry-machinery characterization suite.

Fills the failure-injection gap identified in the behavioral trustworthiness
review: ``WebhookService._deliver`` is the only component with a retry loop
(bounded attempts + exponential backoff + jitter), and prior to this suite its
retry behavior had NO test coverage — only the SSRF-rejection single-attempt
path was pinned (test_p0_remediation). If the retry condition, attempt cap, or
delivery-ledger bookkeeping ever regresses (e.g. unbounded retries, retries on
success, or lost delivery records), these tests fail.

Behavior characterized (from webhooks/service.py, not from intent):
- failures are retried up to MAX_RETRIES additional attempts
- retries sleep with exponential backoff + jitter (mocked: never actually slept)
- a success on a retry attempt stops the loop and records status="success"
- every attempt appends a delivery record; ``retries`` reflects the attempt index
- SSRF-blocked targets are marked failed (http_status 403) and NOT retried
  (status "failed" IS the retry condition — but the SSRF path returns before
  the retry branch via its early record/log/append; pinned here so a future
  edit cannot silently make SSRF blocks retryable)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from repositories.factory import reset_repositories, set_webhook_repository
from repositories.in_memory import InMemoryWebhookRepository
from webhooks.models import WebhookEventType, WebhookSubscription
from webhooks.service import MAX_RETRIES, RETRY_BACKOFF_BASE, WebhookService, _backoff, _delivery_log


def _mock_public_dns():
    """Mock DNS so SSRF pre-connection resolution sees a safe public IP (offline-safe).
    Same pattern as tests/test_webhooks.py."""
    return patch(
        "socket.getaddrinfo",
        return_value=[(None, None, None, None, ("1.1.1.1", 443))],
    )


def _subscription(sub_id: str = "sub-retry-1") -> WebhookSubscription:
    return WebhookSubscription(
        id=sub_id,
        url="https://hooks.example.com/alert",
        events=[WebhookEventType.SCAN_COMPLETE],
        secret="test-secret-at-least-32-chars-long-secure",
        owner_id="user-1",
        enabled=True,
    )


@pytest.fixture(autouse=True)
def _isolated_repo():
    reset_repositories()
    set_webhook_repository(InMemoryWebhookRepository())
    yield
    reset_repositories()


@pytest.fixture(autouse=True)
def _no_sleep():
    """Retry backoff sleeps must never slow the suite; capture requested delays instead."""
    with patch("webhooks.service.asyncio.sleep", new=AsyncMock()) as mock_sleep:
        yield mock_sleep


def _attempts_of(sub_id: str):
    return [d for d in _delivery_log if d.subscription_id == sub_id]


# ---------------------------------------------------------------------------
# 1. Bounded retries: always-failing HTTP target
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_failure_retried_up_to_max_retries_then_stops(_no_sleep):
    sub = _subscription()
    failing_response = MagicMock(status_code=500, text="boom")

    with _mock_public_dns(), patch("webhooks.service._get_client", new=AsyncMock()) as mock_client:
        client = MagicMock()
        client.post = AsyncMock(return_value=failing_response)
        mock_client.return_value = client

        await WebhookService._deliver(sub, WebhookEventType.SCAN_COMPLETE, {"k": "v"})

        # Initial attempt + MAX_RETRIES retries
        assert client.post.await_count == 1 + MAX_RETRIES
        attempts = _attempts_of(sub.id)
        assert len(attempts) == 1 + MAX_RETRIES
        assert all(a.status == "failed" for a in attempts)
        # retries field reflects the attempt index (0..MAX_RETRIES)
        assert [a.retries for a in attempts] == list(range(1 + MAX_RETRIES))


# ---------------------------------------------------------------------------
# 2. Backoff is exponential with jitter and grows across attempts
# ---------------------------------------------------------------------------

def test_backoff_base_schedule_is_exponential():
    """With jitter neutralized (random=0.5), delay == base**attempt exactly."""
    with patch("webhooks.service.random.random", return_value=0.5):
        assert _backoff(1) == pytest.approx(RETRY_BACKOFF_BASE)
        assert _backoff(2) == pytest.approx(RETRY_BACKOFF_BASE ** 2)
        assert _backoff(3) == pytest.approx(RETRY_BACKOFF_BASE ** 3)


def test_backoff_jitter_stays_within_bounds():
    """±50% jitter: every sample within [base*(1-f), base*(1+f)].

    NOTE: adjacent attempts' jitter bands overlap (2*1.5 > 4*0.5), so delay
    ordering across attempts is NOT guaranteed by the implementation — only
    the per-attempt band is. Do not assert cross-attempt ordering here.
    """
    for attempt in (1, 2, 3):
        samples = [_backoff(attempt) for _ in range(50)]
        expected_base = RETRY_BACKOFF_BASE ** attempt
        assert all(
            expected_base * 0.5 <= s <= expected_base * 1.5 for s in samples
        ), f"attempt {attempt}: samples outside jitter bound: {samples[:3]}"
        # jitter means not all samples identical
        assert len(set(round(s, 6) for s in samples)) > 1


@pytest.mark.asyncio
async def test_retry_delays_follow_backoff_schedule(_no_sleep):
    sub = _subscription()
    failing_response = MagicMock(status_code=503, text="overloaded")

    with _mock_public_dns(), patch("webhooks.service._get_client", new=AsyncMock()) as mock_client:
        client = MagicMock()
        client.post = AsyncMock(return_value=failing_response)
        mock_client.return_value = client

        await WebhookService._deliver(sub, WebhookEventType.SCAN_COMPLETE, {"k": "v"})

        delays = [call.args[0] for call in _no_sleep.await_args_list]
        assert len(delays) == MAX_RETRIES
        # Schedule must use attempt+1 (not the current attempt): neutralize jitter
        # by re-deriving the expected bases and checking each delay is within
        # that attempt's ±50% band. (Bands overlap, so ordering is not asserted.)
        for idx, delay in enumerate(delays, start=1):
            base = RETRY_BACKOFF_BASE ** idx
            assert base * 0.5 <= delay <= base * 1.5, (
                f"retry {idx} delay {delay} outside backoff band [{base*0.5}, {base*1.5}]"
            )


# ---------------------------------------------------------------------------
# 3. Recovery: success on a retry attempt stops the loop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_success_on_retry_stops_loop(_no_sleep):
    sub = _subscription("sub-retry-recover")
    fail_response = MagicMock(status_code=500, text="transient")
    ok_response = MagicMock(status_code=200, text="ok")

    with _mock_public_dns(), patch("webhooks.service._get_client", new=AsyncMock()) as mock_client:
        client = MagicMock()
        client.post = AsyncMock(side_effect=[fail_response, fail_response, ok_response])
        mock_client.return_value = client

        await WebhookService._deliver(sub, WebhookEventType.SCAN_COMPLETE, {"k": "v"})

        assert client.post.await_count == 3  # fail, fail, success
        attempts = _attempts_of(sub.id)
        assert len(attempts) == 3
        assert attempts[-1].status == "success"
        assert attempts[-1].http_status == 200
        assert [a.retries for a in attempts] == [0, 1, 2]


# ---------------------------------------------------------------------------
# 4. Ledger integrity: every attempt is recorded with duration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_every_attempt_recorded_with_duration_and_payload(_no_sleep):
    sub = _subscription("sub-retry-ledger")
    failing_response = MagicMock(status_code=500, text="boom")

    with _mock_public_dns(), patch("webhooks.service._get_client", new=AsyncMock()) as mock_client:
        client = MagicMock()
        client.post = AsyncMock(return_value=failing_response)
        mock_client.return_value = client

        await WebhookService._deliver(sub, WebhookEventType.SCAN_COMPLETE, {"scan": "s1"})

        attempts = _attempts_of(sub.id)
        assert len(attempts) == 1 + MAX_RETRIES
        for a in attempts:
            assert a.duration_ms >= 0.0
            assert a.payload["event"] == WebhookEventType.SCAN_COMPLETE.value
            assert a.payload["data"] == {"scan": "s1"}
            assert a.response_body  # failure body captured for diagnosis


# ---------------------------------------------------------------------------
# 5. SSRF rejection is terminal: no retries, single attempt, 403
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssrf_blocked_target_is_not_retried(_no_sleep):
    sub = WebhookSubscription(
        id="sub-retry-ssrf",
        url="http://169.254.169.254/latest/meta-data",
        events=[WebhookEventType.SCAN_COMPLETE],
        secret="test-secret-at-least-32-chars-long-secure",
        owner_id="user-1",
        enabled=True,
    )

    with _mock_public_dns(), patch("webhooks.service._get_client", new=AsyncMock()) as mock_client:
        client = MagicMock()
        client.post = AsyncMock()
        mock_client.return_value = client

        await WebhookService._deliver(sub, WebhookEventType.SCAN_COMPLETE, {"k": "v"})

        # never reached the HTTP client at all
        client.post.assert_not_awaited()
        attempts = _attempts_of(sub.id)
        assert len(attempts) == 1
        assert attempts[0].status == "failed"
        assert attempts[0].http_status == 403
        assert "SSRF blocked" in attempts[0].response_body
        # and no retry sleep was requested
        _no_sleep.assert_not_awaited()
