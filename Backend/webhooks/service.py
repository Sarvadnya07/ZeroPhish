"""
Webhook delivery service — HMAC signing, async dispatch with retry, delivery log.

Backed by repository abstraction. Supports exponential backoff with jitter,
configurable timeouts, and connection pooling.

Environment variables:
- WEBHOOK_MAX_RETRIES: int (default 3)
- WEBHOOK_TIMEOUT_SEC: int (default 10)
- WEBHOOK_MAX_CONCURRENT: int (default 20)
- WEBHOOK_RETRY_BACKOFF_BASE: float (default 2.0)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None

from repositories.factory import get_webhook_repository
from security.middleware import is_safe_webhook_url

from .models import (
    WebhookDelivery,
    WebhookEvent,
    WebhookEventType,
    WebhookSubscription,
    WebhookSubscriptionCreate,
)

logger = logging.getLogger(__name__)

# ---------- Configuration ----------
MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))
TIMEOUT_SEC = float(os.getenv("WEBHOOK_TIMEOUT_SEC", "10.0"))
MAX_CONCURRENT = int(os.getenv("WEBHOOK_MAX_CONCURRENT", "20"))
RETRY_BACKOFF_BASE = float(os.getenv("WEBHOOK_RETRY_BACKOFF_BASE", "2.0"))
JITTER_FACTOR = 0.5  # ±50% jitter
ENV = os.getenv("ENV", "development")

# In‑memory fallback for tests (direct references)
_subscriptions: Dict[str, WebhookSubscription] = {}
_delivery_log: deque[WebhookDelivery] = deque(maxlen=1000)

# Shared httpx client with connection pooling (lazy init).
# Annotate as Optional[Any] to avoid referencing httpx.AsyncClient at import
# time when httpx may be unavailable (ImportError fallback sets httpx=None).
_client: Optional[Any] = None
_client_lock = asyncio.Lock()


async def _get_client() -> Any:
    """Get or create a shared httpx client with connection pooling."""
    global _client
    if not HTTPX_AVAILABLE:
        raise RuntimeError("httpx is not available; install httpx to enable webhook delivery")
    if _client is None:
        async with _client_lock:
            if _client is None:
                # Use getattr to access httpx.Timeout/Limits to satisfy static analyzers
                TimeoutCls = getattr(httpx, "Timeout")
                LimitsCls = getattr(httpx, "Limits")
                _client = httpx.AsyncClient(  # type: ignore[attr-defined]
                    timeout=TimeoutCls(TIMEOUT_SEC, connect=5.0),
                    limits=LimitsCls(max_keepalive_connections=MAX_CONCURRENT, max_connections=MAX_CONCURRENT),
                )
                logger.info("Webhook HTTP client initialized (max_connections=%d)", MAX_CONCURRENT)
    return _client


async def _close_client() -> None:
    """Close the shared HTTP client (for graceful shutdown)."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
        logger.info("Webhook HTTP client closed.")


def _sign(secret: str, payload: bytes) -> str:
    """Generate HMAC‑SHA256 signature for webhook payload."""
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _backoff(attempt: int) -> float:
    """Calculate exponential backoff with jitter."""
    base = RETRY_BACKOFF_BASE ** attempt
    jitter = base * (1 + (random.random() - 0.5) * JITTER_FACTOR * 2)
    return min(jitter, 30.0)  # cap at 30 seconds


class WebhookService:
    """
    Service for managing webhook subscriptions and dispatching events.

    All methods are static; they delegate to the repository for persistence.
    """

    @staticmethod
    def subscribe(
        data: WebhookSubscriptionCreate,
        owner_id: Optional[str] = None,
    ) -> WebhookSubscription:
        """
        Create a new webhook subscription.

        Validates the URL (SSRF protection) and generates a secret.

        Raises:
            ValueError: If the URL is unsafe or invalid.
        """
        is_dev = ENV == "development"
        if not is_safe_webhook_url(data.url, allow_http=is_dev):
            raise ValueError(f"Provided webhook URL is unsafe or invalid: {data.url}")

        repo = get_webhook_repository()
        sub_id = str(uuid.uuid4())
        secret = secrets.token_hex(32)

        sub = WebhookSubscription(
            id=sub_id,
            url=data.url,
            events=data.events,
            secret=secret,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            owner_id=owner_id,
            description=data.description,
            headers=data.headers or {},
        )
        saved = repo.save_subscription(sub)
        _subscriptions[saved.id] = saved
        logger.info("Webhook subscription created: id=%s, owner=%s, events=%d",
                    sub_id, owner_id, len(data.events))
        return saved

    @staticmethod
    def unsubscribe(sub_id: str, owner_id: Optional[str] = None) -> bool:
        """Delete a subscription. Owner check applied if provided."""
        repo = get_webhook_repository()
        _subscriptions.pop(sub_id, None)
        deleted = repo.delete_subscription(sub_id, owner_id=owner_id)
        if deleted:
            logger.info("Webhook subscription deleted: id=%s, owner=%s", sub_id, owner_id)
        return deleted

    @staticmethod
    def list_subscriptions(owner_id: Optional[str] = None) -> List[WebhookSubscription]:
        """List subscriptions, optionally filtered by owner."""
        repo = get_webhook_repository()
        return repo.list_subscriptions(owner_id=owner_id)

    @staticmethod
    def get_subscription(sub_id: str) -> Optional[WebhookSubscription]:
        """Retrieve a subscription by ID."""
        repo = get_webhook_repository()
        return repo.get_subscription(sub_id)

    @staticmethod
    def delivery_log(limit: int = 100) -> List[WebhookDelivery]:
        """Get recent delivery log entries."""
        repo = get_webhook_repository()
        return repo.get_delivery_log(limit=limit)

    @staticmethod
    async def fire(event_type: WebhookEventType, payload: Dict[str, Any]) -> None:
        """
        Dispatch event to all matching, enabled subscriptions (fire‑and‑forget).

        Uses a semaphore to limit concurrency per batch.
        """
        repo = get_webhook_repository()
        targets = [s for s in repo.list_subscriptions() if s.enabled and event_type in s.events]

        if not targets:
            logger.debug("No enabled subscriptions for event %s", event_type.value)
            return

        logger.info("Firing event %s to %d subscriptions", event_type.value, len(targets))

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        async def bounded_deliver(sub: WebhookSubscription) -> None:
            async with semaphore:
                await WebhookService._deliver(sub, event_type, payload)

        tasks = [bounded_deliver(s) for s in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _deliver(
        sub: WebhookSubscription,
        event_type: WebhookEventType,
        payload: Dict[str, Any],
        attempt: int = 0,
    ) -> None:
        """
        Deliver a single webhook event with retries and exponential backoff.

        Attempts up to MAX_RETRIES. After each failure, sleeps with backoff+jitter.
        """
        repo = get_webhook_repository()
        delivery_id = str(uuid.uuid4())
        timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        envelope = {
            "id": delivery_id,
            "event": event_type.value,
            "timestamp": timestamp_str,
            "data": payload,
        }
        body = json.dumps(envelope).encode()
        sig = _sign(sub.secret, body)

        headers = {
            "Content-Type": "application/json",
            "X-ZeroPhish-Signature": sig,
            "X-ZeroPhish-Event": event_type.value,
            "X-ZeroPhish-Timestamp": timestamp_str,
            "X-ZeroPhish-Delivery-ID": delivery_id,
            **sub.headers,
        }

        delivery = WebhookDelivery(
            id=delivery_id,
            subscription_id=sub.id,
            event_type=event_type,
            payload=envelope,
            status="pending",
            attempted_at=timestamp_str,
            retries=attempt,
        )

        if not HTTPX_AVAILABLE:
            delivery.status = "failed"
            delivery.response_body = "httpx not installed"
            repo.record_delivery(delivery)
            _delivery_log.append(delivery)
            logger.error("Webhook delivery failed (httpx unavailable): sub=%s", sub.id)
            return

        start = time.perf_counter()
        try:
            client = await _get_client()
            resp = await client.post(sub.url, content=body, headers=headers)
            delivery.http_status = resp.status_code
            delivery.response_body = resp.text[:512]
            delivery.status = "success" if 200 <= resp.status_code < 300 else "failed"
        except Exception as exc:
            delivery.status = "failed"
            delivery.response_body = str(exc)[:256]
            logger.warning("Webhook delivery error (sub=%s, attempt=%d): %s", sub.id, attempt, exc)
        finally:
            delivery.duration_ms = (time.perf_counter() - start) * 1000
            repo.record_delivery(delivery)
            _delivery_log.append(delivery)

        # Retry if failed and under limit
        if delivery.status == "failed" and attempt < MAX_RETRIES:
            delay = _backoff(attempt + 1)
            logger.info("Retrying webhook delivery (sub=%s, attempt=%d, delay=%.2fs)", sub.id, attempt + 1, delay)
            await asyncio.sleep(delay)
            await WebhookService._deliver(sub, event_type, payload, attempt + 1)
        elif delivery.status == "success":
            logger.debug("Webhook delivered successfully: sub=%s, event=%s", sub.id, event_type.value)
        else:
            logger.warning("Webhook delivery permanently failed: sub=%s, event=%s", sub.id, event_type.value)