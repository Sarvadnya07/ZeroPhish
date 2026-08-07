"""
Webhook delivery service — HMAC signing, async dispatch with retry, delivery log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
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

from .models import (
    WebhookDelivery,
    WebhookEvent,
    WebhookEventType,
    WebhookSubscription,
    WebhookSubscriptionCreate,
)

_subscriptions: Dict[str, WebhookSubscription] = {}
_delivery_log: deque[WebhookDelivery] = deque(maxlen=1000)

MAX_RETRIES = 3
TIMEOUT_SEC = 10


def _sign(secret: str, payload: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


class WebhookService:

    @staticmethod
    def subscribe(data: WebhookSubscriptionCreate, owner_id: Optional[str] = None) -> WebhookSubscription:
        from security.middleware import is_safe_webhook_url
        import os
        allow_http = os.getenv("ENV", "development").lower() != "production"
        if not is_safe_webhook_url(data.url, allow_http=allow_http):
            raise ValueError("Invalid or unsafe webhook URL (SSRF protection)")

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
            headers=data.headers,
        )
        _subscriptions[sub_id] = sub
        return sub

    @staticmethod
    def unsubscribe(sub_id: str, owner_id: Optional[str] = None) -> bool:
        sub = _subscriptions.get(sub_id)
        if not sub:
            return False
        if owner_id and sub.owner_id != owner_id:
            return False
        _subscriptions.pop(sub_id)
        return True

    @staticmethod
    def list_subscriptions(owner_id: Optional[str] = None) -> List[WebhookSubscription]:
        subs = list(_subscriptions.values())
        if owner_id:
            subs = [s for s in subs if s.owner_id == owner_id]
        return subs

    @staticmethod
    def get_subscription(sub_id: str) -> Optional[WebhookSubscription]:
        return _subscriptions.get(sub_id)

    @staticmethod
    def delivery_log(limit: int = 100) -> List[WebhookDelivery]:
        return list(_delivery_log)[-limit:]

    @staticmethod
    async def fire(event_type: WebhookEventType, payload: Dict[str, Any]) -> None:
        """Dispatch event to all matching, enabled subscriptions (fire-and-forget)."""
        import asyncio
        targets = [s for s in _subscriptions.values() if s.enabled and event_type in s.events]
        tasks = [WebhookService._deliver(s, event_type, payload) for s in targets]
        if tasks:
            asyncio.ensure_future(asyncio.gather(*tasks, return_exceptions=True))

    @staticmethod
    async def _deliver(
        sub: WebhookSubscription,
        event_type: WebhookEventType,
        payload: Dict[str, Any],
        attempt: int = 0,
    ) -> None:
        import asyncio

        envelope = {
            "id": str(uuid.uuid4()),
            "event": event_type.value,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": payload,
        }
        body = json.dumps(envelope).encode()
        sig  = _sign(sub.secret, body)
        headers = {
            "Content-Type": "application/json",
            "X-ZeroPhish-Signature": sig,
            "X-ZeroPhish-Event": event_type.value,
            **sub.headers,
        }

        delivery_id = str(uuid.uuid4())
        start = time.perf_counter()
        delivery = WebhookDelivery(
            id=delivery_id,
            subscription_id=sub.id,
            event_type=event_type,
            payload=envelope,
            status="pending",
            attempted_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            retries=attempt,
        )

        from security.middleware import is_safe_webhook_url
        import os
        allow_http = os.getenv("ENV", "development").lower() != "production"
        if not is_safe_webhook_url(sub.url, allow_http=allow_http):
            delivery.status = "failed"
            delivery.response_body = "Unsafe or blocked destination URL (SSRF defense)"
            _delivery_log.append(delivery)
            return

        if not HTTPX_AVAILABLE:
            delivery.status = "failed"
            delivery.response_body = "httpx not installed"
            _delivery_log.append(delivery)
            return

        try:
            async with httpx.AsyncClient(timeout=TIMEOUT_SEC) as client:
                resp = await client.post(sub.url, content=body, headers=headers)
            delivery.http_status = resp.status_code
            delivery.response_body = resp.text[:512]
            delivery.status = "success" if 200 <= resp.status_code < 300 else "failed"
        except Exception as exc:
            delivery.status = "failed"
            delivery.response_body = str(exc)[:256]
        finally:
            delivery.duration_ms = (time.perf_counter() - start) * 1000
            _delivery_log.append(delivery)

        # Retry with exponential back-off
        if delivery.status == "failed" and attempt < MAX_RETRIES:
            await asyncio.sleep(2 ** attempt)
            await WebhookService._deliver(sub, event_type, payload, attempt + 1)
