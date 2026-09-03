"""
Webhook subscription models.

Defines the data contracts for webhook subscriptions, events, and delivery logs.
All timestamps are timezone‑aware datetime objects (UTC).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class WebhookEventType(str, Enum):
    """Supported webhook event types."""
    SCAN_COMPLETE = "scan.complete"
    SCAN_CRITICAL = "scan.critical"      # score >= 70
    SCAN_SUSPICIOUS = "scan.suspicious"  # 30-69
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    CIRCUIT_OPENED = "circuit.opened"
    USER_REGISTERED = "user.registered"
    FALSE_POSITIVE_FLAGGED = "false_positive.flagged"


class WebhookSubscription(BaseModel):
    """
    A webhook subscription for receiving event notifications.

    Attributes:
        id: Unique subscription identifier.
        url: Destination URL for webhook deliveries.
        events: List of event types to subscribe to.
        secret: HMAC‑SHA256 secret for signing payloads.
        enabled: Whether the subscription is active.
        created_at: Timestamp when the subscription was created.
        owner_id: Optional user ID of the subscription owner.
        description: Optional human‑readable description.
        headers: Extra HTTP headers to include in deliveries.
    """
    id: str = Field(..., min_length=1, description="Unique subscription identifier")
    url: HttpUrl = Field(..., description="Destination URL for webhook deliveries")
    events: List[WebhookEventType] = Field(..., min_length=1, description="Subscribed event types")
    secret: str = Field(..., min_length=32, max_length=64, description="HMAC‑SHA256 signing secret")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Creation timestamp (UTC)")
    owner_id: Optional[str] = Field(None, min_length=1, description="Owner user ID")
    description: Optional[str] = Field(None, max_length=256, description="Human‑readable description")
    headers: Dict[str, str] = Field(default_factory=dict, description="Extra HTTP headers")

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Ensure header keys are not reserved and values are non‑empty."""
        reserved = {"content-type", "x-zerophish-signature", "x-zerophish-event",
                    "x-zerophish-timestamp", "x-zerophish-delivery-id"}
        for key, value in v.items():
            if key.lower() in reserved:
                raise ValueError(f"Header key '{key}' is reserved")
            if not value or not value.strip():
                raise ValueError(f"Header value for '{key}' cannot be empty")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: List[WebhookEventType]) -> List[WebhookEventType]:
        if not v:
            raise ValueError("At least one event type must be subscribed")
        return v


class WebhookSubscriptionCreate(BaseModel):
    """
    Payload for creating a new webhook subscription.

    Attributes:
        url: Destination URL.
        events: List of event types to subscribe to.
        description: Optional description.
        headers: Extra HTTP headers.
    """
    url: HttpUrl = Field(..., description="Destination URL")
    events: List[WebhookEventType] = Field(..., min_length=1, description="Subscribed event types")
    description: Optional[str] = Field(None, max_length=256, description="Human‑readable description")
    headers: Dict[str, str] = Field(default_factory=dict, description="Extra HTTP headers")

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        reserved = {"content-type", "x-zerophish-signature", "x-zerophish-event",
                    "x-zerophish-timestamp", "x-zerophish-delivery-id"}
        for key, value in v.items():
            if key.lower() in reserved:
                raise ValueError(f"Header key '{key}' is reserved")
            if not value or not value.strip():
                raise ValueError(f"Header value for '{key}' cannot be empty")
        return v


class WebhookDelivery(BaseModel):
    """
    Record of a single webhook delivery attempt.

    Attributes:
        id: Unique delivery identifier.
        subscription_id: ID of the subscription this delivery is for.
        event_type: The event type that triggered this delivery.
        payload: The full payload sent.
        status: Delivery status (success, failed, pending).
        http_status: HTTP status code from the target server (if any).
        response_body: Response body from the target (truncated).
        attempted_at: Timestamp when the delivery was attempted.
        duration_ms: Round‑trip time in milliseconds.
        retries: Number of retry attempts before this delivery.
    """
    id: str = Field(..., min_length=1, description="Unique delivery identifier")
    subscription_id: str = Field(..., min_length=1, description="Subscription ID")
    event_type: WebhookEventType = Field(..., description="Event type")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Full payload")
    status: str = Field(..., description="Delivery status: success, failed, pending")
    http_status: Optional[int] = Field(None, ge=100, le=599, description="HTTP status code")
    response_body: Optional[str] = Field(None, max_length=1024, description="Response body (truncated)")
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Attempt timestamp (UTC)")
    duration_ms: Optional[float] = Field(None, ge=0.0, description="Round‑trip time in milliseconds")
    retries: int = Field(default=0, ge=0, le=10, description="Number of retries before this delivery")


class WebhookEvent(BaseModel):
    """
    A webhook event to be dispatched.

    Attributes:
        event_type: The event type.
        payload: The event payload.
    """
    event_type: WebhookEventType = Field(..., description="Event type")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Event payload")