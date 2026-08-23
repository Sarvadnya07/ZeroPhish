"""
Webhook subscription models.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class WebhookEventType(str, Enum):
    SCAN_COMPLETE = "scan.complete"
    SCAN_CRITICAL = "scan.critical"  # score >= 70
    SCAN_SUSPICIOUS = "scan.suspicious"  # 30-69
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    CIRCUIT_OPENED = "circuit.opened"
    USER_REGISTERED = "user.registered"
    FALSE_POSITIVE_FLAGGED = "false_positive.flagged"


class WebhookSubscription(BaseModel):
    id: str
    url: str
    events: List[WebhookEventType]
    secret: str  # HMAC-SHA256 signing secret
    enabled: bool = True
    created_at: str
    owner_id: Optional[str] = None
    description: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)  # extra HTTP headers


class WebhookSubscriptionCreate(BaseModel):
    url: str = Field(..., max_length=2048)
    events: List[WebhookEventType]
    description: Optional[str] = Field(None, max_length=256)
    headers: Dict[str, str] = Field(default_factory=dict)


class WebhookDelivery(BaseModel):
    id: str
    subscription_id: str
    event_type: WebhookEventType
    payload: Dict[str, Any]
    status: str  # "success" | "failed" | "pending"
    http_status: Optional[int] = None
    response_body: Optional[str] = None
    attempted_at: str
    duration_ms: Optional[float] = None
    retries: int = 0


class WebhookEvent(BaseModel):
    event_type: WebhookEventType
    payload: Dict[str, Any]
