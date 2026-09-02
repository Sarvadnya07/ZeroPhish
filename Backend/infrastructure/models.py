"""
SQLAlchemy 2.x ORM models for durable storage across ZeroPhish domains.

This module defines the core database entities for users, incidents, scan events,
false positives, policy rules, webhooks, and scan results. All models use
timezone-aware datetime fields and appropriate constraints.

Relationships are explicitly defined, and indexes are added for common query patterns.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (  # type: ignore[import-not-found]
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship  # type: ignore[import-not-found]

from .database import Base


# ---------- Mixins ----------
class TimestampMixin:
    """Mixin to add created_at and updated_at timestamp columns."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ---------- User Model ----------
class UserDB(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    clerk_user_id: Mapped[Optional[str]] = mapped_column(
        String(128), unique=True, index=True, nullable=True
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(256), nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="user", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships (if any)
    # incidents_reported = relationship("IncidentDB", foreign_keys="IncidentDB.reporter_id")
    # incidents_assigned = relationship("IncidentDB", foreign_keys="IncidentDB.assignee_id")

    def __repr__(self) -> str:
        return f"<UserDB id={self.id} email={self.email} role={self.role}>"


# ---------- Token Revocation ----------
class TokenRevocationDB(Base):
    __tablename__ = "token_revocations"

    token: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False)  # timestamp as float


# ---------- Incident Models ----------
class IncidentDB(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    reporter_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    assignee_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    final_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    sender: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, server_default="[]")
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, server_default="[]")
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    comments: Mapped[List["IncidentCommentDB"]] = relationship(
        "IncidentCommentDB",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<IncidentDB id={self.id} title={self.title[:30]} severity={self.severity}>"


class IncidentCommentDB(Base, TimestampMixin):
    __tablename__ = "incident_comments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    incident_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[str] = mapped_column(String(64), nullable=False)
    author_name: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped["IncidentDB"] = relationship("IncidentDB", back_populates="comments")

    __table_args__ = (
        Index("idx_incident_comments_incident_created", "incident_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<IncidentCommentDB id={self.id} incident={self.incident_id}>"


# ---------- Scan Events ----------
class ScanEventDB(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ts: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    hour: Mapped[int] = mapped_column(Integer, nullable=False)
    day: Mapped[int] = mapped_column(Integer, nullable=False)
    sender_domain: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    final_score: Mapped[float] = mapped_column(Float, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    tier1_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tier2_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tier3_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    __table_args__ = (
        Index("idx_scan_events_scan_ts", "scan_id", "ts"),
        Index("idx_scan_events_sender_ts", "sender_domain", "ts"),
    )

    def __repr__(self) -> str:
        return f"<ScanEventDB id={self.id} scan={self.scan_id} score={self.final_score}>"


# ---------- False Positives ----------
class FalsePositiveDB(Base, TimestampMixin):
    __tablename__ = "false_positives"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reporter_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    original_score: Mapped[float] = mapped_column(Float, nullable=False)
    original_verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    reviewer_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # created_at and updated_at from TimestampMixin

    __table_args__ = (
        Index("idx_fp_scan_reviewed", "scan_id", "reviewed"),
    )


# ---------- Policy Rules ----------
class PolicyRuleDB(Base, TimestampMixin):
    __tablename__ = "policy_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    condition_type: Mapped[str] = mapped_column(String(64), nullable=False)
    condition_value: Mapped[str] = mapped_column(String(500), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)

    def __repr__(self) -> str:
        return f"<PolicyRuleDB id={self.id} name={self.name} enabled={self.enabled}>"


# ---------- Webhooks ----------
class WebhookSubscriptionDB(Base, TimestampMixin):
    __tablename__ = "webhook_subscriptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    events_json: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of event types
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    owner_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    headers_json: Mapped[str] = mapped_column(Text, nullable=False, server_default="{}")

    # Relationships
    deliveries: Mapped[List["WebhookDeliveryDB"]] = relationship(
        "WebhookDeliveryDB",
        back_populates="subscription",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<WebhookSubscriptionDB id={self.id} url={self.url[:30]}>"


class WebhookDeliveryDB(Base, TimestampMixin):
    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    subscription_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    retries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    subscription: Mapped["WebhookSubscriptionDB"] = relationship(
        "WebhookSubscriptionDB", back_populates="deliveries"
    )

    __table_args__ = (
        Index("idx_delivery_subscription_status", "subscription_id", "status"),
    )


# ---------- Scan Results (cache) ----------
class ScanResultDB(Base):
    __tablename__ = "scan_results"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    partial_score: Mapped[float] = mapped_column(Float, nullable=False)
    final_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    layers_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)  # UNIX timestamp
    # Optionally add expires_at for cache TTL

    __table_args__ = (
        Index("idx_scan_results_created", "created_at"),
    )