"""
SQLAlchemy 2.x ORM models for durable storage across ZeroPhish domains.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


class UserDB(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    email = Column(String(320), unique=True, index=True, nullable=False)
    full_name = Column(String(256), nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="user", nullable=False)
    status = Column(String(32), default="active", nullable=False)
    mfa_secret = Column(String(128), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    scan_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    created_at = Column(String(64), nullable=False)
    last_login = Column(String(64), nullable=True)


class TokenRevocationDB(Base):
    __tablename__ = "token_revocations"

    token = Column(String(128), primary_key=True, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    expires_at = Column(Float, nullable=False)


class IncidentDB(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), default="open", nullable=False, index=True)
    scan_id = Column(String(64), nullable=True, index=True)
    reporter_id = Column(String(64), nullable=True, index=True)
    assignee_id = Column(String(64), nullable=True, index=True)
    final_score = Column(Float, nullable=True)
    sender = Column(String(320), nullable=True)
    subject = Column(String(500), nullable=True)
    evidence_json = Column(Text, default="[]")
    tags_json = Column(Text, default="[]")
    false_positive = Column(Boolean, default=False)
    created_at = Column(String(64), nullable=False)
    updated_at = Column(String(64), nullable=False)
    resolved_at = Column(String(64), nullable=True)

    comments = relationship("IncidentCommentDB", back_populates="incident", cascade="all, delete-orphan")


class IncidentCommentDB(Base):
    __tablename__ = "incident_comments"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=False, index=True)
    author_id = Column(String(64), nullable=False)
    author_name = Column(String(256), nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False)

    incident = relationship("IncidentDB", back_populates="comments")


class ScanEventDB(Base):
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(String(64), nullable=False)
    ts = Column(Float, index=True, nullable=False)
    hour = Column(Integer, nullable=False)
    day = Column(Integer, nullable=False)
    sender_domain = Column(String(256), index=True, nullable=False)
    subject = Column(String(500), nullable=True)
    final_score = Column(Float, nullable=False)
    verdict = Column(String(32), index=True, nullable=False)
    category = Column(String(128), nullable=False)
    tier1_score = Column(Float, default=0.0)
    tier2_score = Column(Float, default=0.0)
    tier3_score = Column(Float, default=0.0)
    user_id = Column(String(64), nullable=True, index=True)


class FalsePositiveDB(Base):
    __tablename__ = "false_positives"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), nullable=False, index=True)
    reporter_id = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    original_score = Column(Float, nullable=False)
    original_verdict = Column(String(32), nullable=False)
    reviewed = Column(Boolean, default=False, index=True)
    reviewer_id = Column(String(64), nullable=True)
    resolution = Column(Text, nullable=True)
    created_at = Column(String(64), nullable=False)


class PolicyRuleDB(Base):
    __tablename__ = "policy_rules"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    condition_type = Column(String(64), nullable=False)
    condition_value = Column(String(500), nullable=False)
    action = Column(String(64), nullable=False)
    created_by = Column(String(64), nullable=False)
    created_at = Column(String(64), nullable=False)


class WebhookSubscriptionDB(Base):
    __tablename__ = "webhook_subscriptions"

    id = Column(String(64), primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    events_json = Column(Text, nullable=False)
    secret = Column(String(128), nullable=False)
    enabled = Column(Boolean, default=True)
    owner_id = Column(String(64), nullable=True, index=True)
    description = Column(String(500), nullable=True)
    headers_json = Column(Text, default="{}")
    created_at = Column(String(64), nullable=False)


class WebhookDeliveryDB(Base):
    __tablename__ = "webhook_deliveries"

    id = Column(String(64), primary_key=True, index=True)
    subscription_id = Column(String(64), ForeignKey("webhook_subscriptions.id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    payload_json = Column(Text, nullable=False)
    status = Column(String(32), nullable=False)
    http_status = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    attempted_at = Column(String(64), nullable=False)
    duration_ms = Column(Float, nullable=True)
    retries = Column(Integer, default=0)


class ScanResultDB(Base):
    __tablename__ = "scan_results"

    scan_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False)
    partial_score = Column(Float, nullable=False)
    final_score = Column(Float, nullable=True)
    verdict = Column(String(32), nullable=False)
    complete = Column(Boolean, default=False)
    layers_completed = Column(Integer, default=0)
    data_json = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False)
