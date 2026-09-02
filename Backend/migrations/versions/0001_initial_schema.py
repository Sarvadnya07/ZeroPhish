"""
Initial baseline schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-08-24 00:00:00.000000

This migration creates the initial schema for ZeroPhish with all core tables:
- users (with Clerk integration)
- token_revocations
- incidents & incident_comments
- scan_events
- false_positives
- policy_rules
- webhook_subscriptions & webhook_deliveries
- scan_results (cache)
"""

# pyright: reportMissingImports=false

from typing import Sequence, Union

import sqlalchemy as sa  # type: ignore[reportMissingImports]
from alembic import op
from sqlalchemy.dialects.postgresql import TIMESTAMP, JSONB  # type: ignore[reportMissingImports]

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ────────────────────────────────────────────────────────────────────────────
    # 1. Users table (Clerk-integrated)
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("clerk_user_id", sa.String(length=128), unique=True, nullable=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=256), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=True),  # Optional for Clerk-only auth
        sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("scan_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        # Timestamps: now using TIMEZONE-aware datetime
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_clerk_user_id", "users", ["clerk_user_id"], unique=True)

    # ────────────────────────────────────────────────────────────────────────────
    # 2. Token Revocations
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "token_revocations",
        sa.Column("token", sa.String(length=128), primary_key=True),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_token_revocations_token", "token_revocations", ["token"])
    op.create_index("ix_token_revocations_user_id", "token_revocations", ["user_id"])

    # ────────────────────────────────────────────────────────────────────────────
    # 3. Incidents
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("scan_id", sa.String(length=64), nullable=True),
        sa.Column("reporter_id", sa.String(length=64), nullable=True),
        sa.Column("assignee_id", sa.String(length=64), nullable=True),
        sa.Column("final_score", sa.Float(), nullable=True),
        sa.Column("sender", sa.String(length=320), nullable=True),
        sa.Column("subject", sa.String(length=500), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("false_positive", sa.Boolean(), nullable=False, server_default="0"),
        # Timestamps: timezone-aware
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_id", "incidents", ["id"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_scan_id", "incidents", ["scan_id"])
    op.create_index("ix_incidents_reporter_id", "incidents", ["reporter_id"])
    op.create_index("ix_incidents_assignee_id", "incidents", ["assignee_id"])

    # ────────────────────────────────────────────────────────────────────────────
    # 4. Incident Comments
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "incident_comments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("author_id", sa.String(length=64), nullable=False),
        sa.Column("author_name", sa.String(length=256), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    # Foreign key with cascade
    op.create_foreign_key(
        "fk_incident_comments_incident_id",
        "incident_comments",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_incident_comments_id", "incident_comments", ["id"])
    op.create_index("ix_incident_comments_incident_id", "incident_comments", ["incident_id"])
    op.create_index(
        "ix_incident_comments_incident_created",
        "incident_comments",
        ["incident_id", "created_at"],
    )

    # ────────────────────────────────────────────────────────────────────────────
    # 5. Scan Events (analytics)
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "scan_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ts", sa.Float(), nullable=False),
        sa.Column("hour", sa.Integer(), nullable=False),
        sa.Column("day", sa.Integer(), nullable=False),
        sa.Column("sender_domain", sa.String(length=256), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=True),
        sa.Column("final_score", sa.Float(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("tier1_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("tier2_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("tier3_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("user_id", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_scan_events_scan_id", "scan_events", ["scan_id"])
    op.create_index("ix_scan_events_ts", "scan_events", ["ts"])
    op.create_index("ix_scan_events_sender_domain", "scan_events", ["sender_domain"])
    op.create_index("ix_scan_events_verdict", "scan_events", ["verdict"])
    op.create_index("ix_scan_events_user_id", "scan_events", ["user_id"])
    # Composite indexes for common queries
    op.create_index(
        "ix_scan_events_scan_ts",
        "scan_events",
        ["scan_id", "ts"],
    )
    op.create_index(
        "ix_scan_events_sender_ts",
        "scan_events",
        ["sender_domain", "ts"],
    )

    # ────────────────────────────────────────────────────────────────────────────
    # 6. False Positives
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "false_positives",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("reporter_id", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("original_score", sa.Float(), nullable=False),
        sa.Column("original_verdict", sa.String(length=32), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("reviewer_id", sa.String(length=64), nullable=True),
        sa.Column("resolution", sa.Text(), nullable=True),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_false_positives_id", "false_positives", ["id"])
    op.create_index("ix_false_positives_scan_id", "false_positives", ["scan_id"])
    op.create_index("ix_false_positives_reviewed", "false_positives", ["reviewed"])
    op.create_index(
        "ix_fp_scan_reviewed",
        "false_positives",
        ["scan_id", "reviewed"],
    )

    # ────────────────────────────────────────────────────────────────────────────
    # 7. Policy Rules
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "policy_rules",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("condition_type", sa.String(length=64), nullable=False),
        sa.Column("condition_value", sa.String(length=500), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_rules_id", "policy_rules", ["id"])

    # ────────────────────────────────────────────────────────────────────────────
    # 8. Webhook Subscriptions
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("events_json", sa.Text(), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("owner_id", sa.String(length=64), nullable=True),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("headers_json", sa.Text(), nullable=False, server_default="{}"),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_webhook_subscriptions_id", "webhook_subscriptions", ["id"])
    op.create_index("ix_webhook_subscriptions_owner_id", "webhook_subscriptions", ["owner_id"])

    # ────────────────────────────────────────────────────────────────────────────
    # 9. Webhook Deliveries
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("subscription_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("retries", sa.Integer(), nullable=False, server_default="0"),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_foreign_key(
        "fk_webhook_deliveries_subscription_id",
        "webhook_deliveries",
        "webhook_subscriptions",
        ["subscription_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_webhook_deliveries_id", "webhook_deliveries", ["id"])
    op.create_index(
        "ix_webhook_deliveries_subscription_id",
        "webhook_deliveries",
        ["subscription_id"],
    )
    op.create_index(
        "ix_delivery_subscription_status",
        "webhook_deliveries",
        ["subscription_id", "status"],
    )

    # ────────────────────────────────────────────────────────────────────────────
    # 10. Scan Results (cache)
    # ────────────────────────────────────────────────────────────────────────────
    op.create_table(
        "scan_results",
        sa.Column("scan_id", sa.String(length=64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("partial_score", sa.Float(), nullable=False),
        sa.Column("final_score", sa.Float(), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("complete", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("layers_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),  # UNIX timestamp for cache TTL
        # Optional TTL column (not yet used)
        # sa.Column("expires_at", sa.Float(), nullable=True),
    )
    op.create_index("ix_scan_results_scan_id", "scan_results", ["scan_id"])
    op.create_index("ix_scan_results_created", "scan_results", ["created_at"])


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table("scan_results")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_subscriptions")
    op.drop_table("policy_rules")
    op.drop_table("false_positives")
    op.drop_table("scan_events")
    op.drop_table("incident_comments")
    op.drop_table("incidents")
    op.drop_table("token_revocations")
    op.drop_table("users")