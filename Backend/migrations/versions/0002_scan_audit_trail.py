"""
Add scan_audit_events table

Revision ID: 0002_scan_audit_trail
Revises: 0001_initial_schema
Create Date: 2026-10-10 00:00:00.000000

Creates the scan_audit_events table for durable gateway scan lifecycle auditing.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_scan_audit_trail"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("previous_state", sa.String(length=64), nullable=True),
        sa.Column("new_state", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("error_category", sa.String(length=128), nullable=True),
        sa.Column("provenance", sa.String(length=128), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_scan_audit_events_event_id", "scan_audit_events", ["event_id"], unique=True)
    op.create_index("ix_scan_audit_events_scan_id", "scan_audit_events", ["scan_id"])
    op.create_index("ix_scan_audit_events_event_type", "scan_audit_events", ["event_type"])
    op.create_index("ix_scan_audit_events_correlation_id", "scan_audit_events", ["correlation_id"])
    op.create_index("ix_scan_audit_events_actor_id", "scan_audit_events", ["actor_id"])
    op.create_index("ix_scan_audit_events_tenant_id", "scan_audit_events", ["tenant_id"])
    op.create_index("idx_scan_audit_scan_ts", "scan_audit_events", ["scan_id", "created_at"])
    op.create_index("idx_scan_audit_correlation", "scan_audit_events", ["correlation_id"])
    op.create_index("idx_scan_audit_event_type", "scan_audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("idx_scan_audit_event_type", table_name="scan_audit_events")
    op.drop_index("idx_scan_audit_correlation", table_name="scan_audit_events")
    op.drop_index("idx_scan_audit_scan_ts", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_tenant_id", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_actor_id", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_correlation_id", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_event_type", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_scan_id", table_name="scan_audit_events")
    op.drop_index("ix_scan_audit_events_event_id", table_name="scan_audit_events")
    op.drop_table("scan_audit_events")
