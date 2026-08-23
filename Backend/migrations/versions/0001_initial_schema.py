"""Initial baseline schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-08-24 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=256), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("mfa_secret", sa.String(length=128), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), server_default="0"),
        sa.Column("scan_count", sa.Integer(), server_default="0"),
        sa.Column("risk_score", sa.Float(), server_default="0.0"),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("last_login", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # Token Revocations
    op.create_table(
        "token_revocations",
        sa.Column("token", sa.String(length=128), primary_key=True),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_token_revocations_token", "token_revocations", ["token"], unique=False)
    op.create_index("ix_token_revocations_user_id", "token_revocations", ["user_id"], unique=False)

    # Incidents
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
        sa.Column("evidence_json", sa.Text(), server_default="[]"),
        sa.Column("tags_json", sa.Text(), server_default="[]"),
        sa.Column("false_positive", sa.Boolean(), server_default="0"),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.Column("resolved_at", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_incidents_id", "incidents", ["id"], unique=False)
    op.create_index("ix_incidents_severity", "incidents", ["severity"], unique=False)
    op.create_index("ix_incidents_status", "incidents", ["status"], unique=False)

    # Incident Comments
    op.create_table(
        "incident_comments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "incident_id", sa.String(length=64), sa.ForeignKey("incidents.id"), nullable=False
        ),
        sa.Column("author_id", sa.String(length=64), nullable=False),
        sa.Column("author_name", sa.String(length=256), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_incident_comments_id", "incident_comments", ["id"], unique=False)
    op.create_index(
        "ix_incident_comments_incident_id", "incident_comments", ["incident_id"], unique=False
    )


def downgrade() -> None:
    op.drop_table("incident_comments")
    op.drop_table("incidents")
    op.drop_table("token_revocations")
    op.drop_table("users")
