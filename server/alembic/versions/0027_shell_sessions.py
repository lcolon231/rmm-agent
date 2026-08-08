# SPDX-License-Identifier: AGPL-3.0-only
"""Interactive shell session foundation (issue #61).

Adds the ``shell_sessions`` lifecycle table and an ``agents.supported_capabilities``
column used to negotiate the feature. No streamed input/output bytes are persisted;
only the authorized session, its bounds, and its outcome are recorded.

Revision ID: 0027
Revises: 0026
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


# Matches the default type name SQLAlchemy derives from ShellSessionStatus, so the
# ORM and the migrated schema agree on PostgreSQL.
shell_session_status = sa.Enum(
    "pending",
    "active",
    "closed",
    "denied",
    "timed_out",
    "failed",
    name="shellsessionstatus",
)


def upgrade() -> None:
    # Advertised agent feature capabilities (e.g. "shell-session-v1"). NULL means
    # the agent predates or does not support any, so capability-gated features
    # fail closed as "unsupported".
    op.add_column(
        "agents",
        sa.Column("supported_capabilities", sa.JSON(), nullable=True),
    )

    op.create_table(
        "shell_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("status", shell_session_status, nullable=False),
        sa.Column("capability_version", sa.String(64), nullable=True),
        sa.Column("close_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("absolute_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idle_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("output_bytes_limit", sa.BigInteger(), nullable=True),
        sa.Column(
            "output_bytes_total", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("frames_out", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("frames_in", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "client_last_seq", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "agent_last_seq", sa.BigInteger(), nullable=False, server_default="0"
        ),
    )
    op.create_index(
        "ix_shell_sessions_agent_id", "shell_sessions", ["agent_id"]
    )
    op.create_index(
        "ix_shell_sessions_operator_id", "shell_sessions", ["operator_id"]
    )
    op.create_index("ix_shell_sessions_status", "shell_sessions", ["status"])
    op.create_index(
        "ix_shell_sessions_agent_status", "shell_sessions", ["agent_id", "status"]
    )
    op.create_index(
        "ix_shell_sessions_created_at", "shell_sessions", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_shell_sessions_created_at", table_name="shell_sessions")
    op.drop_index("ix_shell_sessions_agent_status", table_name="shell_sessions")
    op.drop_index("ix_shell_sessions_status", table_name="shell_sessions")
    op.drop_index("ix_shell_sessions_operator_id", table_name="shell_sessions")
    op.drop_index("ix_shell_sessions_agent_id", table_name="shell_sessions")
    op.drop_table("shell_sessions")
    op.drop_column("agents", "supported_capabilities")
    shell_session_status.drop(op.get_bind(), checkfirst=True)
