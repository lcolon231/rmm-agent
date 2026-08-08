# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled tasks schema for recurring task scheduling (issue #49).

Revision ID: 0026
Revises: 0025
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("target_type", sa.String(20), nullable=False),  # "agent" or "site"
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False, server_default="UTC"),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column(
            "script_version_id",
            sa.String(36),
            sa.ForeignKey("script_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("concurrency_policy", sa.String(20), nullable=False, server_default="skip"),
        sa.Column("misfire_policy", sa.String(20), nullable=False, server_default="run_once"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(50), nullable=True),
        sa.Column(
            "created_by_operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_email", sa.String(320), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("ix_scheduled_tasks_due", "scheduled_tasks", ["enabled", "next_run_at"])
    op.create_index("ix_scheduled_tasks_target", "scheduled_tasks", ["target_type", "target_id"])


def downgrade() -> None:
    op.drop_index("ix_scheduled_tasks_target", table_name="scheduled_tasks")
    op.drop_index("ix_scheduled_tasks_due", table_name="scheduled_tasks")
    op.drop_table("scheduled_tasks")
