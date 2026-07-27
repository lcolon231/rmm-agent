# SPDX-License-Identifier: AGPL-3.0-only
"""Add durable command-result delivery state.

Revision ID: 0009
Revises: 0008

`result_pending` distinguishes execution/outcome completion on the endpoint
from server acknowledgement. `agent_completed_at` retains the agent-local
completion timestamp separately from `completed_at`, which remains the server
receipt time. Forward-only.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "ALTER TYPE commandstatus ADD VALUE IF NOT EXISTS "
            "'result_pending' AFTER 'running'"
        )
    op.add_column(
        "commands",
        sa.Column("agent_completed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
