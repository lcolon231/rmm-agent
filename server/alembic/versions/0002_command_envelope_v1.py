# SPDX-License-Identifier: AGPL-3.0-only
"""Add command-envelope negotiation and persisted envelope versions.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column(
            "command_envelope_versions",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    op.add_column(
        "commands",
        sa.Column(
            "envelope_version",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'legacy-unversioned'"),
        ),
    )
    # A legacy signature does not cover envelope_version. It must never be
    # delivered as command-v1 after rollout, so queued legacy work expires.
    op.execute("UPDATE commands SET status = 'expired' WHERE status = 'queued'")


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
