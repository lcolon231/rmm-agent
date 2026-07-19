# SPDX-License-Identifier: AGPL-3.0-only
"""Record command output truncation evidence.

Revision ID: 0006
Revises: 0005

Historical rows stay NULL: their outputs were captured before limits existed,
so "unknown" is the honest value — never backfill them as complete or
truncated. Forward-only, like every NodeLink migration.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("commands", sa.Column("stdout_truncated", sa.Boolean(), nullable=True))
    op.add_column("commands", sa.Column("stderr_truncated", sa.Boolean(), nullable=True))
    op.add_column(
        "commands", sa.Column("stdout_total_bytes", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "commands", sa.Column("stderr_total_bytes", sa.BigInteger(), nullable=True)
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
