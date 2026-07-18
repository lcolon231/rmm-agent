# SPDX-License-Identifier: AGPL-3.0-only
"""Bind schema, timestamps, and a nonce into command-v2 signatures.

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable is intentional: historical command-v1 rows never signed these
    # values, so inventing backfill values would misrepresent their provenance.
    op.add_column("commands", sa.Column("schema_version", sa.Integer(), nullable=True))
    op.add_column(
        "commands", sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("commands", sa.Column("nonce", sa.String(64), nullable=True))
    op.create_index(
        "ux_commands_agent_nonce", "commands", ["agent_id", "nonce"], unique=True
    )

    # Active agents accept only command-v2. Retire queued v1 work rather than
    # reinterpret it under a stronger contract its signature did not cover.
    op.execute(
        "UPDATE commands SET status = 'expired' "
        "WHERE status = 'queued' AND envelope_version = 'command-v1'"
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
