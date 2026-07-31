# SPDX-License-Identifier: AGPL-3.0-only
"""Widen the inventory section status column.

Revision ID: 0015
Revises: 0014

``agent_inventory_snapshots.status`` was sized at 16 characters, which fit
every status the section vocabulary had when it was created (``ok``,
``partial``, ``unavailable``, ``unsupported``). ``permission_denied`` is 17.

This is worth a migration rather than a shorter name because the failure it
would otherwise cause is silent in exactly the wrong place: SQLite ignores
VARCHAR length entirely, so an over-long value passes every local and CI SQLite
test and only fails against PostgreSQL, where it raises rather than truncates.

Widening a varchar is a metadata-only change on PostgreSQL — no table rewrite.
The downgrade narrows it back, which is safe only while no stored row exceeds
16 characters, so it refuses rather than truncating operator-visible evidence.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_inventory_snapshots") as batch:
        batch.alter_column(
            "status",
            existing_type=sa.String(length=16),
            type_=sa.String(length=32),
            existing_nullable=False,
        )


def downgrade() -> None:
    # Truncating a status would turn "permission_denied" into something that
    # reads as a different, wrong fact about an endpoint. Refuse instead.
    over_long = op.get_bind().execute(
        sa.text(
            "SELECT count(*) FROM agent_inventory_snapshots WHERE length(status) > 16"
        )
    ).scalar_one()
    if over_long:
        raise RuntimeError(
            f"Cannot narrow agent_inventory_snapshots.status: {over_long} row(s) "
            "hold a status longer than 16 characters. Resolve or delete those "
            "snapshots before downgrading."
        )
    with op.batch_alter_table("agent_inventory_snapshots") as batch:
        batch.alter_column(
            "status",
            existing_type=sa.String(length=32),
            type_=sa.String(length=16),
            existing_nullable=False,
        )
