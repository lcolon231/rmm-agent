# SPDX-License-Identifier: AGPL-3.0-only
"""Add per-operator arbitrary-script-execution permission (default-deny).

Revision ID: 0009
Revises: 0008

Arbitrary powershell/shell execution is gated by an explicit per-operator grant
separate from role (issue #111). Existing operators are backfilled to the
default-deny state (``false``): after this migration nobody can dispatch an
arbitrary script until an admin explicitly grants the permission, which is the
intended fail-closed posture. Forward-only, like every NodeLink migration.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "operators",
        sa.Column(
            "can_execute_scripts",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
