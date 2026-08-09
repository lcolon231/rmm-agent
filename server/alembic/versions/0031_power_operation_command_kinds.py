# SPDX-License-Identifier: AGPL-3.0-only
"""Add audited endpoint power-operation command kinds (issue #60).

Only the PostgreSQL enum changes. Policy evidence is stored in the existing
signed payload and audit chain, so no table or backfill is required.

Revision ID: 0031
Revises: 0030
"""
from alembic import op


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in ("reboot", "shutdown", "cancel_power_action"):
            op.execute(f"ALTER TYPE commandkind ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
