# SPDX-License-Identifier: AGPL-3.0-only
"""Add the install_updates command kind.

Selective Windows Update installation is dispatched through the ordinary command
pipeline, so ``commandkind`` gains a new value. Forward-only.

Revision ID: 0029
Revises: 0028
"""
from __future__ import annotations

from alembic import op


revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "ALTER TYPE commandkind ADD VALUE IF NOT EXISTS 'install_updates'"
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
