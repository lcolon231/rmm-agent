# SPDX-License-Identifier: AGPL-3.0-only
"""Add explicit scoped arbitrary-script permission to operators.

Revision ID: 0010
Revises: 0009

Both columns are nullable so every existing and newly created operator starts
default-denied. `scope_id` is populated only for site/agent grants. Forward-only.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


script_scope = sa.Enum("global", "site", "agent", name="scriptexecutionscope")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        script_scope.create(bind, checkfirst=True)
    op.add_column(
        "operators",
        sa.Column("script_execution_scope", script_scope, nullable=True),
    )
    op.add_column(
        "operators",
        sa.Column("script_execution_scope_id", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
