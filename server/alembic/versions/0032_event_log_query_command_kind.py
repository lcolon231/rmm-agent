# SPDX-License-Identifier: AGPL-3.0-only
"""Add bounded Windows event log query command kind (issue #58).

Only the PostgreSQL enum changes. The query payload and its metadata-only result
live in the existing signed payload, command output, and audit chain, so no
table or backfill is required.

Revision ID: 0032
Revises: 0031
"""
from alembic import op


revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE commandkind ADD VALUE IF NOT EXISTS 'query_event_log'")


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
