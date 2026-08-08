# SPDX-License-Identifier: AGPL-3.0-only
"""Add the scan_updates command kind (issue #51).

The typed Windows Update scan is dispatched through the ordinary command
pipeline, so ``commandkind`` gains a new value. The normalized scan result is
carried by the ``windows_updates`` inventory section, which stores as JSON and
needs no schema change. Forward-only.

Revision ID: 0028
Revises: 0027
"""
from __future__ import annotations

from alembic import op


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # PostgreSQL 12+ permits ADD VALUE inside a transaction as long as the
        # new value is not used in the same transaction; this migration only
        # adds it. IF NOT EXISTS keeps re-runs safe.
        op.execute(
            "ALTER TYPE commandkind ADD VALUE IF NOT EXISTS 'scan_updates'"
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
