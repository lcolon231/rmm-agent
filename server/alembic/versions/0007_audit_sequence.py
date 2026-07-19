# SPDX-License-Identifier: AGPL-3.0-only
"""Add monotonic audit sequence numbers with legacy backfill.

Revision ID: 0007
Revises: 0006

Existing events are assigned seq 1..N in their historical (ts, id) order —
the order verification and anchoring already used — and marked hash_schema=1
to record, permanently and honestly, that their hashes do NOT cover the
sequence (it did not exist when they were written). Events appended after
this revision bind seq into their hash (hash_schema=2). Rewriting legacy
hashes to pretend otherwise would itself be history falsification, so it is
deliberately not done.

Forward-only, like every NodeLink migration.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column(
        "audit_events",
        sa.Column(
            "hash_schema",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
        ),
    )

    # Freeze the historical order into explicit sequence numbers. ROW_NUMBER
    # over (ts, id) reproduces the exact order the verifier and anchors used
    # before sequences existed. Works on PostgreSQL and SQLite >= 3.25.
    op.execute(
        """
        UPDATE audit_events SET
            seq = (
                SELECT rn FROM (
                    SELECT id, ROW_NUMBER() OVER (ORDER BY ts, id) AS rn
                    FROM audit_events
                ) ordered WHERE ordered.id = audit_events.id
            ),
            hash_schema = 1
        """
    )

    op.create_index("ux_audit_events_seq", "audit_events", ["seq"], unique=True)


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
