# SPDX-License-Identifier: AGPL-3.0-only
"""Add agent trust state (active/quarantined/revoked) with change metadata.

Revision ID: 0005
Revises: 0004

Every existing agent is backfilled to 'active' — this migration does not change
the effective trust of any enrolled agent, it only makes trust explicit and
operable. Forward-only, like every NodeLink migration.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    trust_enum = sa.Enum("active", "quarantined", "revoked", name="agenttruststate")
    # add_column does not auto-create the PostgreSQL enum type the way
    # create_table does; a no-op on SQLite.
    trust_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "agents",
        sa.Column(
            "trust_state",
            trust_enum,
            nullable=False,
            server_default=sa.text("'active'"),
        ),
    )
    op.add_column("agents", sa.Column("trust_state_reason", sa.Text(), nullable=True))
    op.add_column(
        "agents",
        sa.Column("trust_state_changed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "agents", sa.Column("trust_state_changed_by", sa.String(320), nullable=True)
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
