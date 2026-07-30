# SPDX-License-Identifier: AGPL-3.0-only
"""Per-section agent inventory snapshots.

Revision ID: 0014
Revises: 0013

Inventory previously had a single free-form ``agents.inventory`` JSON column
written straight from the heartbeat body with no schema and no size bound. No
released agent ever populated it — the runtime always sent ``nil`` — so the
column is NULL in every deployment and there is nothing to migrate. This
revision adds the validated per-section table and leaves the old column in
place, unwritten, so a rollback to the previous server finds the schema it
expects. A later revision drops it once no supported server references it.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_inventory_snapshots",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(length=36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("section", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_agent_inventory_snapshots_agent_id",
        "agent_inventory_snapshots",
        ["agent_id"],
    )
    op.create_index(
        "ix_agent_inventory_snapshots_received_at",
        "agent_inventory_snapshots",
        ["received_at"],
    )
    # Serves both reads this table has: "newest row for this section" and
    # "history for this section, newest first".
    op.create_index(
        "ix_agent_inventory_agent_section_received",
        "agent_inventory_snapshots",
        ["agent_id", "section", "received_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_inventory_agent_section_received",
        table_name="agent_inventory_snapshots",
    )
    op.drop_index(
        "ix_agent_inventory_snapshots_received_at",
        table_name="agent_inventory_snapshots",
    )
    op.drop_index(
        "ix_agent_inventory_snapshots_agent_id",
        table_name="agent_inventory_snapshots",
    )
    op.drop_table("agent_inventory_snapshots")
