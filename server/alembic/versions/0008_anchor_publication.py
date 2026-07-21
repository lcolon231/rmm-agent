# SPDX-License-Identifier: AGPL-3.0-only
"""Record external publication of audit anchors.

Revision ID: 0008
Revises: 0007

Additive only: a new anchor_publications table. Existing anchors have no
publication rows and are simply reported as unpublished by the status endpoint
until the scheduler publishes them. No backfill — an anchor made before this
revision was never externally published, and pretending otherwise would be the
kind of false record the audit system exists to prevent. Forward-only.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "anchor_publications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "anchor_id",
            sa.String(36),
            sa.ForeignKey("audit_anchors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("backend", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("uri", sa.String(1024), nullable=True),
        sa.Column("receipt", sa.JSON(), nullable=True),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("anchor_id", "backend", name="ux_anchor_publication_backend"),
    )
    op.create_index(
        "ix_anchor_publications_anchor_id", "anchor_publications", ["anchor_id"]
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
