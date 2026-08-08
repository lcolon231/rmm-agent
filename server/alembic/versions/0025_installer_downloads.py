# SPDX-License-Identifier: AGPL-3.0-only
"""Personalized installer download records (issue #9).

Adds the installer_downloads table: one audit/retention row per personalized
installer package a technician downloads for a site. Only metadata is stored —
the minted enrollment token's secret lives (hashed) on enrollment_tokens, never
here. The row links to that token, records who downloaded which verified stock
artifact, and carries the token expiry for expiry/revocation display and
retention cleanup.

Revision ID: 0025
Revises: 0024
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "installer_downloads",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "site_id",
            sa.String(36),
            sa.ForeignKey("sites.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "enrollment_token_id",
            sa.String(36),
            sa.ForeignKey("enrollment_tokens.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_by_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
        ),
        sa.Column("created_by_email", sa.String(320)),
        sa.Column("artifact_version", sa.String(100), nullable=False, server_default=""),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index(
        "ix_installer_downloads_site_id", "installer_downloads", ["site_id"]
    )
    op.create_index(
        "ix_installer_downloads_enrollment_token_id",
        "installer_downloads",
        ["enrollment_token_id"],
    )
    op.create_index(
        "ix_installer_downloads_created_by_id",
        "installer_downloads",
        ["created_by_id"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
