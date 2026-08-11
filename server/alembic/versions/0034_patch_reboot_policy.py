# SPDX-License-Identifier: AGPL-3.0-only
"""Add post-install reboot policy and retry bound to patch policy revisions (issue #53).

Adds four columns to ``patch_approval_policy_revisions``. All are defaulted so
existing revisions keep the fail-safe behavior: ``reboot_policy='never'`` (no
automatic reboot), a 300s reboot delay, reboot only when no user is present, and
two install attempts. No data migration is required.

Revision ID: 0034
Revises: 0033
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "patch_approval_policy_revisions",
        sa.Column("reboot_policy", sa.String(length=16), nullable=False, server_default="never"),
    )
    op.add_column(
        "patch_approval_policy_revisions",
        sa.Column("reboot_delay_seconds", sa.Integer(), nullable=False, server_default="300"),
    )
    op.add_column(
        "patch_approval_policy_revisions",
        sa.Column("reboot_requires_no_user", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "patch_approval_policy_revisions",
        sa.Column("max_install_attempts", sa.Integer(), nullable=False, server_default="2"),
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
