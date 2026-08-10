# SPDX-License-Identifier: AGPL-3.0-only
"""Patch approval policies and recurring maintenance windows (issue #52).

Adds the versioned, scoped patch approval policy tables (identity + append-only
revisions, mirroring the monitoring policy model) and extends maintenance
windows with an optional IANA timezone and weekly recurrence. The tables reuse
the existing ``monitoringscope`` PostgreSQL enum created in revision 0016, so no
new type is defined here. Existing absolute maintenance windows are unaffected:
``timezone`` defaults to UTC and ``recurrence`` is NULL.

Revision ID: 0033
Revises: 0032
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


SCOPE_VALUES = ("global", "client", "site", "agent")


def _scope_column() -> postgresql.ENUM:
    # Reuse the enum created in 0016; do not emit CREATE TYPE again.
    return postgresql.ENUM(*SCOPE_VALUES, name="monitoringscope", create_type=False)


def upgrade() -> None:
    op.create_table(
        "patch_approval_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope", _scope_column(), nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ux_patch_approval_policies_scope_name_normalized",
        "patch_approval_policies",
        ["scope", "scope_id", sa.text("lower(trim(name))")],
        unique=True,
    )

    op.create_table(
        "patch_approval_policy_revisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "policy_id",
            sa.String(length=36),
            sa.ForeignKey("patch_approval_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("default_action", sa.String(length=16), nullable=False, server_default="deny"),
        sa.Column(
            "require_maintenance_window",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "policy_id", "version", name="ux_patch_approval_policy_revision_version"
        ),
    )
    op.create_index(
        "ix_patch_approval_policy_revisions_policy_id",
        "patch_approval_policy_revisions",
        ["policy_id"],
    )

    op.add_column(
        "maintenance_windows",
        sa.Column("timezone", sa.String(length=64), nullable=False, server_default="UTC"),
    )
    op.add_column(
        "maintenance_windows",
        sa.Column("recurrence", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
