# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy and check-result models.

Revision ID: 0016
Revises: 0015

Issue #41 adds the foundational monitoring data model: versioned, scoped
monitoring policies (identity + append-only revisions holding a validated check
set), scoped maintenance windows, and the append-only check-result contract that
#42's agent-side evaluation will populate. All tables are new; there is no
existing data to migrate. The enum types are created explicitly (idempotently)
so the migration is safe on PostgreSQL, where ``sa.Enum`` columns need a type to
exist first.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


SCOPE_VALUES = ("global", "client", "site", "agent")
STATUS_VALUES = ("ok", "warning", "critical", "unknown")


def _scope_column() -> postgresql.ENUM:
    # create_type=False: the type is created once by the explicit .create() calls
    # below, so create_table must not try to emit CREATE TYPE again (it is reused
    # by two tables, which would otherwise duplicate on PostgreSQL).
    return postgresql.ENUM(
        *SCOPE_VALUES, name="monitoringscope", create_type=False
    )


def upgrade() -> None:
    bind = op.get_bind()
    # Create the enum types up front, idempotently. These objects DO create the
    # type; the per-column objects above do not.
    postgresql.ENUM(*SCOPE_VALUES, name="monitoringscope").create(
        bind, checkfirst=True
    )
    postgresql.ENUM(*STATUS_VALUES, name="checkresultstatus").create(
        bind, checkfirst=True
    )
    check_result_status = postgresql.ENUM(
        *STATUS_VALUES, name="checkresultstatus", create_type=False
    )

    op.create_table(
        "monitoring_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope", _scope_column(), nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ux_monitoring_policies_scope_name_normalized",
        "monitoring_policies",
        ["scope", "scope_id", sa.text("lower(trim(name))")],
        unique=True,
    )

    op.create_table(
        "monitoring_policy_revisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "policy_id",
            sa.String(length=36),
            sa.ForeignKey("monitoring_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "policy_id", "version", name="ux_monitoring_policy_revision_version"
        ),
    )
    op.create_index(
        "ix_monitoring_policy_revisions_policy_id",
        "monitoring_policy_revisions",
        ["policy_id"],
    )

    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope", _scope_column(), nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "check_results",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(length=36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(length=36), nullable=True),
        sa.Column("policy_revision_id", sa.String(length=36), nullable=True),
        sa.Column("check_key", sa.String(length=64), nullable=False),
        sa.Column("status", check_result_status, nullable=False),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_check_results_agent_id", "check_results", ["agent_id"])
    op.create_index("ix_check_results_received_at", "check_results", ["received_at"])
    op.create_index(
        "ix_check_results_agent_key_received",
        "check_results",
        ["agent_id", "check_key", "received_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
