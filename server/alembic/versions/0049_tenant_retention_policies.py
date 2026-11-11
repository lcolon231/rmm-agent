# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-specific retention policies (issue #88).

Adds ``tenant_retention_policies``: one optional row per tenant (client) whose
nullable columns override the platform retention defaults. A missing row, or a
NULL column, inherits the platform value, so no backfill is required and every
existing tenant keeps exactly the retention it had before this revision.

``ix_alerts_state_resolved`` supports the new resolved-alert pruner, which
selects by ``state`` and ``resolved_at``.

Compatibility and rollout: every change is additive. An older application
binary never reads the new table or index. The new destructive classes
(command records, resolved alerts, notification deliveries) default to 0 --
keep forever -- so applying this revision and deploying the build that uses it
deletes nothing that was not already pruned until an operator opts in.

Rollback: migrations here are forward-only. Backing a tenant's policy out is
an API call (``DELETE /clients/{id}/retention-policy`` reverts it to the
platform defaults); backing the capability out is setting the new
``*_RETENTION_DAYS`` back to 0. Crossing back below this revision requires the
exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0049
Revises: 0048
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_retention_policies",
        sa.Column(
            "client_id",
            sa.String(length=36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("telemetry_days", sa.Integer(), nullable=True),
        sa.Column("command_output_days", sa.Integer(), nullable=True),
        sa.Column("command_record_days", sa.Integer(), nullable=True),
        sa.Column("inventory_history_per_section", sa.Integer(), nullable=True),
        sa.Column("alert_days", sa.Integer(), nullable=True),
        sa.Column("notification_days", sa.Integer(), nullable=True),
        sa.Column("evidence_default_days", sa.Integer(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("set_by", sa.String(length=320), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_state_resolved", "alerts", ["state", "resolved_at"])


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
