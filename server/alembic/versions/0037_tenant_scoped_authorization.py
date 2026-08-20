# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped authorization: operator-client memberships and platform admin.

Issue #66 (Milestone 3). Replaces global operator visibility with a default-deny
tenant boundary anchored on the existing Client. Adds:

  * ``Operator.is_platform_admin`` — a deployment-wide superuser flag; the only
    principal that crosses the tenant boundary.
  * ``operator_client_memberships`` — one role (``clientrole``) per
    (operator, client), the sole way a non-platform-admin sees a client.

It also anchors historical audit events to their client through the previously
unused ``audit_events.organization_id`` column, and backfills authorization so
existing operators keep today's access on upgrade:

  * existing global ``admin`` operators become platform admins;
  * existing ``operator`` / ``readonly`` operators receive a membership to every
    client that exists at upgrade time, with the equivalent client role.

New clients and new operators are default-deny. The backfill is a one-time data
migration; ongoing grant/revoke goes through the audited operator API.

Compatibility: additive and forward-only (docs/ROLLBACK.md). ``organization_id``
is not part of the audit hash document, so existing chains still verify. The new
PostgreSQL enum cannot be dropped in place; crossing back below this revision
requires the exact-revision restore procedure.

Revision ID: 0037
Revises: 0036
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


CLIENT_ROLE_VALUES = ("client_admin", "client_operator", "client_readonly")
# Preserve pre-tenancy access: map each legacy global role to its client role.
_ROLE_TO_CLIENT_ROLE = {
    "operator": "client_operator",
    "readonly": "client_readonly",
}


def upgrade() -> None:
    bind = op.get_bind()

    # Created once here so create_table can reuse it (create_type=False), the
    # same pattern as revision 0036. A no-op on SQLite.
    postgresql.ENUM(*CLIENT_ROLE_VALUES, name="clientrole").create(
        bind, checkfirst=True
    )

    op.add_column(
        "operators",
        sa.Column(
            "is_platform_admin",
            sa.Boolean(),
            nullable=False,
            server_default="0",
        ),
    )

    op.create_table(
        "operator_client_memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "client_id",
            sa.String(36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role",
            postgresql.ENUM(*CLIENT_ROLE_VALUES, name="clientrole", create_type=False),
            nullable=False,
        ),
        sa.Column("granted_by", sa.String(320), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "operator_id", "client_id", name="uq_operator_client_membership"
        ),
    )
    op.create_index(
        "ix_operator_client_memberships_operator",
        "operator_client_memberships",
        ["operator_id"],
    )
    op.create_index(
        "ix_operator_client_memberships_client",
        "operator_client_memberships",
        ["client_id"],
    )
    # Tenant-filtered audit-timeline reads land on (organization_id, ts, id).
    op.create_index(
        "ix_audit_events_org_ts",
        "audit_events",
        ["organization_id", "ts", "id"],
    )

    # --- Data backfill ----------------------------------------------------- #

    # 1. Anchor historical audit events to their client via agent -> site.
    #    System events with no resolvable agent keep NULL.
    bind.execute(
        sa.text(
            """
            UPDATE audit_events
            SET organization_id = (
                SELECT s.client_id
                FROM agents a
                JOIN sites s ON s.id = a.site_id
                WHERE a.id = audit_events.agent_id
            )
            WHERE agent_id IS NOT NULL AND organization_id IS NULL
            """
        )
    )

    # 2. Promote existing global admins to platform admin (see all tenants).
    bind.execute(
        sa.text(
            "UPDATE operators SET is_platform_admin = :flag WHERE role = 'admin'"
        ),
        {"flag": True},
    )

    # 3. Grant every existing non-admin operator a membership to every existing
    #    client, preserving pre-tenancy visibility. New clients are not granted.
    operators = bind.execute(
        sa.text(
            "SELECT id, role FROM operators WHERE role IN ('operator', 'readonly')"
        )
    ).fetchall()
    client_ids = [
        row[0] for row in bind.execute(sa.text("SELECT id FROM clients")).fetchall()
    ]
    if operators and client_ids:
        membership_table = sa.table(
            "operator_client_memberships",
            sa.column("id", sa.String),
            sa.column("operator_id", sa.String),
            sa.column("client_id", sa.String),
            sa.column("role", sa.Enum(*CLIENT_ROLE_VALUES, name="clientrole")),
            sa.column("granted_by", sa.String),
            sa.column("reason", sa.Text),
            sa.column("created_at", sa.DateTime(timezone=True)),
        )
        now = datetime.now(timezone.utc)
        rows = [
            {
                "id": str(uuid.uuid4()),
                "operator_id": operator_id,
                "client_id": client_id,
                "role": _ROLE_TO_CLIENT_ROLE[role],
                "granted_by": None,
                "reason": "0037 backfill: preserve pre-tenancy access",
                "created_at": now,
            }
            for operator_id, role in operators
            for client_id in client_ids
        ]
        op.bulk_insert(membership_table, rows)


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
