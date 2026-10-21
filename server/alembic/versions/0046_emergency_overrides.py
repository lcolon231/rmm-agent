# SPDX-License-Identifier: AGPL-3.0-only
"""Justified emergency override (issue #65).

Adds the per-policy opt-in that says an approval requirement *may* be stood in
for by one authorized person in an emergency, the table that records each such
exception, and the link from a command run to the override it spent.

The security weight sits on two columns, stated here for the same reason 0041
states its own:

* ``approval_policies.emergency_override_allowed`` defaults to false. Nothing
  in this revision changes the behavior of any existing policy; a tenant that
  never flips the flag keeps strict dual control exactly as before.
* ``emergency_overrides.payload_sha256`` is the execution binding. Dispatch
  recomputes it from the submitted payload and refuses on any difference, so an
  override minted for one command cannot be transplanted onto another.

Override rows are never deleted by the application. Expired, revoked, and
consumed overrides keep their justification, notification outcome, and review,
because "who invoked the exception, who was told, and who checked it" is the
evidence the control exists to produce. Ordinary retention pruning applies.

Compatibility and rollout: every change is additive. The new table and the two
nullable/defaulted columns are never read by an older application binary, which
dispatches exactly as before. The capability is inert until an administrator
opts a policy in, so the schema is safe to apply ahead of the build that uses
it and safe to leave applied if that build is rolled back.

Rollback: migrations here are forward-only. Backing the capability out is a
data change (clear the policy flag), not a schema change. Crossing back below
this revision requires the exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0046
Revises: 0045
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None

# Mirrors app.models.models.EmergencyOverrideStatus.
STATUS_VALUES = ("active", "consumed", "expired", "revoked")


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    status_type = postgresql.ENUM(*STATUS_VALUES, name="emergencyoverridestatus")
    if is_postgres:
        status_type.create(bind, checkfirst=True)
    override_status = (
        postgresql.ENUM(*STATUS_VALUES, name="emergencyoverridestatus", create_type=False)
        if is_postgres
        else sa.Enum(*STATUS_VALUES, name="emergencyoverridestatus")
    )
    command_kind = (
        postgresql.ENUM(name="commandkind", create_type=False)
        if is_postgres
        else sa.String(length=64)
    )

    # Opt-in flag. server_default=false is the whole compatibility story: no
    # existing policy becomes overridable by applying this revision.
    op.add_column(
        "approval_policies",
        sa.Column(
            "emergency_override_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.create_table(
        "emergency_overrides",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(length=36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("client_id", sa.String(length=36), nullable=True),
        sa.Column("site_id", sa.String(length=36), nullable=True),
        sa.Column("kind", command_kind, nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=True),
        sa.Column("required_approvals", sa.Integer(), nullable=False),
        sa.Column(
            "activated_by_operator_id",
            sa.String(length=36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("activated_by_email", sa.String(length=320), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("status", override_status, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_email", sa.String(length=320), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notification_error", sa.String(length=64), nullable=True),
        sa.Column(
            "notified_recipient_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_email", sa.String(length=320), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
    )
    op.create_index("ix_emergency_overrides_agent_id", "emergency_overrides", ["agent_id"])
    op.create_index("ix_emergency_overrides_client_id", "emergency_overrides", ["client_id"])
    op.create_index("ix_emergency_overrides_status", "emergency_overrides", ["status"])
    op.create_index(
        "ix_emergency_overrides_activated_by_operator_id",
        "emergency_overrides",
        ["activated_by_operator_id"],
    )
    op.create_index(
        "ix_emergency_overrides_client_status",
        "emergency_overrides",
        ["client_id", "status"],
    )
    op.create_index(
        "ix_emergency_overrides_unreviewed",
        "emergency_overrides",
        ["reviewed_at", "created_at"],
    )

    # Execution binding on the run itself, exactly like approval_request_id.
    op.add_column(
        "commands",
        sa.Column("emergency_override_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_commands_emergency_override_id", "commands", ["emergency_override_id"]
    )
    if is_postgres:
        # SQLite cannot add a foreign key to an existing table without a full
        # rebuild; the dispatcher only ever writes an id it has just validated,
        # so the constraint is defense in depth where it is free.
        op.create_foreign_key(
            "fk_commands_emergency_override_id",
            "commands",
            "emergency_overrides",
            ["emergency_override_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
