# SPDX-License-Identifier: AGPL-3.0-only
"""Approval workflows and two-person authorization (issue #64).

Adds the policy table that says *where* approval is required, the request table
that carries one proposed command and its binding, and the decision table that
records who agreed.

Two schema decisions carry security weight and are stated here because the
control rests on them:

* ``ux_approval_decision_one_per_operator`` is the real enforcement of "two
  *distinct* people". The application checks for a duplicate first to return a
  clean 409, but under concurrency it is this constraint that stops one identity
  counting twice toward a two-approval policy.
* ``approval_requests.payload_sha256`` is the execution binding. Dispatch
  recomputes the digest from the payload actually submitted and refuses on any
  difference, so an approval cannot be transplanted onto a mutated command.

Decision and request rows are never deleted by the application: a rejected,
expired, or cancelled request keeps every verdict recorded against it, because
"who declined this, and why" is the evidence the control exists to produce.
Ordinary retention pruning still applies.

Compatibility and rollout: every change is additive. The three tables are new
and ``commands.approval_request_id`` is a nullable column, so an older
application binary running against this schema never reads them and dispatches
exactly as before. The capability is additionally inert until an administrator
creates a policy -- with no policy rows, ``resolve_policy`` returns None and
every dispatch follows the pre-existing role and script-scope rules. That is
what makes this safe to apply ahead of the build that uses it, and safe to
leave applied if the build is rolled back.

Rollback: migrations here are forward-only. Backing the capability out is a
data change (delete or disable the policy rows), not a schema change, which
leaves the request and decision history intact for audit. Crossing back below
this revision requires the exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0041
Revises: 0040
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

# Mirrors app.models.models.ApprovalRequestStatus / ApprovalDecisionKind.
REQUEST_STATUS_VALUES = (
    "pending",
    "approved",
    "rejected",
    "cancelled",
    "expired",
    "consumed",
)
DECISION_VALUES = ("approve", "reject")


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # Create the new enum types once, explicitly and idempotently, then
    # reference them with create_type=False. Emitting CREATE TYPE a second time
    # from create_table fails outright on PostgreSQL (pattern from 0016/0040).
    status_type = postgresql.ENUM(*REQUEST_STATUS_VALUES, name="approvalrequeststatus")
    decision_type = postgresql.ENUM(*DECISION_VALUES, name="approvaldecisionkind")
    if is_postgres:
        status_type.create(bind, checkfirst=True)
        decision_type.create(bind, checkfirst=True)

    request_status = (
        postgresql.ENUM(
            *REQUEST_STATUS_VALUES, name="approvalrequeststatus", create_type=False
        )
        if is_postgres
        else sa.Enum(*REQUEST_STATUS_VALUES, name="approvalrequeststatus")
    )
    decision_kind = (
        postgresql.ENUM(*DECISION_VALUES, name="approvaldecisionkind", create_type=False)
        if is_postgres
        else sa.Enum(*DECISION_VALUES, name="approvaldecisionkind")
    )
    # The existing monitoringscope and commandkind/operatorrole types are reused
    # rather than redefined: an approval policy targets exactly the same scopes
    # as a monitoring or patch policy, and a divergent copy of that vocabulary
    # is precisely how the two would drift apart.
    monitoring_scope = (
        postgresql.ENUM(name="monitoringscope", create_type=False)
        if is_postgres
        else sa.String(length=16)
    )
    command_kind = (
        postgresql.ENUM(name="commandkind", create_type=False)
        if is_postgres
        else sa.String(length=64)
    )
    operator_role = (
        postgresql.ENUM(name="operatorrole", create_type=False)
        if is_postgres
        else sa.String(length=16)
    )

    op.create_table(
        "approval_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope", monitoring_scope, nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=True),
        sa.Column("command_kinds", sa.JSON(), nullable=False),
        sa.Column(
            "required_approvals", sa.Integer(), nullable=False, server_default="2"
        ),
        sa.Column(
            "request_ttl_seconds", sa.Integer(), nullable=False, server_default="3600"
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=True),
        sa.CheckConstraint(
            "required_approvals >= 1 AND required_approvals <= 2",
            name="ck_approval_policies_required_approvals",
        ),
    )
    # Case- and whitespace-insensitive uniqueness per scope target, matching the
    # monitoring/patch policy indexes.
    op.create_index(
        "ux_approval_policies_scope_name_normalized",
        "approval_policies",
        ["scope", "scope_id", sa.text("lower(trim(name))")],
        unique=True,
    )

    op.create_table(
        "approval_requests",
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
            "requested_by_operator_id",
            sa.String(length=36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("requested_by_email", sa.String(length=320), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", request_status, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by_email", sa.String(length=320), nullable=True),
        sa.Column("closed_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_approval_requests_agent_id", "approval_requests", ["agent_id"]
    )
    op.create_index(
        "ix_approval_requests_client_id", "approval_requests", ["client_id"]
    )
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])
    op.create_index(
        "ix_approval_requests_requested_by_operator_id",
        "approval_requests",
        ["requested_by_operator_id"],
    )
    op.create_index(
        "ix_approval_requests_status_expires",
        "approval_requests",
        ["status", "expires_at"],
    )
    op.create_index(
        "ix_approval_requests_client_status",
        "approval_requests",
        ["client_id", "status"],
    )

    op.create_table(
        "approval_decisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "request_id",
            sa.String(length=36),
            sa.ForeignKey("approval_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("operator_id", sa.String(length=36), nullable=False),
        sa.Column("operator_email", sa.String(length=320), nullable=False),
        sa.Column("operator_role", operator_role, nullable=False),
        sa.Column("decision", decision_kind, nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.UniqueConstraint(
            "request_id", "operator_id", name="ux_approval_decision_one_per_operator"
        ),
    )
    op.create_index(
        "ix_approval_decisions_request_id", "approval_decisions", ["request_id"]
    )

    # Execution binding recorded on the run itself. Nullable and unbackfilled:
    # NULL means "no policy required approval for this run", never a claim that
    # one was waived.
    op.add_column(
        "commands",
        sa.Column("approval_request_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_commands_approval_request_id", "commands", ["approval_request_id"]
    )
    if is_postgres:
        # SQLite cannot add a foreign key to an existing table without a full
        # table rebuild. The column is written only by the dispatcher, from an
        # id it has just validated, so the constraint is defense in depth rather
        # than the integrity guarantee -- worth having where it is free.
        op.create_foreign_key(
            "fk_commands_approval_request_id",
            "commands",
            "approval_requests",
            ["approval_request_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
