# SPDX-License-Identifier: AGPL-3.0-only
"""Signed, staged agent self-update and rollback (issue #63).

Adds the release publication table, the per-endpoint attempt table that carries
the operator-visible evidence and feeds the canary halt rule, an
``agents.update_channel`` column, and the two new command-kind enum values.

Compatibility: every change is additive. An older application ignores the new
tables and column and never dispatches the new kinds, so a mixed-version fleet
degrades to "self-update unavailable" rather than misbehaving. The new
PostgreSQL enum values cannot be removed in place; crossing back below this
revision requires the exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0035
Revises: 0034
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


# Type names match what SQLAlchemy derives from the ORM enums, so the migrated
# schema and the ORM agree on PostgreSQL.
agent_update_channel = sa.Enum(
    "stable", "beta", "canary", name="agentupdatechannel"
)
agent_update_release_state = sa.Enum(
    "published",
    "rolling",
    "paused",
    "halted",
    "completed",
    name="agentupdatereleasestate",
)
agent_update_attempt_status = sa.Enum(
    "dispatched",
    "staged",
    "succeeded",
    "rolled_back",
    "failed",
    name="agentupdateattemptstatus",
)

# Command kinds introduced by this revision plus the kinds added by issues #55,
# #56, and #57, which landed as ORM-only changes. ADD VALUE IF NOT EXISTS is
# idempotent, so naming them here repairs a PostgreSQL enum that would otherwise
# reject those commands at insert time without changing anything on a database
# that already has them.
_COMMAND_KINDS = (
    "scan_packages",
    "install_packages",
    "deploy_software",
    "list_services",
    "control_service",
    "list_processes",
    "terminate_process",
    "agent_self_update",
    "agent_update_rollback",
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Enum values must be committed before a later statement in the same
        # transaction can reference them; ADD VALUE is transactional in
        # PostgreSQL 12+, and these are only referenced by later inserts.
        for kind in _COMMAND_KINDS:
            op.execute(f"ALTER TYPE commandkind ADD VALUE IF NOT EXISTS '{kind}'")

    # Release channel the endpoint reported following. NULL means the endpoint
    # predates self-update or has not reported one, and is therefore treated as
    # following the default stable channel wherever targeting is decided.
    op.add_column("agents", sa.Column("update_channel", sa.String(16), nullable=True))

    agent_update_channel.create(bind, checkfirst=True)
    agent_update_release_state.create(bind, checkfirst=True)
    agent_update_attempt_status.create(bind, checkfirst=True)

    op.create_table(
        "agent_update_releases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("channel", agent_update_channel, nullable=False),
        sa.Column("platform", sa.String(64), nullable=False),
        sa.Column("artifact_url", sa.Text(), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("artifact_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("signer_thumbprint", sa.String(40), nullable=True),
        sa.Column("min_supported_version", sa.String(64), nullable=False),
        # The immutable signed publication record.
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False),
        sa.Column(
            "state",
            agent_update_release_state,
            nullable=False,
            server_default="published",
        ),
        sa.Column(
            "rollout_percent", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "failure_threshold_percent",
            sa.Integer(),
            nullable=False,
            server_default="20",
        ),
        sa.Column(
            "min_attempts_before_halt",
            sa.Integer(),
            nullable=False,
            server_default="5",
        ),
        sa.Column(
            "health_timeout_seconds",
            sa.Integer(),
            nullable=False,
            server_default="600",
        ),
        sa.Column("created_by_email", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("halted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("halted_reason", sa.String(100), nullable=True),
        sa.UniqueConstraint(
            "version", "channel", "platform", name="uq_agent_update_release_identity"
        ),
        sa.CheckConstraint(
            "rollout_percent >= 0 AND rollout_percent <= 100",
            name="ck_agent_update_rollout_percent",
        ),
        sa.CheckConstraint(
            "failure_threshold_percent >= 1 AND failure_threshold_percent <= 100",
            name="ck_agent_update_failure_threshold",
        ),
    )
    op.create_index(
        "ix_agent_update_releases_channel_state",
        "agent_update_releases",
        ["channel", "state"],
    )

    op.create_table(
        "agent_update_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "release_id",
            sa.String(36),
            sa.ForeignKey("agent_update_releases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            sa.String(36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "command_id",
            sa.String(36),
            sa.ForeignKey("commands.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status",
            agent_update_attempt_status,
            nullable=False,
            server_default="dispatched",
        ),
        sa.Column("from_version", sa.String(64), nullable=True),
        sa.Column("to_version", sa.String(64), nullable=True),
        sa.Column("observed_version", sa.String(64), nullable=True),
        sa.Column("reason", sa.String(100), nullable=True),
        sa.Column("health_attempts", sa.Integer(), nullable=True),
        sa.Column("rollout_bucket", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("release_id", "agent_id", name="uq_agent_update_attempt"),
    )
    op.create_index(
        "ix_agent_update_attempts_release_id", "agent_update_attempts", ["release_id"]
    )
    op.create_index(
        "ix_agent_update_attempts_agent_id", "agent_update_attempts", ["agent_id"]
    )
    op.create_index(
        "ix_agent_update_attempts_status",
        "agent_update_attempts",
        ["release_id", "status"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
