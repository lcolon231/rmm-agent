# SPDX-License-Identifier: AGPL-3.0-only
"""Administrative session management and break-glass access (issue #69).

Adds the server-side operator session table that makes sessions inventoryable
and individually revocable, plus the break-glass account and activation-review
tables.

Compatibility and rollout: every change is additive and introduces no new
non-nullable column on an existing table, so an older application binary running
against this schema simply never reads the new tables and keeps issuing
stateless sessions. That is what makes activation safe to stage -- the schema
can be migrated well ahead of the build that uses it.

Sessions issued before this revision carry no ``sid`` claim. They are accepted
until they expire on their own (``ADMIN_SESSION_ACCEPT_LEGACY_TOKENS``, default
true) so that upgrading does not sign an entire fleet out mid-shift; such
sessions are unmanaged but still bounded by the access-token lifetime and still
killed by a ``token_generation`` bump. Set the flag false to refuse them.

Rollback: migrations here are forward-only. Backing this capability out is a
configuration change (``BREAK_GLASS_ENABLED=false``, and the legacy-token flag),
not a schema change; crossing back below this revision requires the
exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0039
Revises: 0038
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


# Matches what SQLAlchemy derives from the OperatorSessionEndReason ORM enum, so
# the migrated schema and the ORM agree on PostgreSQL.
END_REASON_VALUES = (
    "revoked_by_self",
    "revoked_by_admin",
    "idle_timeout",
    "absolute_timeout",
    "superseded",
    "operator_disabled",
)


def upgrade() -> None:
    bind = op.get_bind()

    # Create the enum type once, explicitly and idempotently, then reference it
    # from create_table with create_type=False. Emitting CREATE TYPE a second
    # time from create_table fails outright on PostgreSQL (pattern from 0016).
    end_reason = postgresql.ENUM(*END_REASON_VALUES, name="operatorsessionendreason")
    end_reason.create(bind, checkfirst=True)

    op.create_table(
        "operator_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("auth_methods", sa.String(120), nullable=False, server_default=""),
        # IPv6 needs 45 characters at most.
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column(
            "is_break_glass", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "end_reason",
            postgresql.ENUM(
                *END_REASON_VALUES,
                name="operatorsessionendreason",
                create_type=False,
            ),
            nullable=True,
        ),
        sa.Column("ended_by_operator_id", sa.String(36), nullable=True),
    )
    op.create_index(
        "ix_operator_sessions_operator_id", "operator_sessions", ["operator_id"]
    )
    # The hot path, evaluated on every authenticated request and every inventory
    # read: the live sessions for one operator.
    op.create_index(
        "ix_operator_sessions_operator_active",
        "operator_sessions",
        ["operator_id", "ended_at"],
    )
    # Supports the bounded sweep that marks lapsed sessions terminal.
    op.create_index(
        "ix_operator_sessions_absolute_expires",
        "operator_sessions",
        ["absolute_expires_at"],
    )

    op.create_table(
        "break_glass_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        # Unique: one emergency credential per dedicated identity, so disabling
        # or rotating one can never affect another.
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(120), nullable=False),
        # bcrypt digest of the credential, never the credential.
        sa.Column("credential_hash", sa.String(255), nullable=False),
        sa.Column("credential_fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by_email", sa.String(320), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "activation_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_reason", sa.String(200), nullable=True),
        sa.UniqueConstraint("operator_id", name="uq_break_glass_operator"),
        sa.UniqueConstraint("label", name="uq_break_glass_label"),
    )
    op.create_index(
        "ix_break_glass_accounts_operator_id", "break_glass_accounts", ["operator_id"]
    )

    op.create_table(
        "break_glass_activations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "account_id",
            sa.String(36),
            sa.ForeignKey("break_glass_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SET NULL, not CASCADE: the activation record is the accountability
        # artefact and must outlive the session it opened.
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("operator_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_email", sa.String(320), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_break_glass_activations_account_id",
        "break_glass_activations",
        ["account_id"],
    )
    # Drives the "what still needs review" queue.
    op.create_index(
        "ix_break_glass_activations_unreviewed",
        "break_glass_activations",
        ["reviewed_at", "activated_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
