# SPDX-License-Identifier: AGPL-3.0-only
"""Repair legacy debug-created databases that were stamped past revisions.

Revision ID: 0012
Revises: 0011

Some early development databases were created with ``Base.metadata.create_all``
and had no Alembic version. Stamping those databases as a later revision made
Alembic skip additive migrations 0002-0011. This forward repair is conditional:
correctly migrated databases are unchanged, while missing columns, indexes, and
the anchor-publication table are restored with the original migration semantics.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns(table)
    }


def _index_names(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {
        item["name"]
        for item in (
            inspector.get_indexes(table) + inspector.get_unique_constraints(table)
        )
        if item.get("name")
    }


def _add_column(table: str, column: sa.Column) -> bool:
    if column.name in _columns(table):
        return False
    op.add_column(table, column)
    return True


def _create_index(
    name: str, table: str, columns: list[str], *, unique: bool = False
) -> None:
    if name not in _index_names(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # Revisions 0009 and 0010 may also have been skipped when a debug-created
    # database was stamped directly to the then-current head.
    _add_column(
        "commands",
        sa.Column("agent_completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    if "script_execution_scope" not in _columns("operators"):
        script_scope = sa.Enum(
            "global", "site", "agent", name="scriptexecutionscope"
        )
        if bind.dialect.name == "postgresql":
            script_scope.create(bind, checkfirst=True)
        op.add_column(
            "operators",
            sa.Column("script_execution_scope", script_scope, nullable=True),
        )
    _add_column(
        "operators",
        sa.Column("script_execution_scope_id", sa.String(36), nullable=True),
    )

    # Revision 0011 enrollment fields are included because this repair is
    # specifically for databases whose revision marker advanced without the
    # matching schema. Correctly migrated databases are unchanged.
    _add_column(
        "enrollment_tokens",
        sa.Column(
            "token_prefix",
            sa.String(12),
            nullable=False,
            server_default="",
        ),
    )
    token_name_added = _add_column(
        "enrollment_tokens",
        sa.Column(
            "name",
            sa.String(200),
            nullable=False,
            server_default="Enrollment token",
        ),
    )
    _add_column(
        "enrollment_tokens", sa.Column("description", sa.Text(), nullable=True)
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("assigned_user_id", sa.String(36), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("environment", sa.String(100), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("hostname_restriction", sa.String(255), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("agent_name_restriction", sa.String(255), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column(
            "labels",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("created_by_id", sa.String(36), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column(
        "enrollment_tokens",
        sa.Column("revoked_by_id", sa.String(36), nullable=True),
    )
    _add_column("enrollment_tokens", sa.Column("notes", sa.Text(), nullable=True))
    if token_name_added:
        op.execute(
            "UPDATE enrollment_tokens SET name = "
            "CASE WHEN label IS NOT NULL AND label <> '' "
            "THEN label ELSE 'Legacy enrollment token' END"
        )
    _create_index(
        "ix_enrollment_tokens_assigned_user_id",
        "enrollment_tokens",
        ["assigned_user_id"],
    )
    _create_index(
        "ix_enrollment_tokens_created_by_id",
        "enrollment_tokens",
        ["created_by_id"],
    )
    _create_index(
        "ix_enrollment_tokens_revoked_by_id",
        "enrollment_tokens",
        ["revoked_by_id"],
    )

    _add_column(
        "agents",
        sa.Column("credential_fingerprint", sa.String(64), nullable=True),
    )
    _add_column(
        "agents",
        sa.Column("credential_issued_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column(
        "agents",
        sa.Column("credential_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column(
        "agents",
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
    )
    _add_column(
        "agents",
        sa.Column(
            "architecture", sa.String(100), nullable=False, server_default=""
        ),
    )
    _add_column("agents", sa.Column("environment", sa.String(100), nullable=True))
    _add_column(
        "agents",
        sa.Column(
            "labels",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    _add_column("agents", sa.Column("owner_user_id", sa.String(36), nullable=True))
    _add_column(
        "agents",
        sa.Column("enrolled_by_token_id", sa.String(36), nullable=True),
    )
    _add_column("agents", sa.Column("ip_address", sa.String(64), nullable=True))
    _add_column(
        "agents", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True)
    )
    _create_index(
        "ix_agents_credential_fingerprint",
        "agents",
        ["credential_fingerprint"],
    )
    _create_index("ix_agents_owner_user_id", "agents", ["owner_user_id"])
    _create_index(
        "ix_agents_enrolled_by_token_id",
        "agents",
        ["enrolled_by_token_id"],
    )

    _add_column(
        "audit_events", sa.Column("actor_user_id", sa.String(36), nullable=True)
    )
    _add_column(
        "audit_events",
        sa.Column("enrollment_token_id", sa.String(36), nullable=True),
    )
    _add_column(
        "audit_events", sa.Column("organization_id", sa.String(36), nullable=True)
    )
    _add_column("audit_events", sa.Column("source_ip", sa.String(64), nullable=True))
    _add_column(
        "audit_events", sa.Column("user_agent", sa.String(500), nullable=True)
    )
    _create_index(
        "ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"]
    )
    _create_index(
        "ix_audit_events_enrollment_token_id",
        "audit_events",
        ["enrollment_token_id"],
    )
    _create_index(
        "ix_audit_events_organization_id",
        "audit_events",
        ["organization_id"],
    )

    envelope_added = _add_column(
        "agents",
        sa.Column(
            "command_envelope_versions",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    command_envelope_added = _add_column(
        "commands",
        sa.Column(
            "envelope_version",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'legacy-unversioned'"),
        ),
    )
    if envelope_added or command_envelope_added:
        op.execute("UPDATE commands SET status = 'expired' WHERE status = 'queued'")

    _add_column("commands", sa.Column("schema_version", sa.Integer(), nullable=True))
    _add_column(
        "commands",
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column("commands", sa.Column("nonce", sa.String(64), nullable=True))
    _create_index(
        "ux_commands_agent_nonce",
        "commands",
        ["agent_id", "nonce"],
        unique=True,
    )
    _add_column(
        "commands", sa.Column("signing_key_id", sa.String(64), nullable=True)
    )

    if "trust_state" not in _columns("agents"):
        trust_enum = sa.Enum(
            "active", "quarantined", "revoked", name="agenttruststate"
        )
        trust_enum.create(bind, checkfirst=True)
        op.add_column(
            "agents",
            sa.Column(
                "trust_state",
                trust_enum,
                nullable=False,
                server_default=sa.text("'active'"),
            ),
        )
    _add_column("agents", sa.Column("trust_state_reason", sa.Text(), nullable=True))
    _add_column(
        "agents",
        sa.Column(
            "trust_state_changed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    _add_column(
        "agents",
        sa.Column("trust_state_changed_by", sa.String(320), nullable=True),
    )

    _add_column(
        "commands", sa.Column("stdout_truncated", sa.Boolean(), nullable=True)
    )
    _add_column(
        "commands", sa.Column("stderr_truncated", sa.Boolean(), nullable=True)
    )
    _add_column(
        "commands", sa.Column("stdout_total_bytes", sa.BigInteger(), nullable=True)
    )
    _add_column(
        "commands", sa.Column("stderr_total_bytes", sa.BigInteger(), nullable=True)
    )

    audit_seq_added = _add_column(
        "audit_events", sa.Column("seq", sa.BigInteger(), nullable=True)
    )
    hash_schema_added = _add_column(
        "audit_events",
        sa.Column(
            "hash_schema",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
        ),
    )
    if audit_seq_added:
        op.execute(
            """
            UPDATE audit_events SET
                seq = (
                    SELECT rn FROM (
                        SELECT id, ROW_NUMBER() OVER (ORDER BY ts, id) AS rn
                        FROM audit_events
                    ) ordered WHERE ordered.id = audit_events.id
                ),
                hash_schema = 1
            """
        )
    elif hash_schema_added:
        op.execute("UPDATE audit_events SET hash_schema = 1")
    _create_index(
        "ux_audit_events_seq",
        "audit_events",
        ["seq"],
        unique=True,
    )

    if "anchor_publications" not in tables:
        op.create_table(
            "anchor_publications",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "anchor_id",
                sa.String(36),
                sa.ForeignKey("audit_anchors.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("backend", sa.String(32), nullable=False),
            sa.Column(
                "status",
                sa.String(16),
                nullable=False,
                server_default="pending",
            ),
            sa.Column("uri", sa.String(1024), nullable=True),
            sa.Column("receipt", sa.JSON(), nullable=True),
            sa.Column("receipt_sha256", sa.String(64), nullable=True),
            sa.Column(
                "attempts", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("last_error", sa.String(500), nullable=True),
            sa.Column(
                "created_at", sa.DateTime(timezone=True), nullable=True
            ),
            sa.Column(
                "published_at", sa.DateTime(timezone=True), nullable=True
            ),
            sa.UniqueConstraint(
                "anchor_id",
                "backend",
                name="ux_anchor_publication_backend",
            ),
        )
    _create_index(
        "ix_anchor_publications_anchor_id",
        "anchor_publications",
        ["anchor_id"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
