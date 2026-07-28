# SPDX-License-Identifier: AGPL-3.0-only
"""Add complete enrollment-token and agent enrollment metadata.

Revision ID: 0011
Revises: 0010

The migration is additive and preserves existing agents and tokens. Legacy
tokens are intentionally left with a NULL expires_at; the new service treats
that state as expired so an old indefinitely-valid enrollment secret cannot
remain usable after upgrade.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enrollment_tokens") as batch:
        batch.add_column(sa.Column("token_prefix", sa.String(12), nullable=False, server_default=""))
        batch.add_column(sa.Column("name", sa.String(200), nullable=False, server_default="Enrollment token"))
        batch.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch.add_column(sa.Column("assigned_user_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("environment", sa.String(100), nullable=True))
        batch.add_column(sa.Column("hostname_restriction", sa.String(255), nullable=True))
        batch.add_column(sa.Column("agent_name_restriction", sa.String(255), nullable=True))
        batch.add_column(sa.Column("labels", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("created_by_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("revoked_by_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("notes", sa.Text(), nullable=True))
        batch.create_foreign_key(
            "fk_enrollment_tokens_assigned_user",
            "operators",
            ["assigned_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_enrollment_tokens_created_by",
            "operators",
            ["created_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_enrollment_tokens_revoked_by",
            "operators",
            ["revoked_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_enrollment_tokens_assigned_user_id", ["assigned_user_id"])
        batch.create_index("ix_enrollment_tokens_created_by_id", ["created_by_id"])
        batch.create_index("ix_enrollment_tokens_revoked_by_id", ["revoked_by_id"])

    # Preserve a useful name for legacy records without exposing their digest.
    op.execute(
        "UPDATE enrollment_tokens SET name = "
        "CASE WHEN label IS NOT NULL AND label <> '' THEN label ELSE 'Legacy enrollment token' END"
    )

    with op.batch_alter_table("agents") as batch:
        batch.add_column(sa.Column("credential_fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("credential_issued_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("credential_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("name", sa.String(255), nullable=False, server_default=""))
        batch.add_column(sa.Column("architecture", sa.String(100), nullable=False, server_default=""))
        batch.add_column(sa.Column("environment", sa.String(100), nullable=True))
        batch.add_column(sa.Column("labels", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("owner_user_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("enrolled_by_token_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("ip_address", sa.String(64), nullable=True))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_foreign_key(
            "fk_agents_owner_user",
            "operators",
            ["owner_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_agents_enrollment_token",
            "enrollment_tokens",
            ["enrolled_by_token_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_agents_credential_fingerprint", ["credential_fingerprint"])
        batch.create_index("ix_agents_owner_user_id", ["owner_user_id"])
        batch.create_index("ix_agents_enrolled_by_token_id", ["enrolled_by_token_id"])

    with op.batch_alter_table("audit_events") as batch:
        batch.add_column(sa.Column("actor_user_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("enrollment_token_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("organization_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("source_ip", sa.String(64), nullable=True))
        batch.add_column(sa.Column("user_agent", sa.String(500), nullable=True))
        batch.create_index("ix_audit_events_actor_user_id", ["actor_user_id"])
        batch.create_index("ix_audit_events_enrollment_token_id", ["enrollment_token_id"])
        batch.create_index("ix_audit_events_organization_id", ["organization_id"])


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
