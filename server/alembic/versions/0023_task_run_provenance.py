# SPDX-License-Identifier: AGPL-3.0-only
"""Task-run provenance and lineage on commands (issue #50).

Adds run provenance to the commands table so the complete task-run history can
answer "who ran what, from where, and where does it sit in the audit chain"
from the run row itself, not only the tamper-evident audit log. Also lands
nullable/defaulted lifecycle+lineage columns (planned_at, attempt,
parent_command_id) that recurring scheduling (#49) and retry work will populate
later, so those features need no further schema change.

All columns are nullable (or defaulted), so no backfill is required: NULL means
"not recorded" (historic rows, or ad-hoc commands with no library origin),
never a positive claim.

Revision ID: 0023
Revises: 0022
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("commands") as batch:
        batch.add_column(sa.Column("actor_email", sa.String(320)))
        batch.add_column(sa.Column("actor_operator_id", sa.String(36)))
        batch.add_column(sa.Column("script_version_id", sa.String(36)))
        batch.add_column(
            sa.Column("script_parameter_value_set_id", sa.String(36))
        )
        batch.add_column(sa.Column("dispatch_audit_event_id", sa.String(36)))
        batch.add_column(sa.Column("planned_at", sa.DateTime(timezone=True)))
        batch.add_column(
            sa.Column(
                "attempt", sa.Integer(), nullable=False, server_default="1"
            )
        )
        batch.add_column(sa.Column("parent_command_id", sa.String(36)))
        batch.create_foreign_key(
            "fk_commands_actor_operator", "operators",
            ["actor_operator_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_commands_script_version", "script_versions",
            ["script_version_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_commands_script_parameter_value_set",
            "script_parameter_value_sets",
            ["script_parameter_value_set_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_commands_dispatch_audit_event", "audit_events",
            ["dispatch_audit_event_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_commands_parent_command", "commands",
            ["parent_command_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_index("ix_commands_actor_operator_id", ["actor_operator_id"])
        batch.create_index("ix_commands_script_version_id", ["script_version_id"])
        batch.create_index("ix_commands_created_at", ["created_at"])


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
