# SPDX-License-Identifier: AGPL-3.0-only
"""Add controlled file and registry remediation command kinds (issue #59).

Only the PostgreSQL enum changes. Command payloads and rollback metadata are
stored in existing bounded JSON/text columns, so no table or backfill is
required. This migration is forward-only, matching the repository policy.

Revision ID: 0030
Revises: 0029
"""
from alembic import op


revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in (
            "file_upload",
            "file_download",
            "registry_read",
            "registry_write",
            "registry_delete",
            "remediation_rollback",
        ):
            op.execute(f"ALTER TYPE commandkind ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
