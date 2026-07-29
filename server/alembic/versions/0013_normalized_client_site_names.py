# SPDX-License-Identifier: AGPL-3.0-only
"""Enforce normalized client and site name uniqueness.

Revision ID: 0013
Revises: 0012

The first-run onboarding UI treats client names as deployment-wide identities
and site names as identities within a client. Refuse ambiguous existing data
instead of silently renaming customer records, then enforce the same
case-insensitive, surrounding-whitespace-insensitive rule used by the API.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _duplicate_count(sql: str) -> int:
    return len(op.get_bind().execute(sa.text(sql)).all())


def upgrade() -> None:
    duplicate_clients = _duplicate_count(
        """
        SELECT lower(trim(name))
        FROM clients
        GROUP BY lower(trim(name))
        HAVING count(*) > 1
        """
    )
    duplicate_sites = _duplicate_count(
        """
        SELECT client_id, lower(trim(name))
        FROM sites
        GROUP BY client_id, lower(trim(name))
        HAVING count(*) > 1
        """
    )
    if duplicate_clients or duplicate_sites:
        raise RuntimeError(
            "Cannot enforce normalized client/site names: "
            f"{duplicate_clients} duplicate client group(s), "
            f"{duplicate_sites} duplicate site group(s). "
            "Resolve the ambiguous names and rerun the migration."
        )

    op.create_index(
        "ux_clients_name_normalized",
        "clients",
        [sa.text("lower(trim(name))")],
        unique=True,
    )
    op.create_index(
        "ux_sites_client_name_normalized",
        "sites",
        ["client_id", sa.text("lower(trim(name))")],
        unique=True,
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
