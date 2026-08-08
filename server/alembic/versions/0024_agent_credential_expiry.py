# SPDX-License-Identifier: AGPL-3.0-only
"""Expiring agent credentials with loss-safe rotation overlap (issue #125).

Adds the columns that turn the per-agent bearer into a short-lived, renewable
credential: a bounded rotation-overlap slot (previous_token_hash /
previous_token_expires_at) so a dropped renewal response never strands an
endpoint, a monotonic rotation counter, the last rotation nonce for replay
rejection, and a last-renewed timestamp.

All columns are nullable or defaulted, so no backfill is required. Existing
agents keep working: a NULL credential_expires_at continues to mean "no
enforced expiry" until the server begins issuing finite lifetimes, and a NULL
previous_token_hash simply means "no credential is in its overlap window".

Revision ID: 0024
Revises: 0023
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as batch:
        batch.add_column(sa.Column("previous_token_hash", sa.String(64)))
        batch.add_column(
            sa.Column("previous_token_expires_at", sa.DateTime(timezone=True))
        )
        batch.add_column(
            sa.Column(
                "credential_generation",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.add_column(sa.Column("last_rotation_nonce", sa.String(64)))
        batch.add_column(sa.Column("last_renewed_at", sa.DateTime(timezone=True)))
        batch.create_index("ix_agents_previous_token_hash", ["previous_token_hash"])


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
