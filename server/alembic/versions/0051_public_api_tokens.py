# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned public API: tenant-scoped API tokens and idempotency keys (#72).

* ``api_tokens`` holds opaque, tenant-scoped bearer credentials for the public
  v1 surface. Only the SHA-256 of the token is stored; the plaintext is shown
  once at creation. Each token is bound to exactly one owning operator and one
  client (tenant), carries role ceilings that can only narrow the owner's
  authority, snapshots the owner's ``token_generation`` (so logout-all and
  membership changes kill it), and has a mandatory expiry.
* ``api_idempotency_keys`` records client ``Idempotency-Key`` reservations and
  the stored response for replay, unique per principal and key.

Roles are application-validated short strings with CHECK constraints, not
database ENUM types, so no PostgreSQL type is created here.

Compatibility and rollout: every change is additive. Both tables start empty
and are never read by an older application binary, so the schema is safe to
apply ahead of the build that uses it and safe to leave applied if that build
is rolled back. The dashboard keeps using operator JWTs; no agent change.

Rollback: migrations here are forward-only. Backing the capability out is an
operational change (revoke tokens), not a schema change. Crossing back below
this revision requires the exact-revision restore procedure in
docs/ROLLBACK.md.

Revision ID: 0051
Revises: 0050
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(length=36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "client_id",
            sa.String(length=36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("role_ceiling", sa.String(length=16), nullable=False),
        sa.Column("client_role_ceiling", sa.String(length=24), nullable=False),
        sa.Column("operator_token_generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=320), nullable=True),
        sa.UniqueConstraint("token_hash", name="ux_api_token_hash"),
        sa.CheckConstraint(
            "role_ceiling IN ('readonly', 'operator', 'admin')",
            name="ck_api_token_role_ceiling",
        ),
        sa.CheckConstraint(
            "client_role_ceiling IN "
            "('client_readonly', 'client_operator', 'client_admin')",
            name="ck_api_token_client_role_ceiling",
        ),
    )
    op.create_index("ix_api_tokens_operator", "api_tokens", ["operator_id"])
    op.create_index("ix_api_tokens_client", "api_tokens", ["client_id"])

    op.create_table(
        "api_idempotency_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("principal", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("route", sa.String(length=255), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "principal", "idempotency_key", name="ux_api_idempotency_principal_key"
        ),
    )
    op.create_index(
        "ix_api_idempotency_keys_expires", "api_idempotency_keys", ["expires_at"]
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
