# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence vault and legal hold (issue #81).

Adds the ledger of signed evidence packages retained in immutable storage and
the scoped legal holds that suspend their deletion.

* ``evidence_vault_records`` is unique per (backend, package_id), which is what
  makes a store request idempotent: a retry finds the existing row instead of
  writing a second object or resetting retention. ``client_id`` intentionally
  has no foreign key, because evidence must outlive the tenant row.
* ``evidence_legal_holds`` carries a partial unique index on
  (client_id, scope_key) for active rows, so two concurrent requests cannot
  both place an active hold on the same scope. ``scope_key`` is the record id,
  or ``*`` for a tenant-wide hold (a NULL would compare distinct).

The application never deletes rows from either table: a disposed package keeps
its row as a ``deleted`` tombstone, and a released hold keeps who placed it,
why, and who released it.

Compatibility and rollout: both tables are new and no existing table changes,
so an older binary is unaffected and the revision is safe to apply ahead of the
build that uses it. The vault is inert until ``EVIDENCE_VAULT_BACKEND`` is set.

Rollback: forward-only. Stored objects live outside the database; rolling the
application back leaves them retained (Object Lock is enforced by storage).
Crossing back below this revision requires the exact-revision restore
procedure in docs/ROLLBACK.md.

Revision ID: 0047
Revises: 0046
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_vault_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("client_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("package_id", sa.String(length=64), nullable=False),
        sa.Column("bundle_id", sa.String(length=64), nullable=False),
        sa.Column("from_seq", sa.Integer(), nullable=False),
        sa.Column("through_seq", sa.Integer(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("signing_key_id", sa.String(length=128), nullable=False),
        sa.Column("backend", sa.String(length=32), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("uri", sa.String(length=1024), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("storage_receipt", sa.JSON(), nullable=False),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=False),
        sa.Column("retention_mode", sa.String(length=16), nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("backend_legal_hold", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("integrity_state", sa.String(length=16), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verify_error", sa.String(length=500), nullable=True),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stored_by_operator_id", sa.String(length=36), nullable=True),
        sa.Column("stored_by_email", sa.String(length=320), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_email", sa.String(length=320), nullable=True),
        sa.UniqueConstraint("backend", "package_id", name="ux_evidence_vault_backend_package"),
    )
    op.create_index(
        "ix_evidence_vault_client_state", "evidence_vault_records", ["client_id", "state"]
    )
    op.create_index(
        "ix_evidence_vault_verify_queue", "evidence_vault_records", ["state", "last_verified_at"]
    )

    op.create_table(
        "evidence_legal_holds",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("client_id", sa.String(length=36), nullable=False),
        sa.Column("record_id", sa.String(length=36), nullable=True),
        sa.Column("scope_key", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("placed_by_operator_id", sa.String(length=36), nullable=True),
        sa.Column("placed_by_email", sa.String(length=320), nullable=False),
        sa.Column("placed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_by_email", sa.String(length=320), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ux_evidence_legal_hold_active_scope",
        "evidence_legal_holds",
        ["client_id", "scope_key"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_evidence_legal_holds_client_status", "evidence_legal_holds", ["client_id", "status"]
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
