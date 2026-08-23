# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence storage: retained artifacts and legal holds.

Issue #81 (Milestone 3), phase 2. Purely additive — two new tables, no change to
any existing table and no data migration:

  * ``evidence_artifacts`` — one durably stored compliance export, bound to its
    exact bytes by ``content_sha256``, carrying the destination receipt and a
    ``retain_until`` frozen at creation so a later policy change cannot move it.
  * ``evidence_legal_holds`` — a named, reasoned suspension of deletion over one
    artifact, one tenant, or every tenant. Release is terminal; re-holding
    creates a new row.

Nothing writes to either table at this revision; the export path, hold API, and
retention sweeper land in later phases. A deployment that never retains an
export sees no behavior change, so this upgrade is a no-op in practice.

Deliberately no PostgreSQL enum: ``state`` and ``scope`` are short strings, like
``anchor_publications.status``. An enum here would add two more types that
cannot be dropped in place, making a future correction to a state name require
the exact-revision restore procedure rather than a forward fix.

Compatibility: additive and forward-only (docs/ROLLBACK.md). Crossing back below
this revision drops the tables, and with them the record of which evidence was
stored — the objects themselves survive at the destination under their own
Object Lock and must be reconciled by hand.

Revision ID: 0038
Revises: 0037
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_id", sa.String(64), nullable=False),
        sa.Column("bundle_id", sa.String(64), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column("from_seq", sa.Integer(), nullable=False),
        sa.Column("through_seq", sa.Integer(), nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=True),
        sa.Column("backend", sa.String(32), nullable=False),
        sa.Column("uri", sa.String(1024), nullable=True),
        sa.Column("receipt", sa.JSON(), nullable=True),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column(
            "state", sa.String(16), nullable=False, server_default="pending"
        ),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        # Re-retaining the same export reconciles onto one row instead of
        # forking a second record of identical bytes.
        sa.UniqueConstraint(
            "tenant_id", "package_id", name="uq_evidence_artifact_package"
        ),
    )
    # The retention sweeper selects on exactly this pair.
    op.create_index(
        "ix_evidence_artifacts_state_retain",
        "evidence_artifacts",
        ["state", "retain_until"],
    )
    op.create_index(
        "ix_evidence_artifacts_tenant",
        "evidence_artifacts",
        ["tenant_id", "created_at"],
    )

    op.create_table(
        "evidence_legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        # artifact | tenant | global; scope_id is NULL for a global hold.
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        # Mandatory for a global hold, optional otherwise — enforced at the API
        # boundary, where the refusal can name a reason.
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by", sa.String(320), nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_evidence_legal_holds_scope",
        "evidence_legal_holds",
        ["scope", "scope_id"],
    )
    # Coverage resolution reads active holds: not released, not expired.
    op.create_index(
        "ix_evidence_legal_holds_active",
        "evidence_legal_holds",
        ["released_at", "expires_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
