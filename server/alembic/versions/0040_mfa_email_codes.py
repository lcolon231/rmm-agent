# SPDX-License-Identifier: AGPL-3.0-only
"""Email one-time-code second factor (issue #226).

Adds the per-operator email factor and the issued-code table behind it.

Two storage decisions are worth stating, because they are what the security
properties rest on:

* Codes are stored as bcrypt digests, never in plaintext, and the column is
  sized for a bcrypt hash. Nothing in this schema can reveal a live code.
* Code rows are *consumed*, not deleted. ``consumed_at`` and ``superseded_at``
  are separate so a reviewer can tell a replay of a spent code apart from a
  presentation of a code that was invalidated by reissue -- deleting rows would
  flatten both into "no such code" and destroy the replay signal the audit
  trail is supposed to carry.

Compatibility and rollout: every change is additive and creates only new
tables, so an older application binary running against this schema never reads
them and behaves exactly as before. The capability is additionally gated by
``MFA_EMAIL_CODE_POLICY``, which defaults to ``off``; migrating the schema does
not enable the factor, and enabling it is a separate, reversible configuration
step. That is what makes this safe to apply ahead of the build that uses it.

Rollback: migrations here are forward-only. Backing the capability out is a
configuration change (``MFA_EMAIL_CODE_POLICY=off``), not a schema change --
which leaves already-verified factors on disk, inert, and ready if the policy is
turned back on. Crossing back below this revision requires the exact-revision
restore procedure in docs/ROLLBACK.md.

Revision ID: 0040
Revises: 0039
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

# Mirrors app.models.models.MfaEmailCodePurpose.
EMAIL_CODE_PURPOSE_VALUES = ("enrollment", "login")


def upgrade() -> None:
    bind = op.get_bind()

    # Create the enum type once, explicitly and idempotently, then reference it
    # from create_table with create_type=False. Emitting CREATE TYPE a second
    # time from create_table fails outright on PostgreSQL (pattern from 0016).
    purpose_type = postgresql.ENUM(
        *EMAIL_CODE_PURPOSE_VALUES, name="mfaemailcodepurpose"
    )
    purpose_type.create(bind, checkfirst=True)

    op.create_table(
        "mfa_email_factors",
        sa.Column("id", sa.String(36), primary_key=True),
        # Unique: an operator has at most one email factor. Two would mean two
        # mailboxes could each complete a login, which is a wider trust
        # boundary than the feature is scoped to.
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        # Snapshot of the operator's login address at verification time. Not a
        # freely chosen destination: it is compared against the operator's
        # current email on every use, so an address change invalidates the
        # factor instead of silently authorizing an unverified mailbox.
        sa.Column("address", sa.String(320), nullable=False),
        # NULL means enrolment in progress. Only a non-NULL value is a factor.
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_mfa_email_factors_operator_id", "mfa_email_factors", ["operator_id"]
    )

    op.create_table(
        "mfa_email_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Bound into the row so a code mailed to prove control of an address
        # cannot be replayed against the login endpoint, or the reverse.
        sa.Column(
            "purpose",
            postgresql.ENUM(
                *EMAIL_CODE_PURPOSE_VALUES,
                name="mfaemailcodepurpose",
                create_type=False,
            ),
            nullable=False,
        ),
        # bcrypt digest, not the code. Column is sized for a bcrypt hash.
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("address", sa.String(320), nullable=False),
        # What makes a six-digit code defensible: the code burns after this many
        # wrong guesses, long before its 10^6 space is meaningfully explored.
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_mfa_email_codes_operator_id", "mfa_email_codes", ["operator_id"]
    )
    op.create_index(
        "ix_mfa_email_codes_operator_live",
        "mfa_email_codes",
        ["operator_id", "consumed_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
