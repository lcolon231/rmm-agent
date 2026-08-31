# SPDX-License-Identifier: AGPL-3.0-only
"""Phishing-resistant WebAuthn MFA with audited recovery (issue #67).

Adds the registered-authenticator table, the single-use challenge table that
carries replay protection, the hashed recovery-code table, and one nullable
``operators`` column recording when a recovery batch was last generated.

Compatibility and rollout: every change is additive and every new column is
nullable or defaulted, so an older application binary running against this
schema simply never reads the new tables and keeps issuing password-only
sessions. That is what makes the staged activation in docs/MFA.md safe — the
schema can be migrated well ahead of turning ``MFA_ENFORCEMENT`` up, and a
mixed-version fleet degrades to "MFA unavailable", never to "MFA bypassed",
because enforcement is decided by the server that owns the login endpoint.

Rollback: migrations here are forward-only. Backing out MFA is a configuration
change (``MFA_ENFORCEMENT=off``), not a schema change; crossing back below this
revision requires the exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0038
Revises: 0037
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


# Matches what SQLAlchemy derives from the WebAuthnChallengePurpose ORM enum, so
# the migrated schema and the ORM agree on PostgreSQL.
CHALLENGE_PURPOSE_VALUES = ("registration", "authentication", "step_up")


def upgrade() -> None:
    bind = op.get_bind()

    # Create the enum type once, explicitly and idempotently, then reference it
    # from create_table with create_type=False. Emitting CREATE TYPE a second
    # time from create_table fails outright on PostgreSQL (pattern from 0016).
    purpose_type = postgresql.ENUM(
        *CHALLENGE_PURPOSE_VALUES, name="webauthnchallengepurpose"
    )
    purpose_type.create(bind, checkfirst=True)

    op.add_column(
        "operators",
        sa.Column(
            "mfa_recovery_codes_generated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # base64url of the raw credential ID (up to 1023 bytes -> 1364 chars).
        # Globally unique: one authenticator must never resolve to two
        # identities, which is an authentication-correctness property, not just
        # a hygiene constraint.
        sa.Column("credential_id", sa.String(1400), nullable=False),
        sa.Column("public_key_cose", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.Integer(), nullable=False),
        # 32-bit unsigned counter; BigInteger avoids the signed-Integer ceiling.
        sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("aaguid", sa.String(36), nullable=False, server_default=""),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("transports", sa.String(120), nullable=True),
        sa.Column(
            "attestation_format", sa.String(32), nullable=False, server_default="none"
        ),
        sa.Column(
            "backup_eligible", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "backup_state", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(64), nullable=True),
        sa.UniqueConstraint("credential_id", name="uq_webauthn_credential_id"),
    )
    op.create_index(
        "ix_webauthn_credentials_operator_id", "webauthn_credentials", ["operator_id"]
    )
    op.create_index(
        "ix_webauthn_credentials_credential_id",
        "webauthn_credentials",
        ["credential_id"],
    )
    # The hot path is "active credentials for this operator", evaluated on every
    # login of an enrolled operator.
    op.create_index(
        "ix_webauthn_credentials_operator_active",
        "webauthn_credentials",
        ["operator_id", "revoked_at"],
    )

    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "purpose",
            postgresql.ENUM(
                *CHALLENGE_PURPOSE_VALUES,
                name="webauthnchallengepurpose",
                create_type=False,
            ),
            nullable=False,
        ),
        # Unique so a collision is a database error rather than an ambiguous
        # lookup that could consume the wrong operator's challenge.
        sa.Column("challenge", sa.String(64), nullable=False),
        sa.Column("rp_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("challenge", name="uq_webauthn_challenge_value"),
    )
    op.create_index(
        "ix_webauthn_challenges_operator_id", "webauthn_challenges", ["operator_id"]
    )
    op.create_index(
        "ix_webauthn_challenges_operator_purpose",
        "webauthn_challenges",
        ["operator_id", "purpose"],
    )
    # Supports the bounded sweep that deletes expired challenges.
    op.create_index(
        "ix_webauthn_challenges_expires_at", "webauthn_challenges", ["expires_at"]
    )

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("batch_id", sa.String(36), nullable=False),
        # bcrypt digest, not the code. Column is sized for a bcrypt hash.
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_mfa_recovery_codes_operator_id", "mfa_recovery_codes", ["operator_id"]
    )
    op.create_index(
        "ix_mfa_recovery_codes_operator_used",
        "mfa_recovery_codes",
        ["operator_id", "used_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
