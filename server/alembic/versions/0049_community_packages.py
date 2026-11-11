# SPDX-License-Identifier: AGPL-3.0-only
"""Moderated community script repository (issue #74).

Adds the publisher/key/package/version/moderation/install registry for signed
community script packages:

* ``community_publishers`` owns a namespace slug; ``community_publisher_keys``
  holds only the *public* half of each Ed25519 package-signing key, bound to
  one publisher forever (unique fingerprint), with terminal revocation.
* ``community_packages`` is the stable ``publisher/name`` identity and
  ``community_package_versions`` the append-only signed manifest + content.
* ``community_package_moderations`` is the final, one-per-version decision.
* ``community_installs`` binds one local library script to one package.
* ``script_versions.community_package_version_id`` records provenance so
  dispatch can re-check trust state on every run.

Statuses are application-validated short strings with CHECK constraints, not
database ENUM types, so no PostgreSQL type is created here.

Compatibility and rollout: every change is additive. The new tables start
empty and the nullable column is never read by an older application binary,
so the schema is safe to apply ahead of the build that uses it and safe to
leave applied if that build is rolled back. No agent change is required; the
signed command envelope is unchanged.

Rollback: migrations here are forward-only. Backing the capability out is an
operational change (revoke publishers / versions, which blocks dispatch), not a
schema change. Crossing back below this revision requires the exact-revision
restore procedure in docs/ROLLBACK.md.

Revision ID: 0049
Revises: 0048
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def _revocation_columns() -> list[sa.Column]:
    return [
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=320), nullable=True),
        sa.Column("revocation_reason_sha256", sa.String(length=64), nullable=True),
        sa.Column("revocation_reason_bytes", sa.Integer(), nullable=True),
    ]


def upgrade() -> None:
    op.create_table(
        "community_publishers",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revocation_request_id", sa.String(length=64), nullable=True),
        *_revocation_columns(),
        sa.UniqueConstraint("slug", name="ux_community_publisher_slug"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_community_publisher_status"
        ),
    )

    op.create_table(
        "community_publisher_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "publisher_id",
            sa.String(length=36),
            sa.ForeignKey("community_publishers.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        *_revocation_columns(),
        sa.UniqueConstraint("publisher_id", "key_id", name="ux_community_key_id"),
        sa.UniqueConstraint("fingerprint", name="ux_community_key_fingerprint"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_community_key_status"
        ),
    )

    op.create_table(
        "community_packages",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "publisher_id",
            sa.String(length=36),
            sa.ForeignKey("community_publishers.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("publisher_id", "name", name="ux_community_package_name"),
    )

    op.create_table(
        "community_package_versions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "package_id",
            sa.String(length=36),
            sa.ForeignKey("community_packages.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("major", sa.Integer(), nullable=False),
        sa.Column("minor", sa.Integer(), nullable=False),
        sa.Column("patch", sa.Integer(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column(
            "signing_key_id",
            sa.String(length=36),
            sa.ForeignKey("community_publisher_keys.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("submitted_by", sa.String(length=320), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        *_revocation_columns(),
        sa.UniqueConstraint("package_id", "version", name="ux_community_version"),
        sa.CheckConstraint(
            "length(content_sha256) = 64", name="ck_community_version_digest"
        ),
        sa.CheckConstraint(
            "content_bytes BETWEEN 1 AND 57344", name="ck_community_version_bytes"
        ),
    )
    op.create_index(
        "ix_community_version_order",
        "community_package_versions",
        ["package_id", "major", "minor", "patch"],
    )

    op.create_table(
        "community_package_moderations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "package_version_id",
            sa.String(length=36),
            sa.ForeignKey("community_package_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("moderated_by", sa.String(length=320), nullable=False),
        sa.Column("reason_sha256", sa.String(length=64), nullable=False),
        sa.Column("reason_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "acknowledged_capability_escalation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "package_version_id", name="ux_community_moderation_final"
        ),
        sa.CheckConstraint(
            "state IN ('approved', 'rejected')", name="ck_community_moderation_state"
        ),
    )

    op.create_table(
        "community_installs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "package_id",
            sa.String(length=36),
            sa.ForeignKey("community_packages.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "script_id",
            sa.String(length=36),
            sa.ForeignKey("script_library_items.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "package_version_id",
            sa.String(length=36),
            sa.ForeignKey("community_package_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.Column("installed_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("script_id", name="ux_community_install_script"),
        sa.UniqueConstraint("package_id", name="ux_community_install_package"),
        sa.UniqueConstraint("request_id", name="ux_community_install_request"),
    )

    with op.batch_alter_table("script_versions") as batch:
        batch.add_column(
            sa.Column(
                "community_package_version_id", sa.String(length=36), nullable=True
            )
        )
        batch.create_foreign_key(
            "fk_script_versions_community_package_version",
            "community_package_versions",
            ["community_package_version_id"],
            ["id"],
            ondelete="RESTRICT",
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
