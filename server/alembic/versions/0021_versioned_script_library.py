# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable, reviewed, versioned script library.

Revision ID: 0021
Revises: 0020
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

LANGUAGE_VALUES = ("powershell", "shell")
REVIEW_VALUES = ("approved", "rejected")


def upgrade() -> None:
    bind = op.get_bind()
    language = postgresql.ENUM(*LANGUAGE_VALUES, name="scriptlanguage")
    review_state = postgresql.ENUM(*REVIEW_VALUES, name="scriptreviewstate")
    language.create(bind, checkfirst=True)
    review_state.create(bind, checkfirst=True)
    language = postgresql.ENUM(
        *LANGUAGE_VALUES, name="scriptlanguage", create_type=False
    )
    review_state = postgresql.ENUM(
        *REVIEW_VALUES, name="scriptreviewstate", create_type=False
    )
    op.create_table(
        "script_library_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("normalized_name", sa.String(200), nullable=False),
        sa.Column("latest_version", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("deprecated_at", sa.DateTime(timezone=True)),
        sa.Column("deprecated_by", sa.String(320)),
        sa.Column("last_deprecation_request_id", sa.String(64)),
        sa.Column("deprecation_reason_sha256", sa.String(64)),
        sa.Column("deprecation_reason_bytes", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "normalized_name", name="ux_script_library_normalized_name"
        ),
        sa.CheckConstraint(
            "latest_version >= 1", name="ck_script_library_latest_version"
        ),
        sa.CheckConstraint(
            "record_version >= 1", name="ck_script_library_record_version"
        ),
    )
    op.create_index(
        "ix_script_library_deprecated_created",
        "script_library_items",
        ["deprecated_at", "created_at"],
    )

    op.create_table(
        "script_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "script_id",
            sa.String(36),
            sa.ForeignKey("script_library_items.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("language", language, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("supported_platforms", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "script_id", "version", name="ux_script_version_number"
        ),
        sa.CheckConstraint("version >= 1", name="ck_script_version_number"),
        sa.CheckConstraint(
            "content_bytes BETWEEN 1 AND 57344",
            name="ck_script_version_content_bytes",
        ),
        sa.CheckConstraint(
            "length(content_sha256) = 64",
            name="ck_script_version_digest_length",
        ),
    )
    op.create_index(
        "ix_script_version_script_created",
        "script_versions",
        ["script_id", "created_at"],
    )

    op.create_table(
        "script_version_reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "script_version_id",
            sa.String(36),
            sa.ForeignKey("script_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", review_state, nullable=False),
        sa.Column("reviewed_by", sa.String(320), nullable=False),
        sa.Column("reason_sha256", sa.String(64), nullable=False),
        sa.Column("reason_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "script_version_id", name="ux_script_version_review_final"
        ),
        sa.CheckConstraint(
            "length(reason_sha256) = 64", name="ck_script_review_digest_length"
        ),
        sa.CheckConstraint(
            "reason_bytes BETWEEN 3 AND 2000", name="ck_script_review_reason_bytes"
        ),
    )
    op.create_index(
        "ix_script_review_created", "script_version_reviews", ["created_at"]
    )

    if bind.dialect.name == "postgresql":
        tables = (
            "script_library_items",
            "script_versions",
            "script_version_reviews",
        )
        for table in tables:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(
            """
            DO $$ DECLARE table_name text; BEGIN
              FOREACH table_name IN ARRAY ARRAY[
                'script_library_items', 'script_versions',
                'script_version_reviews'
              ] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                  EXECUTE format('REVOKE ALL ON TABLE %I FROM anon', table_name);
                END IF;
                IF EXISTS (
                  SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'
                ) THEN
                  EXECUTE format(
                    'REVOKE ALL ON TABLE %I FROM authenticated', table_name
                  );
                END IF;
              END LOOP;
            END $$
            """
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
