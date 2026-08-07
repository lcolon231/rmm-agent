# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable typed script parameters and encrypted per-run values.

Revision ID: 0022
Revises: 0021
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

PARAMETER_KIND_VALUES = ("string", "number", "boolean", "choice", "secret")


def upgrade() -> None:
    bind = op.get_bind()
    parameter_kind = postgresql.ENUM(
        *PARAMETER_KIND_VALUES, name="scriptparameterkind"
    )
    parameter_kind.create(bind, checkfirst=True)
    parameter_kind = postgresql.ENUM(
        *PARAMETER_KIND_VALUES,
        name="scriptparameterkind",
        create_type=False,
    )

    op.create_table(
        "script_parameter_definitions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "script_version_id",
            sa.String(36),
            sa.ForeignKey("script_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500)),
        sa.Column("kind", parameter_kind, nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("has_default", sa.Boolean(), nullable=False),
        sa.Column("default_value", sa.JSON()),
        sa.Column("min_length", sa.Integer()),
        sa.Column("max_length", sa.Integer()),
        sa.Column("minimum", sa.Float()),
        sa.Column("maximum", sa.Float()),
        sa.Column("choices", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "script_version_id", "position", name="ux_script_parameter_position"
        ),
        sa.UniqueConstraint(
            "script_version_id", "key", name="ux_script_parameter_key"
        ),
        sa.CheckConstraint("position >= 0", name="ck_script_parameter_position"),
        sa.CheckConstraint(
            "min_length IS NULL OR min_length >= 0",
            name="ck_script_parameter_min_length",
        ),
        sa.CheckConstraint(
            "max_length IS NULL OR max_length >= 1",
            name="ck_script_parameter_max_length",
        ),
    )
    op.create_index(
        "ix_script_parameter_version",
        "script_parameter_definitions",
        ["script_version_id", "position"],
    )

    op.create_table(
        "script_parameter_value_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "script_version_id",
            sa.String(36),
            sa.ForeignKey("script_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("encrypted_values", sa.Text(), nullable=False),
        sa.Column("values_fingerprint", sa.String(64), nullable=False),
        sa.Column("provided_keys", sa.JSON(), nullable=False),
        sa.Column("defaulted_keys", sa.JSON(), nullable=False),
        sa.Column("secret_keys", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "script_version_id",
            "request_id",
            name="ux_script_parameter_set_request",
        ),
        sa.CheckConstraint(
            "length(values_fingerprint) = 64",
            name="ck_script_parameter_set_fingerprint",
        ),
    )
    op.create_index(
        "ix_script_parameter_set_version_created",
        "script_parameter_value_sets",
        ["script_version_id", "created_at"],
    )
    op.create_index(
        "ix_script_parameter_set_expiry",
        "script_parameter_value_sets",
        ["expires_at"],
    )

    if bind.dialect.name == "postgresql":
        tables = (
            "script_parameter_definitions",
            "script_parameter_value_sets",
        )
        for table in tables:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(
            """
            DO $$ DECLARE table_name text; BEGIN
              FOREACH table_name IN ARRAY ARRAY[
                'script_parameter_definitions',
                'script_parameter_value_sets'
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
