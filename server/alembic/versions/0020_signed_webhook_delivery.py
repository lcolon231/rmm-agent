# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned signed webhook endpoints, secrets, and delivery history.

Revision ID: 0020
Revises: 0019
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

DELIVERY_VALUES = (
    "pending", "sending", "retrying", "delivered", "failed", "suppressed",
)
ATTEMPT_VALUES = ("sending", "delivered", "retrying", "failed")
EVENT_VALUES = (
    "state_imported", "opened", "reopened", "acknowledged", "assigned",
    "commented", "manual_resolution", "automatic_recovery", "policy_revised",
    "policy_deleted", "policy_superseded",
)


def upgrade() -> None:
    bind = op.get_bind()
    delivery_status = postgresql.ENUM(
        *DELIVERY_VALUES, name="webhookdeliverystatus"
    )
    attempt_status = postgresql.ENUM(
        *ATTEMPT_VALUES, name="webhookattemptstatus"
    )
    delivery_status.create(bind, checkfirst=True)
    attempt_status.create(bind, checkfirst=True)
    delivery_status = postgresql.ENUM(
        *DELIVERY_VALUES, name="webhookdeliverystatus", create_type=False
    )
    attempt_status = postgresql.ENUM(
        *ATTEMPT_VALUES, name="webhookattemptstatus", create_type=False
    )
    event_type = postgresql.ENUM(
        *EVENT_VALUES, name="alerteventtype", create_type=False
    )

    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("current_secret_version", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("updated_by", sa.String(320), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="ux_webhook_endpoint_name"),
        sa.CheckConstraint(
            "current_secret_version >= 1", name="ck_webhook_endpoint_secret_version"
        ),
        sa.CheckConstraint("version >= 1", name="ck_webhook_endpoint_version"),
    )
    op.create_index(
        "ix_webhook_endpoint_enabled", "webhook_endpoints",
        ["enabled", "deleted_at"],
    )

    op.create_table(
        "webhook_secret_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "endpoint_id", sa.String(36),
            sa.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "endpoint_id", "version", name="ux_webhook_secret_endpoint_version"
        ),
        sa.CheckConstraint("version >= 1", name="ck_webhook_secret_version"),
    )
    op.create_index(
        "ix_webhook_secret_endpoint", "webhook_secret_versions",
        ["endpoint_id", "created_at"],
    )

    op.create_table(
        "alert_webhook_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "endpoint_id", sa.String(36),
            sa.ForeignKey("webhook_endpoints.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "secret_version_id", sa.String(36),
            sa.ForeignKey("webhook_secret_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "alert_id", sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "alert_event_id", sa.String(36),
            sa.ForeignKey("alert_events.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("event_type", event_type, nullable=False),
        sa.Column("destination_url", sa.String(2048), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("signature_timestamp", sa.BigInteger(), nullable=False),
        sa.Column("status", delivery_status, nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("last_http_status", sa.Integer()),
        sa.Column("last_error_code", sa.String(100)),
        sa.Column("last_retry_request_id", sa.String(64)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "alert_event_id", "endpoint_id",
            name="ux_alert_webhook_event_endpoint",
        ),
        sa.CheckConstraint("generation >= 0", name="ck_alert_webhook_generation"),
        sa.CheckConstraint(
            "attempt_count >= 0", name="ck_alert_webhook_attempt_count"
        ),
        sa.CheckConstraint(
            "max_attempts BETWEEN 1 AND 20", name="ck_alert_webhook_max_attempts"
        ),
        sa.CheckConstraint(
            "last_http_status IS NULL OR last_http_status BETWEEN 100 AND 599",
            name="ck_alert_webhook_http_status",
        ),
    )
    op.create_index(
        "ix_alert_webhook_due", "alert_webhook_deliveries",
        ["status", "next_attempt_at", "created_at"],
    )
    op.create_index(
        "ix_alert_webhook_alert_created", "alert_webhook_deliveries",
        ["alert_id", "created_at"],
    )
    op.create_index(
        "ix_alert_webhook_endpoint_created", "alert_webhook_deliveries",
        ["endpoint_id", "created_at"],
    )

    op.create_table(
        "alert_webhook_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "delivery_id", sa.String(36),
            sa.ForeignKey("alert_webhook_deliveries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("status", attempt_status, nullable=False),
        sa.Column("http_status", sa.Integer()),
        sa.Column("error_code", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "delivery_id", "attempt_number",
            name="ux_alert_webhook_attempt_number",
        ),
        sa.CheckConstraint(
            "attempt_number >= 1", name="ck_alert_webhook_attempt_number"
        ),
        sa.CheckConstraint(
            "http_status IS NULL OR http_status BETWEEN 100 AND 599",
            name="ck_alert_webhook_attempt_http_status",
        ),
    )
    op.create_index(
        "ix_alert_webhook_attempt_delivery", "alert_webhook_attempts",
        ["delivery_id", "created_at"],
    )

    if bind.dialect.name == "postgresql":
        tables = (
            "webhook_endpoints", "webhook_secret_versions",
            "alert_webhook_deliveries", "alert_webhook_attempts",
        )
        for table in tables:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(
            """
            DO $$ DECLARE table_name text; BEGIN
              FOREACH table_name IN ARRAY ARRAY[
                'webhook_endpoints', 'webhook_secret_versions',
                'alert_webhook_deliveries', 'alert_webhook_attempts'
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
