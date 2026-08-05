# SPDX-License-Identifier: AGPL-3.0-only
"""Durable alert email queue and provider attempt history.

Revision ID: 0019
Revises: 0018
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

DELIVERY_VALUES = ("pending", "sending", "retrying", "sent", "failed", "suppressed")
ATTEMPT_VALUES = ("sending", "sent", "retrying", "failed")
EVENT_VALUES = (
    "state_imported", "opened", "reopened", "acknowledged", "assigned",
    "commented", "manual_resolution", "automatic_recovery", "policy_revised",
    "policy_deleted", "policy_superseded",
)


def upgrade() -> None:
    bind = op.get_bind()
    delivery_status = postgresql.ENUM(
        *DELIVERY_VALUES, name="emaildeliverystatus"
    )
    attempt_status = postgresql.ENUM(*ATTEMPT_VALUES, name="emailattemptstatus")
    delivery_status.create(bind, checkfirst=True)
    attempt_status.create(bind, checkfirst=True)
    delivery_status = postgresql.ENUM(
        *DELIVERY_VALUES, name="emaildeliverystatus", create_type=False
    )
    attempt_status = postgresql.ENUM(
        *ATTEMPT_VALUES, name="emailattemptstatus", create_type=False
    )
    event_type = postgresql.ENUM(
        *EVENT_VALUES, name="alerteventtype", create_type=False
    )

    op.create_table(
        "alert_email_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
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
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("text_body", sa.Text(), nullable=False),
        sa.Column("html_body", sa.Text(), nullable=False),
        sa.Column("status", delivery_status, nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("provider_message_id", sa.String(255)),
        sa.Column("last_error_code", sa.String(100)),
        sa.Column("last_retry_request_id", sa.String(64)),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "alert_event_id", "recipient", name="ux_alert_email_event_recipient"
        ),
        sa.CheckConstraint("generation >= 0", name="ck_alert_email_generation"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_alert_email_attempt_count"),
        sa.CheckConstraint("max_attempts BETWEEN 1 AND 20", name="ck_alert_email_max_attempts"),
    )
    op.create_index(
        "ix_alert_email_due", "alert_email_deliveries",
        ["status", "next_attempt_at", "created_at"],
    )
    op.create_index(
        "ix_alert_email_alert_created", "alert_email_deliveries",
        ["alert_id", "created_at"],
    )

    op.create_table(
        "alert_email_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "delivery_id", sa.String(36),
            sa.ForeignKey("alert_email_deliveries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("status", attempt_status, nullable=False),
        sa.Column("provider_message_id", sa.String(255)),
        sa.Column("error_code", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "delivery_id", "attempt_number", name="ux_alert_email_attempt_number"
        ),
        sa.CheckConstraint("attempt_number >= 1", name="ck_alert_email_attempt_number"),
    )
    op.create_index(
        "ix_alert_email_attempt_delivery", "alert_email_attempts",
        ["delivery_id", "created_at"],
    )

    if bind.dialect.name == "postgresql":
        for table in ("alert_email_deliveries", "alert_email_attempts"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(
            """
            DO $$ BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                REVOKE ALL ON TABLE alert_email_deliveries FROM anon;
                REVOKE ALL ON TABLE alert_email_attempts FROM anon;
              END IF;
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                REVOKE ALL ON TABLE alert_email_deliveries FROM authenticated;
                REVOKE ALL ON TABLE alert_email_attempts FROM authenticated;
              END IF;
            END $$
            """
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
