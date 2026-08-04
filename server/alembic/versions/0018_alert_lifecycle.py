# SPDX-License-Identifier: AGPL-3.0-only
"""Alert acknowledgement, assignment, resolution, and immutable history.

Revision ID: 0018
Revises: 0017
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

ALERT_STATE_VALUES = ("open", "acknowledged", "resolved")
EVENT_VALUES = (
    "state_imported", "opened", "reopened", "acknowledged", "assigned",
    "commented", "manual_resolution", "automatic_recovery", "policy_revised",
    "policy_deleted", "policy_superseded",
)


def upgrade() -> None:
    bind = op.get_bind()
    event_type = postgresql.ENUM(*EVENT_VALUES, name="alerteventtype")
    event_type.create(bind, checkfirst=True)
    event_type = postgresql.ENUM(
        *EVENT_VALUES, name="alerteventtype", create_type=False
    )
    alert_state = postgresql.ENUM(
        *ALERT_STATE_VALUES, name="alertstate", create_type=False
    )

    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("assigned_to_operator_id", sa.String(36)))
        batch.add_column(sa.Column("assigned_to_email", sa.String(320)))
        batch.add_column(sa.Column("acknowledged_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("acknowledged_by", sa.String(320)))
        batch.add_column(
            sa.Column("version", sa.Integer(), nullable=False, server_default="1")
        )
        batch.create_foreign_key(
            "fk_alerts_assigned_operator", "operators",
            ["assigned_to_operator_id"], ["id"], ondelete="SET NULL",
        )
        batch.create_index(
            "ix_alerts_assigned_to_operator_id", ["assigned_to_operator_id"]
        )

    op.create_table(
        "alert_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "alert_id", sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("event_type", event_type, nullable=False),
        sa.Column("from_state", alert_state),
        sa.Column("to_state", alert_state),
        sa.Column("actor", sa.String(320), nullable=False),
        sa.Column("actor_user_id", sa.String(36)),
        sa.Column("comment", sa.Text()),
        sa.Column("comment_redacted", sa.Boolean(), nullable=False),
        sa.Column("assigned_to_operator_id", sa.String(36)),
        sa.Column("assigned_to_email", sa.String(320)),
        sa.Column("source_result_id", sa.String(36)),
        sa.Column("request_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "request_id", name="ux_alert_event_request"),
        sa.UniqueConstraint(
            "alert_id", "source_result_id", name="ux_alert_event_source_result"
        ),
        sa.CheckConstraint("generation >= 0", name="ck_alert_event_generation"),
    )
    op.create_index(
        "ix_alert_events_alert_created", "alert_events", ["alert_id", "created_at"]
    )

    # Existing alert rows receive an immutable baseline event. New transitions
    # are then appended by the application.
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            INSERT INTO alert_events
              (id, alert_id, generation, event_type, from_state, to_state, actor,
               comment_redacted, created_at)
            SELECT md5(id || ':' || updated_at::text), id, generation,
                   'state_imported', NULL, state, 'system:migration', false, updated_at
            FROM alerts
            """
        )
        op.execute("ALTER TABLE alert_events ENABLE ROW LEVEL SECURITY")
        op.execute("REVOKE ALL ON TABLE alert_events FROM PUBLIC")
        op.execute(
            """
            DO $$ BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                REVOKE ALL ON TABLE alert_events FROM anon;
              END IF;
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                REVOKE ALL ON TABLE alert_events FROM authenticated;
              END IF;
            END $$
            """
        )
    else:
        op.execute(
            """
            INSERT INTO alert_events
              (id, alert_id, generation, event_type, from_state, to_state, actor,
               comment_redacted, created_at)
            SELECT lower(hex(randomblob(16))), id, generation, 'state_imported',
                   NULL, state, 'system:migration', 0, updated_at
            FROM alerts
            """
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
