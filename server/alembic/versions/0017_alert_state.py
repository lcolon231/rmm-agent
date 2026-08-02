# SPDX-License-Identifier: AGPL-3.0-only
"""Deduplicated monitoring alert state.

Revision ID: 0017
Revises: 0016

Issue #43 adds one reusable alert row per policy/endpoint/check identity. There
is no historical alert data to backfill. Existing check results remain intact;
new results begin driving alert state after the server is deployed.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


ALERT_STATE_VALUES = ("open", "acknowledged", "resolved")
CHECK_STATUS_VALUES = ("ok", "warning", "critical", "unknown")


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM(*ALERT_STATE_VALUES, name="alertstate").create(
        bind, checkfirst=True
    )
    # Reuse #41's existing check-result status type for the latest observation.
    alert_state = postgresql.ENUM(
        *ALERT_STATE_VALUES, name="alertstate", create_type=False
    )
    check_status = postgresql.ENUM(
        *CHECK_STATUS_VALUES, name="checkresultstatus", create_type=False
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(length=36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("policy_revision_id", sa.String(length=36), nullable=False),
        sa.Column("check_key", sa.String(length=64), nullable=False),
        sa.Column("state", alert_state, nullable=False),
        sa.Column("last_result_status", check_status, nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("total_occurrence_count", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("first_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result_id", sa.String(length=36), nullable=True),
        sa.Column("last_value", sa.Float(), nullable=True),
        sa.Column("resolution_reason", sa.String(length=64), nullable=True),
        sa.Column("suppression_window_id", sa.String(length=36), nullable=True),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "agent_id", "policy_id", "check_key", name="ux_alert_identity"
        ),
        sa.CheckConstraint(
            "occurrence_count >= 0 AND total_occurrence_count >= 0 AND generation >= 0",
            name="ck_alert_nonnegative_counters",
        ),
    )
    op.create_index(
        "ix_alerts_state_last_observed",
        "alerts",
        ["state", "last_observed_at"],
    )
    op.create_index("ix_alerts_agent_state", "alerts", ["agent_id", "state"])
    op.create_table(
        "alert_observations",
        sa.Column(
            "check_result_id",
            sa.String(length=36),
            sa.ForeignKey("check_results.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "alert_id",
            sa.String(length=36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", check_status, nullable=False),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("out_of_order", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_alert_observations_alert_evaluated",
        "alert_observations",
        ["alert_id", "evaluated_at"],
    )

    # Supabase exposes ``public`` through the Data API by default. NodeLink's
    # FastAPI boundary owns authorization, so direct anon/authenticated access
    # is denied and RLS is enabled without permissive policies. The DO block is
    # portable to ordinary PostgreSQL instances where those roles do not exist.
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE alerts ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE alert_observations ENABLE ROW LEVEL SECURITY")
        op.execute(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                REVOKE ALL ON TABLE alerts FROM anon;
                REVOKE ALL ON TABLE alert_observations FROM anon;
              END IF;
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                REVOKE ALL ON TABLE alerts FROM authenticated;
                REVOKE ALL ON TABLE alert_observations FROM authenticated;
              END IF;
            END
            $$
            """
        )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
