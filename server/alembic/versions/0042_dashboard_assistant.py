# SPDX-License-Identifier: AGPL-3.0-only
"""Private, encrypted dashboard assistant history.

Revision ID: 0042
Revises: 0041
"""
from alembic import op
import sqlalchemy as sa

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assistant_conversations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("operator_id", sa.String(36), sa.ForeignKey("operators.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("operator_id", "client_id", "expires_at"):
        op.create_index(f"ix_assistant_conversations_{column}", "assistant_conversations", [column])
    op.create_table(
        "assistant_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("conversation_id", sa.String(36), sa.ForeignKey("assistant_conversations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("tool_count", sa.Integer(), nullable=False),
        sa.Column("usage_tokens", sa.Integer(), nullable=False),
        sa.UniqueConstraint("conversation_id", "request_id", name="uq_assistant_request"),
    )
    for column in ("conversation_id", "created_at"):
        op.create_index(f"ix_assistant_runs_{column}", "assistant_runs", [column])


def downgrade():
    op.drop_table("assistant_runs")
    op.drop_table("assistant_conversations")
