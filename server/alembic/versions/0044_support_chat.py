# SPDX-License-Identifier: AGPL-3.0-only
"""Endpoint support chat. Revision 0044, following current head 0043."""
from alembic import op
import sqlalchemy as sa

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "support_conversations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(6), nullable=False),
        sa.Column("opened_by", sa.String(10), nullable=False),
        sa.Column("subject", sa.String(120)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_message_at", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("closed_by_operator_id", sa.String(36), sa.ForeignKey("operators.id", ondelete="SET NULL")),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notice_version", sa.String(32)),
        sa.Column("notice_acknowledged_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_support_agent_status", "support_conversations", ["agent_id", "status"])
    op.create_index("ix_support_client_status", "support_conversations", ["client_id", "status"])
    op.create_table(
        "support_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("conversation_id", sa.String(36), sa.ForeignKey("support_conversations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("sender", sa.String(10), nullable=False),
        sa.Column("operator_id", sa.String(36), sa.ForeignKey("operators.id", ondelete="SET NULL")),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("conversation_id", "seq", name="uq_support_message_seq"),
    )


def downgrade():
    op.drop_table("support_messages")
    op.drop_table("support_conversations")
