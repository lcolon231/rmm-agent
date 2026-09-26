# SPDX-License-Identifier: AGPL-3.0-only
"""Support chat lifecycle index (issue #237). Revision 0045, following 0044.

Retention selects conversations closed before a cutoff, which leads on
``status``; the existing ``(agent_id, status)`` and ``(client_id, status)``
indexes cannot serve it.
Index-only, so downgrade drops it with no data consequence.
"""
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_support_status_closed_at", "support_conversations", ["status", "closed_at"]
    )


def downgrade():
    op.drop_index("ix_support_status_closed_at", table_name="support_conversations")
