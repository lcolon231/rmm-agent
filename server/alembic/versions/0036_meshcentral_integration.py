# SPDX-License-Identifier: AGPL-3.0-only
"""MeshCentral remote-desktop launch mapping and audit metadata (issue #62).

Adds the agent-to-MeshCentral-node identity mapping table and the launch record
table that carries the operator-visible, secret-free evidence for a remote
desktop session launch. MeshCentral remains a separate trust boundary: neither
table stores a MeshCentral credential, login cookie, or session payload.

Compatibility: every change is additive and the provider defaults to
``disabled``. An older application ignores the new tables and never mints a
launch, so a mixed-version fleet degrades to "remote desktop unavailable"
rather than misbehaving. The new PostgreSQL enum types cannot be removed in
place; crossing back below this revision requires the exact-revision restore
procedure in docs/ROLLBACK.md.

Revision ID: 0036
Revises: 0035
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


# Type names match what SQLAlchemy derives from the ORM enums, so the migrated
# schema and the ORM agree on PostgreSQL.
MAPPING_STATE_VALUES = ("active", "stale", "unmapped", "conflict")
MAPPING_ORIGIN_VALUES = ("manual", "reconciled")
LAUNCH_STATUS_VALUES = ("requested", "authorized", "denied", "failed", "closed")


def _enum_column(values: tuple[str, ...], name: str) -> postgresql.ENUM:
    """Column type that reuses an already-created PostgreSQL enum.

    ``create_type=False`` matters: the types are created once by the explicit
    ``.create(checkfirst=True)`` calls in :func:`upgrade`, so ``create_table``
    must not emit ``CREATE TYPE`` a second time. Mirrors revision ``0035``.
    """
    return postgresql.ENUM(*values, name=name, create_type=False)


def upgrade() -> None:
    bind = op.get_bind()

    postgresql.ENUM(*MAPPING_STATE_VALUES, name="meshmappingstate").create(
        bind, checkfirst=True
    )
    postgresql.ENUM(*MAPPING_ORIGIN_VALUES, name="meshmappingorigin").create(
        bind, checkfirst=True
    )
    postgresql.ENUM(*LAUNCH_STATUS_VALUES, name="meshlaunchstatus").create(
        bind, checkfirst=True
    )

    op.create_table(
        "meshcentral_mappings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("meshcentral_node_id", sa.String(128), nullable=False),
        sa.Column("meshcentral_mesh_id", sa.String(128), nullable=True),
        sa.Column(
            "state",
            _enum_column(MAPPING_STATE_VALUES, "meshmappingstate"),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "origin",
            _enum_column(MAPPING_ORIGIN_VALUES, "meshmappingorigin"),
            nullable=False,
            server_default="manual",
        ),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_in_mesh_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("agent_id", name="uq_meshcentral_mappings_agent"),
    )
    op.create_index(
        "ix_meshcentral_mappings_agent_id", "meshcentral_mappings", ["agent_id"]
    )
    op.create_index(
        "ix_meshcentral_mappings_node",
        "meshcentral_mappings",
        ["meshcentral_node_id"],
    )
    op.create_index(
        "ix_meshcentral_mappings_agent_state",
        "meshcentral_mappings",
        ["agent_id", "state"],
    )

    op.create_table(
        "meshcentral_launches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "agent_id",
            sa.String(36),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mapping_id",
            sa.String(36),
            sa.ForeignKey("meshcentral_mappings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("meshcentral_node_id", sa.String(128), nullable=True),
        sa.Column(
            "status",
            _enum_column(LAUNCH_STATUS_VALUES, "meshlaunchstatus"),
            nullable=False,
            server_default="requested",
        ),
        sa.Column("denied_reason", sa.String(64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("meshcentral_session_ref", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_meshcentral_launches_agent_id", "meshcentral_launches", ["agent_id"]
    )
    op.create_index(
        "ix_meshcentral_launches_operator_id",
        "meshcentral_launches",
        ["operator_id"],
    )
    op.create_index(
        "ix_meshcentral_launches_status", "meshcentral_launches", ["status"]
    )
    op.create_index(
        "ix_meshcentral_launches_agent_created",
        "meshcentral_launches",
        ["agent_id", "created_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
