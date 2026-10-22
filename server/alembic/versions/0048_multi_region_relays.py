# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-region relays (issue #87).

Adds the control-plane registry that lets a regional relay forward agent
traffic without being trusted for content:

* ``relay_regions`` and ``relays`` name the ingress points agents may use.
* ``relay_keys`` holds only the *public* half of each relay's Ed25519
  forwarding key, with an explicit active/overlap/retired/revoked lifecycle and
  a hard ``not_after``.
* ``tenant_region_policies`` pins a tenant's agent ingress to a home region,
  either ``preferred`` (failover elsewhere allowed) or ``strict``.
* ``relay_forward_receipts`` is the replay guard. The unique (relay_id, nonce)
  index is what makes a replayed or duplicated forward refuse instead of
  executing twice, under concurrency as well as sequentially.
* ``agents.relay_route`` records the server-observed ingress path of the last
  accepted check-in so a path change is audited once, not on every beat.

Statuses are application-validated short strings, not database ENUM types, so
no PostgreSQL type is created here.

Compatibility and rollout: every change is additive. The new tables and the
nullable column are never read by an older application binary. The capability
is inert until ``RELAY_ROUTING_ENABLED`` is set, so the schema is safe to apply
ahead of the build that uses it and safe to leave applied if that build is
rolled back; agents fall back to direct origin polling.

Rollback: migrations here are forward-only. Backing the capability out is a
configuration change (disable relay routing), not a schema change. Crossing
back below this revision requires the exact-revision restore procedure in
docs/ROLLBACK.md.

Revision ID: 0048
Revises: 0047
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "relay_regions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("code", name="ux_relay_regions_code"),
    )

    op.create_table(
        "relays",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "region_id",
            sa.String(length=36),
            sa.ForeignKey("relay_regions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("tls_spki_pins", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_forward_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("base_url", name="ux_relays_base_url"),
    )
    op.create_index("ix_relays_region_status", "relays", ["region_id", "status"])

    op.create_table(
        "relay_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "relay_id",
            sa.String(length=36),
            sa.ForeignKey("relays.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("public_key_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("key_id", name="ux_relay_keys_key_id"),
    )
    op.create_index("ix_relay_keys_relay_status", "relay_keys", ["relay_id", "status"])

    op.create_table(
        "tenant_region_policies",
        sa.Column(
            "client_id",
            sa.String(length=36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "region_id",
            sa.String(length=36),
            sa.ForeignKey("relay_regions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("set_by", sa.String(length=320), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_tenant_region_policies_region", "tenant_region_policies", ["region_id"]
    )

    op.create_table(
        "relay_forward_receipts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "relay_id",
            sa.String(length=36),
            sa.ForeignKey("relays.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("path", sa.String(length=256), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("relay_id", "nonce", name="ux_relay_forward_receipts_nonce"),
    )
    op.create_index(
        "ix_relay_forward_receipts_received", "relay_forward_receipts", ["received_at"]
    )
    op.create_index(
        "ix_relay_forward_receipts_agent",
        "relay_forward_receipts",
        ["agent_id", "received_at"],
    )

    op.add_column("agents", sa.Column("relay_route", sa.String(length=36), nullable=True))


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
