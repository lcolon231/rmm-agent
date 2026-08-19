# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped authorization: memberships, platform admin, audit anchoring (issue #66).

Phase 1 of docs/TENANT-AUTHORIZATION.md — the data model the enforcement layer
is built on. This revision alone changes no behavior: it adds the tables and
columns, and backfills them so that applying it preserves exactly the access
every operator has today. The default-deny query boundary that *uses* them
lands in the following phase.

What is added:

* ``operator_client_memberships`` — one row per (operator, client) grant, with
  the tenant-scoped role and mandatory provenance (``granted_by``, ``reason``).
* ``operators.is_platform_admin`` — the deployment-wide superuser flag, default
  ``false`` so a new operator is default-deny.
* ``ix_audit_events_org_ts_id`` — the index tenant-filtered timeline reads use.

What is backfilled:

* ``audit_events.organization_id`` from ``agent -> site -> client`` for every
  event that carries a resolvable ``agent_id``. Events with no derivable client
  (system events) keep ``NULL``. ``organization_id`` is not part of the hashed
  audit document (``app/core/audit.py``), so this backfill leaves every
  existing hash chain and anchor verifiable unchanged.
* Authorization, to preserve current visibility: existing global ``admin``
  operators become platform admins; existing ``operator``/``readonly``
  operators receive a membership over every client that exists at migration
  time, at the equivalent tenant role. New clients and new operators are
  default-deny. The stricter alternative — grant nothing and require every
  membership to be re-issued — is rejected in the design because a silent
  post-upgrade lockout of every non-admin operator is a worse operational
  failure than a one-time broad grant a platform admin can immediately tighten.

Backfilled rows are stamped ``granted_by = 'migration:0037'`` so a broad,
automatic grant is never mistaken for a deliberate one and can be found and
revoked with a single query. The migration deliberately does **not** append an
audit event: the chain's hashing and serialized-append logic lives in the
application, and reproducing it inside a migration would risk forking the
chain. The stamped provenance on each row is the evidence; the audited
grant/revoke events arrive with the membership admin API.

Compatibility: additive and forward-only. No agent or protocol change — tenancy
is enforced entirely at the operator/server boundary, and the JWT is unchanged.
The new PostgreSQL enum type cannot be removed in place; crossing back below
this revision requires the exact-revision restore procedure in docs/ROLLBACK.md.

Revision ID: 0037
Revises: 0036
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


# Matches what SQLAlchemy derives from the ``ClientRole`` ORM enum, so the
# migrated schema and the ORM agree on PostgreSQL.
CLIENT_ROLE_VALUES = ("client_readonly", "client_operator", "client_admin")

# Global role -> equivalent tenant role for the visibility-preserving backfill.
ROLE_EQUIVALENTS = {
    "readonly": "client_readonly",
    "operator": "client_operator",
}

BACKFILL_GRANTOR = "migration:0037"
BACKFILL_REASON = (
    "Backfilled by migration 0037 to preserve pre-tenancy visibility (issue #66); "
    "review and tighten"
)


def upgrade() -> None:
    bind = op.get_bind()

    postgresql.ENUM(*CLIENT_ROLE_VALUES, name="clientrole").create(
        bind, checkfirst=True
    )

    op.create_table(
        "operator_client_memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "client_id",
            sa.String(36),
            sa.ForeignKey("clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role",
            # ``create_type=False``: the type is created once by the explicit
            # ``.create(checkfirst=True)`` above, so ``create_table`` must not
            # emit ``CREATE TYPE`` a second time. Mirrors revision 0036.
            postgresql.ENUM(*CLIENT_ROLE_VALUES, name="clientrole", create_type=False),
            nullable=False,
        ),
        sa.Column("granted_by", sa.String(320), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "operator_id",
            "client_id",
            name="uq_operator_client_memberships_operator_client",
        ),
    )
    op.create_index(
        "ix_operator_client_memberships_operator_id",
        "operator_client_memberships",
        ["operator_id"],
    )
    op.create_index(
        "ix_operator_client_memberships_client_id",
        "operator_client_memberships",
        ["client_id"],
    )
    op.create_index(
        "ix_operator_client_memberships_operator_client",
        "operator_client_memberships",
        ["operator_id", "client_id"],
    )

    op.add_column(
        "operators",
        sa.Column(
            "is_platform_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.create_index(
        "ix_audit_events_org_ts_id",
        "audit_events",
        ["organization_id", "ts", "id"],
    )

    # Anchor historical audit events to the tenant they belong to. Set-based,
    # like the ROW_NUMBER backfill in 0007; only events whose agent still
    # resolves through site -> client are stamped.
    op.execute(
        """
        UPDATE audit_events SET
            organization_id = (
                SELECT sites.client_id
                FROM agents
                JOIN sites ON sites.id = agents.site_id
                WHERE agents.id = audit_events.agent_id
            )
        WHERE organization_id IS NULL
          AND agent_id IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM agents
              JOIN sites ON sites.id = agents.site_id
              WHERE agents.id = audit_events.agent_id
          )
        """
    )

    # Existing global admins become platform admins: they can see every tenant
    # today, and demoting them silently at upgrade would lock the deployment's
    # only administrators out of their own fleet.
    op.execute(
        "UPDATE operators SET is_platform_admin = true WHERE role = 'admin'"
    )

    _backfill_memberships(bind)


def _backfill_memberships(bind: sa.engine.Connection) -> None:
    """Grant every non-admin operator its current visibility, once.

    Rows are built in Python rather than a set-based INSERT ... SELECT because
    each needs a fresh UUID primary key; the cross product is bounded by
    (operators x clients) at upgrade time, which is small for every deployment
    this migration can reach.
    """
    client_ids = [
        row[0] for row in bind.execute(sa.text("SELECT id FROM clients")).fetchall()
    ]
    if not client_ids:
        return

    operators = bind.execute(
        sa.text("SELECT id, role FROM operators WHERE role <> 'admin'")
    ).fetchall()
    if not operators:
        return

    now = datetime.now(timezone.utc)
    rows = [
        {
            "id": str(uuid.uuid4()),
            "operator_id": operator_id,
            "client_id": client_id,
            "role": ROLE_EQUIVALENTS[_role_value(role)],
            "granted_by": BACKFILL_GRANTOR,
            "reason": BACKFILL_REASON,
            "created_at": now,
        }
        for operator_id, role in operators
        for client_id in client_ids
        if _role_value(role) in ROLE_EQUIVALENTS
    ]
    if not rows:
        return

    memberships = sa.table(
        "operator_client_memberships",
        sa.column("id", sa.String),
        sa.column("operator_id", sa.String),
        sa.column("client_id", sa.String),
        # The declared type must match the real column: on PostgreSQL a VARCHAR
        # bind against the ``clientrole`` enum is rejected outright.
        sa.column(
            "role",
            postgresql.ENUM(*CLIENT_ROLE_VALUES, name="clientrole", create_type=False),
        ),
        sa.column("granted_by", sa.String),
        sa.column("reason", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(memberships, rows)


def _role_value(role: object) -> str:
    """Normalize a stored role to its string value.

    SQLite returns the raw string; PostgreSQL's enum round-trips as a string
    too, but a driver that hands back an ``Enum`` must not silently fall
    through to "no equivalent tenant role" and skip the grant.
    """
    return getattr(role, "value", role)


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
