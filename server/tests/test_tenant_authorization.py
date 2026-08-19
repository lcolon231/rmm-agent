# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped authorization data model and migration tests (issue #66).

Phase 1 of docs/TENANT-AUTHORIZATION.md. Behavior under test:
  - a new operator is default-deny: ``is_platform_admin`` is false and it holds
    no membership unless one is granted
  - one operator may hold at most one membership per client
  - migration 0037 preserves existing access: global admins become platform
    admins, other operators receive an equivalent-role membership over every
    client that existed at upgrade time, stamped with migration provenance
  - clients and operators created *after* the migration are not auto-granted
  - the migration backfills ``audit_events.organization_id`` from
    agent -> site -> client, leaves undrivable events NULL, and the audit hash
    chain still verifies afterwards
  - the same schema and backfill hold on PostgreSQL, not only SQLite

Run just this file:  pytest tests/test_tenant_authorization.py -q
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_tenant_authz.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
import sqlalchemy as sa  # noqa: E402
from alembic import command  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)

from app.core import audit  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
)
from tests.test_migrations import migration_config, sqlite_url  # noqa: E402


NOW = "2026-07-18T12:00:00+00:00"
# asyncpg binds timestamps as datetimes, not ISO strings, so the PostgreSQL
# path uses this instead of the literal SQLite tests insert.
NOW_DT = datetime.fromisoformat(NOW)


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def test_new_operator_is_default_deny(db):
    """No membership and no platform-admin flag unless explicitly granted."""
    operator = Operator(
        email="viewer@nodelink.test",
        password_hash=hash_password("viewer-password"),
        role=OperatorRole.admin,
    )
    db.add(operator)
    await db.commit()
    await db.refresh(operator)

    # Even a *global* admin is not a platform admin by construction: the
    # promotion is an explicit act (or the one-time 0037 backfill).
    assert operator.is_platform_admin is False
    memberships = (
        await db.execute(
            sa.select(OperatorClientMembership).where(
                OperatorClientMembership.operator_id == operator.id
            )
        )
    ).scalars().all()
    assert memberships == []


async def test_membership_is_unique_per_operator_and_client(db):
    operator = Operator(
        email="tech@nodelink.test",
        password_hash=hash_password("tech-password"),
        role=OperatorRole.operator,
    )
    client = Client(name="North Clinic")
    db.add_all([operator, client])
    await db.commit()

    db.add(
        OperatorClientMembership(
            operator_id=operator.id,
            client_id=client.id,
            role=ClientRole.client_operator,
            granted_by="admin@nodelink.test",
            reason="Assigned to the North Clinic account",
        )
    )
    await db.commit()

    db.add(
        OperatorClientMembership(
            operator_id=operator.id,
            client_id=client.id,
            role=ClientRole.client_readonly,
            granted_by="admin@nodelink.test",
            reason="Duplicate grant with a different role",
        )
    )
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


def _seed_pre_tenancy(db_path: Path) -> None:
    """A deployment as it looks at revision 0036: two clients, agents under
    both, one global admin, one operator, one readonly, and audit events with
    and without a resolvable agent."""
    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            [("client-a", "North Clinic", NOW), ("client-b", "South Depot", NOW)],
        )
        connection.executemany(
            "INSERT INTO sites (id, client_id, name, created_at) VALUES (?, ?, ?, ?)",
            [("site-a", "client-a", "HQ", NOW), ("site-b", "client-b", "Yard", NOW)],
        )
        connection.executemany(
            """INSERT INTO agents
               (id, site_id, token_hash, hostname, os, os_version,
                agent_version, status, enrolled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                ("agent-a", "site-a", "hash-a", "PC-A", "windows", "11", "0.1", "pending", NOW),
                ("agent-b", "site-b", "hash-b", "PC-B", "windows", "11", "0.1", "pending", NOW),
            ],
        )
        connection.executemany(
            """INSERT INTO operators
               (id, email, password_hash, role, disabled, token_generation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                ("op-admin", "admin@nodelink.test", "hash", "admin", 0, 0, NOW),
                ("op-tech", "tech@nodelink.test", "hash", "operator", 0, 0, NOW),
                ("op-view", "view@nodelink.test", "hash", "readonly", 0, 0, NOW),
            ],
        )
        connection.commit()


def _seed_audit_chain(db_path: Path) -> None:
    """Three chained events: one per agent, plus a system event with no agent,
    and one referencing an agent that no longer exists."""
    rows = []
    prev = "0" * 64
    seeds = [
        ("agent.enrolled", "agent-a"),
        ("agent.enrolled", "agent-b"),
        ("system.startup", None),
        ("agent.offline", "agent-deleted"),
    ]
    for index, (action, agent_id) in enumerate(seeds, start=1):
        event_id = str(uuid.uuid4())
        ts = f"2026-02-0{index} 00:00:00.000000"
        ts_iso = f"2026-02-0{index}T00:00:00+00:00"
        event_hash = audit._hash_event(
            prev,
            ts_iso,
            "system",
            action,
            agent_id,
            {},
            seq=index,
            hash_schema=audit.HASH_SCHEMA_SEQUENCED,
        )
        rows.append(
            (event_id, index, 2, ts, ts_iso, "system", action, agent_id, "{}", prev, event_hash)
        )
        prev = event_hash

    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            """INSERT INTO audit_events
               (id, seq, hash_schema, ts, ts_iso, actor, action, agent_id,
                detail, prev_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        connection.commit()


def test_migration_preserves_existing_access_and_marks_provenance(tmp_path: Path):
    db_path = tmp_path / "pre-tenancy.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "0036")
    _seed_pre_tenancy(db_path)

    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as connection:
        platform_admins = connection.execute(
            "SELECT id FROM operators WHERE is_platform_admin = 1"
        ).fetchall()
        memberships = connection.execute(
            """SELECT operator_id, client_id, role, granted_by, reason
               FROM operator_client_memberships
               ORDER BY operator_id, client_id"""
        ).fetchall()

    # The global admin keeps deployment-wide reach; nobody else is promoted.
    assert platform_admins == [("op-admin",)]

    # The other two keep exactly what they could see before: every client that
    # existed at upgrade time, at the equivalent tenant role.
    assert [(row[0], row[1], row[2]) for row in memberships] == [
        ("op-tech", "client-a", "client_operator"),
        ("op-tech", "client-b", "client_operator"),
        ("op-view", "client-a", "client_readonly"),
        ("op-view", "client-b", "client_readonly"),
    ]
    # A platform admin can find and revoke the broad grant in one query.
    assert {row[3] for row in memberships} == {"migration:0037"}
    assert all("migration 0037" in row[4] for row in memberships)


def test_migration_does_not_grant_clients_or_operators_created_later(tmp_path: Path):
    """The backfill is a one-time preservation, not a standing rule."""
    db_path = tmp_path / "post-migration-rows.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "0036")
    _seed_pre_tenancy(db_path)
    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            ("client-new", "East Labs", NOW),
        )
        connection.execute(
            """INSERT INTO operators
               (id, email, password_hash, role, is_platform_admin, disabled,
                token_generation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("op-new", "new@nodelink.test", "hash", "operator", 0, 0, 0, NOW),
        )
        connection.commit()

        granted_clients = connection.execute(
            "SELECT DISTINCT client_id FROM operator_client_memberships"
        ).fetchall()
        new_operator_memberships = connection.execute(
            "SELECT COUNT(*) FROM operator_client_memberships WHERE operator_id = 'op-new'"
        ).fetchone()

    assert sorted(row[0] for row in granted_clients) == ["client-a", "client-b"]
    assert new_operator_memberships == (0,)


def test_migration_on_empty_deployment_grants_nothing(tmp_path: Path):
    db_path = tmp_path / "empty.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM operator_client_memberships"
        ).fetchone()
    assert count == (0,)


def test_migration_anchors_audit_events_to_their_tenant(tmp_path: Path):
    db_path = tmp_path / "audit-tenancy.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0036")
    _seed_pre_tenancy(db_path)
    _seed_audit_chain(db_path)

    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as connection:
        anchored = connection.execute(
            "SELECT action, agent_id, organization_id FROM audit_events ORDER BY seq"
        ).fetchall()
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }

    assert anchored == [
        ("agent.enrolled", "agent-a", "client-a"),
        ("agent.enrolled", "agent-b", "client-b"),
        # No agent to resolve through: a system event belongs to no tenant.
        ("system.startup", None, None),
        # An agent_id that no longer resolves is left NULL rather than guessed.
        ("agent.offline", "agent-deleted", None),
    ]
    assert "ix_audit_events_org_ts_id" in indexes

    async def verify() -> None:
        migrated_engine = create_async_engine(url)
        maker = async_sessionmaker(migrated_engine, expire_on_commit=False)
        try:
            async with maker() as session:
                ok, broken = await audit.verify_chain(session)
                assert ok, f"chain broken at {broken} after organization_id backfill"
        finally:
            await migrated_engine.dispose()

    # organization_id is not part of the hashed document, so stamping it must
    # leave every existing chain and anchor verifiable.
    asyncio.run(verify())


async def _reset_postgres_schema(url: str) -> None:
    """Return the disposable CI database to empty.

    ``TEST_POSTGRES_URL`` is shared with test_migrations.py, which asserts the
    database starts empty. Resetting on both sides of this test keeps the two
    independent of ordering, and drops the ``clientrole`` enum type this
    revision creates, which a plain table drop would leave behind.
    """
    reset_engine = create_async_engine(url, isolation_level="AUTOCOMMIT")
    try:
        async with reset_engine.connect() as connection:
            await connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            await connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        await reset_engine.dispose()


@pytest.mark.skipif(
    not os.getenv("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is only configured for the disposable CI database",
)
def test_postgresql_upgrade_creates_membership_schema_and_backfills():
    """The enum, table, and backfill behave the same on the production engine."""
    url = os.environ["TEST_POSTGRES_URL"]
    config = migration_config(url)
    asyncio.run(_reset_postgres_schema(url))
    command.upgrade(config, "0036")

    async def seed() -> None:
        seed_engine = create_async_engine(url)
        try:
            async with seed_engine.begin() as connection:
                await connection.execute(
                    sa.text(
                        "INSERT INTO clients (id, name, created_at)"
                        " VALUES (:id, :name, :ts)"
                    ),
                    {"id": "client-a", "name": "North Clinic", "ts": NOW_DT},
                )
                await connection.execute(
                    sa.text(
                        """INSERT INTO operators
                           (id, email, password_hash, role, disabled,
                            token_generation, created_at)
                           VALUES (:id, :email, 'hash', :role, false, 0, :ts)"""
                    ),
                    [
                        {
                            "id": "op-admin",
                            "email": "admin@nodelink.test",
                            "role": "admin",
                            "ts": NOW_DT,
                        },
                        {
                            "id": "op-tech",
                            "email": "tech@nodelink.test",
                            "role": "operator",
                            "ts": NOW_DT,
                        },
                    ],
                )
        finally:
            await seed_engine.dispose()

    async def inspect_migrated() -> tuple[list, list]:
        migrated_engine = create_async_engine(url)
        try:
            async with migrated_engine.connect() as connection:
                platform_admins = (
                    await connection.execute(
                        sa.text("SELECT id FROM operators WHERE is_platform_admin")
                    )
                ).fetchall()
                memberships = (
                    await connection.execute(
                        sa.text(
                            "SELECT operator_id, client_id, role::text, granted_by"
                            " FROM operator_client_memberships"
                        )
                    )
                ).fetchall()
                with pytest.raises(IntegrityError):
                    await connection.execute(
                        sa.text(
                            """INSERT INTO operator_client_memberships
                               (id, operator_id, client_id, role, granted_by,
                                reason, created_at)
                               VALUES (:id, 'op-tech', 'client-a',
                                       'client_readonly', 'admin@nodelink.test',
                                       'duplicate', :ts)"""
                        ),
                        {"id": str(uuid.uuid4()), "ts": NOW_DT},
                    )
            return platform_admins, memberships
        finally:
            await migrated_engine.dispose()

    asyncio.run(seed())
    command.upgrade(config, "head")
    try:
        platform_admins, memberships = asyncio.run(inspect_migrated())
    finally:
        asyncio.run(_reset_postgres_schema(url))

    assert platform_admins == [("op-admin",)]
    assert memberships == [
        ("op-tech", "client-a", "client_operator", "migration:0037")
    ]
