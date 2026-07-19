# SPDX-License-Identifier: AGPL-3.0-only
"""Audit sequence-number tests (issue #75).

Behavior under test:
  - appends assign a contiguous monotonic seq (1, 2, 3, ...) bound into the
    event hash (hash_schema=2)
  - verification walks seq order and fails on gaps, duplicates/reorders,
    edits to seq, and legacy-schema events appearing after the cutover
  - the unique constraint on seq rejects forked appends
  - migration 0007 backfills legacy rows 1..N in (ts, id) order as
    hash_schema=1 and the mixed chain still verifies
  - concurrent appends on PostgreSQL serialize without gaps or duplicates

Run just this file:  pytest tests/test_audit_sequence.py -q
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import uuid
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_audit_seq.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from alembic import command  # noqa: E402
from sqlalchemy import select, text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

from app.core import audit  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.models.models import AuditEvent  # noqa: E402
from tests.test_migrations import migration_config, sqlite_url  # noqa: E402


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def _append(db: AsyncSession, n: int) -> list[AuditEvent]:
    events = []
    for i in range(n):
        events.append(await audit.record(db, action=f"test.event{i}"))
    await db.commit()
    return events


@pytest.mark.asyncio
async def test_appends_are_contiguous_and_seq_is_hashed(db):
    events = await _append(db, 5)
    assert [e.seq for e in events] == [1, 2, 3, 4, 5]
    assert all(e.hash_schema == audit.HASH_SCHEMA_SEQUENCED for e in events)

    ok, broken = await audit.verify_chain(db)
    assert ok and broken is None

    # seq is part of the hash: renumbering an event breaks its own hash even
    # if a tamperer fixes up the neighbors' ordering.
    ev = events[2]
    recomputed_with_wrong_seq = audit._hash_event(
        ev.prev_hash, ev.ts_iso, ev.actor, ev.action, ev.agent_id, ev.detail,
        seq=99, hash_schema=audit.HASH_SCHEMA_SEQUENCED,
    )
    assert recomputed_with_wrong_seq != ev.event_hash


@pytest.mark.asyncio
async def test_gap_is_detected(db):
    events = await _append(db, 4)
    await db.execute(
        AuditEvent.__table__.delete().where(AuditEvent.id == events[1].id)
    )
    await db.commit()
    db.expire_all()
    ok, broken = await audit.verify_chain(db)
    assert not ok
    assert broken == events[2].id  # first event after the hole


@pytest.mark.asyncio
async def test_seq_edit_is_detected(db):
    events = await _append(db, 3)
    # Renumber the tail event to fake extra history before it.
    await db.execute(
        AuditEvent.__table__.update()
        .where(AuditEvent.id == events[2].id)
        .values(seq=5)
    )
    await db.commit()
    db.expire_all()  # raw UPDATE bypassed the ORM; drop cached attributes
    ok, broken = await audit.verify_chain(db)
    assert not ok
    assert broken == events[2].id


@pytest.mark.asyncio
async def test_duplicate_seq_is_rejected_by_constraint(db):
    events = await _append(db, 2)
    with pytest.raises(Exception):
        await db.execute(
            AuditEvent.__table__.update()
            .where(AuditEvent.id == events[1].id)
            .values(seq=1)
        )
        await db.commit()


@pytest.mark.asyncio
async def test_null_seq_fails_verification(db):
    events = await _append(db, 2)
    await db.execute(
        AuditEvent.__table__.update()
        .where(AuditEvent.id == events[1].id)
        .values(seq=None)
    )
    await db.commit()
    db.expire_all()
    ok, broken = await audit.verify_chain(db)
    assert not ok


def test_migration_backfills_legacy_events_in_ts_id_order(tmp_path: Path):
    """Insert pre-0007 events at revision 0006, upgrade, and confirm the
    backfill froze (ts, id) order into seq with hash_schema=1."""
    db_path = tmp_path / "legacy_audit.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0006")

    # Legacy-style rows: hash chain in (ts, id) order, no seq columns yet.
    rows = []
    prev = "0" * 64
    for i in range(4):
        ev_id = str(uuid.uuid4())
        ts = f"2026-01-0{i + 1} 00:00:00.000000"
        ts_iso = f"2026-01-0{i + 1}T00:00:00+00:00"
        ev_hash = audit._hash_event(
            prev, ts_iso, "legacy", f"legacy.event{i}", None, {},
            hash_schema=audit.HASH_SCHEMA_LEGACY,
        )
        rows.append((ev_id, ts, ts_iso, "legacy", f"legacy.event{i}", None, "{}", prev, ev_hash))
        prev = ev_hash

    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO audit_events (id, ts, ts_iso, actor, action, agent_id, detail, prev_hash, event_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()

    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as conn:
        got = conn.execute(
            "SELECT seq, hash_schema, action FROM audit_events ORDER BY seq"
        ).fetchall()
    assert [(r[0], r[1]) for r in got] == [(1, 1), (2, 1), (3, 1), (4, 1)]
    assert [r[2] for r in got] == [f"legacy.event{i}" for i in range(4)]

    async def verify_and_extend() -> None:
        eng = create_async_engine(url)
        maker = async_sessionmaker(eng, expire_on_commit=False)
        try:
            async with maker() as session:
                ok, broken = await audit.verify_chain(session)
                assert ok, f"legacy backfilled chain broken at {broken}"
                # New appends continue the numbering under the current schema.
                ev = await audit.record(session, action="post.migration")
                await session.commit()
                assert ev.seq == 5
                assert ev.hash_schema == audit.HASH_SCHEMA_SEQUENCED
                ok, broken = await audit.verify_chain(session)
                assert ok, f"mixed-schema chain broken at {broken}"
        finally:
            await eng.dispose()

    asyncio.run(verify_and_extend())


@pytest.mark.asyncio
async def test_legacy_schema_after_cutover_fails(db):
    events = await _append(db, 2)
    # Downgrade the tail event's schema marker: a forger trying to append
    # unhashed-seq events after the cutover must be caught.
    await db.execute(
        AuditEvent.__table__.update()
        .where(AuditEvent.id == events[1].id)
        .values(hash_schema=audit.HASH_SCHEMA_LEGACY)
    )
    await db.commit()
    db.expire_all()
    ok, broken = await audit.verify_chain(db)
    assert not ok


@pytest.mark.skipif(
    not os.getenv("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is only configured for the disposable CI database",
)
def test_concurrent_appends_serialize_on_postgresql():
    """Many concurrent appends must produce a contiguous, gap-free sequence —
    the advisory lock serializes them and no append is lost or forked."""
    url = os.environ["TEST_POSTGRES_URL"]

    async def run() -> None:
        eng = create_async_engine(url)
        try:
            async with eng.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
            maker = async_sessionmaker(eng, expire_on_commit=False)

            async def one_append(i: int) -> None:
                async with maker() as session:
                    await audit.record(session, action=f"concurrent.{i}")
                    await session.commit()

            await asyncio.gather(*(one_append(i) for i in range(25)))

            async with maker() as session:
                seqs = (
                    await session.execute(
                        select(AuditEvent.seq).order_by(AuditEvent.seq)
                    )
                ).scalars().all()
                assert seqs == list(range(1, 26))
                ok, broken = await audit.verify_chain(session)
                assert ok, f"concurrent chain broken at {broken}"
            async with eng.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
        finally:
            await eng.dispose()

    asyncio.run(run())
