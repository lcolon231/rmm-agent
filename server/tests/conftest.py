# SPDX-License-Identifier: AGPL-3.0-only
"""Shared PostgreSQL fixtures (issue #286).

SQLite serializes writers and ignores ``SELECT ... FOR UPDATE`` and advisory
locks, so row-lock and constraint races only mean something on PostgreSQL.
Tests marked ``postgres`` run against the disposable server in
``TEST_POSTGRES_URL`` (the CI ``server`` job's postgres:16 service) and are
skipped without it.

Each test gets its own throwaway database rather than a schema: alembic's
asyncpg URL cannot carry a ``search_path``, and a database also isolates
migration tests completely. The database named by ``TEST_POSTGRES_URL`` is
never written; ``test_fresh_postgresql_install_reaches_head`` requires it to
start empty.

Nothing here imports ``app`` at module import time: test modules pick the
SQLite ``DATABASE_URL`` with ``os.environ.setdefault`` before importing the
app, and an earlier import from this file would win that race.
"""
from __future__ import annotations

import asyncio
import os
import time
from uuid import uuid4

import pytest
import pytest_asyncio

POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "postgres: needs the disposable PostgreSQL in TEST_POSTGRES_URL; "
        "skipped without it",
    )


def pytest_collection_modifyitems(config, items):
    if POSTGRES_URL:
        return
    skip = pytest.mark.skip(reason="TEST_POSTGRES_URL is not set")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip)


def _admin_dsn() -> str:
    from sqlalchemy.engine import make_url

    return (
        make_url(POSTGRES_URL)
        .set(drivername="postgresql")
        .render_as_string(hide_password=False)
    )


async def _admin(statement: str) -> None:
    import asyncpg

    connection = await asyncpg.connect(_admin_dsn())
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


@pytest.fixture
def pg_database_factory():
    """Callable returning the URL of a fresh, empty PostgreSQL database.

    Every database it creates is dropped after the test. Synchronous on
    purpose: alembic's async ``env.py`` calls ``asyncio.run``, which cannot
    nest inside a running loop, so migration tests are sync tests.
    """
    from sqlalchemy.engine import make_url

    created: list[str] = []

    def create() -> str:
        name = f"nodelink_t_{uuid4().hex[:16]}"
        asyncio.run(_admin(f'CREATE DATABASE "{name}"'))
        created.append(name)
        return make_url(POSTGRES_URL).set(database=name).render_as_string(
            hide_password=False
        )

    try:
        yield create
    finally:
        for name in created:
            asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest.fixture
def pg_database_url(pg_database_factory):
    """URL of one fresh, empty PostgreSQL database, dropped after the test."""
    return pg_database_factory()


@pytest_asyncio.fixture
async def pg_engine(pg_database_url):
    """Async engine on a fresh database holding the ORM schema."""
    from sqlalchemy.ext.asyncio import create_async_engine

    import app.models.models  # noqa: F401  (registers every table)
    from app.core.database import Base

    engine = create_async_engine(pg_database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


async def wait_for_lock_waiters(engine, count: int, timeout: float = 10.0) -> None:
    """Block until ``count`` other backends are waiting on a lock.

    Race tests use this as their barrier. A test holds a lock in its own
    transaction, starts the competing requests, and waits here until all of
    them are parked behind that lock (a row lock, a unique-index insert, or the
    audit advisory lock) before releasing it. That way both requests have
    passed their application-level checks before either one commits, and the
    race happens on every run rather than only when the scheduler cooperates.
    """
    from sqlalchemy import text

    deadline = time.monotonic() + timeout
    waiting = 0
    while time.monotonic() < deadline:
        async with engine.connect() as connection:
            waiting = await connection.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND wait_event_type = 'Lock' "
                    "AND pid <> pg_backend_pid()"
                )
            )
        if waiting >= count:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(
        f"expected {count} backend(s) waiting on a lock, saw {waiting}"
    )
