# SPDX-License-Identifier: AGPL-3.0-only
"""Alembic baseline, forward-upgrade, and startup revision tests."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.schema_revision import SchemaRevisionMismatch, ensure_schema_current


SERVER_ROOT = Path(__file__).resolve().parents[1]


def migration_config(url: str) -> Config:
    config = Config(str(SERVER_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    config.attributes["prefer_configured_url"] = True
    return config


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


async def _assert_current(url: str) -> None:
    engine = create_async_engine(url)
    try:
        await ensure_schema_current(engine)
    finally:
        await engine.dispose()


def test_fresh_database_upgrades_to_head(tmp_path: Path):
    url = sqlite_url(tmp_path / "fresh.db")
    command.upgrade(migration_config(url), "head")
    asyncio.run(_assert_current(url))

    with sqlite3.connect(tmp_path / "fresh.db") as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {"alembic_version", "agents", "commands", "audit_events"} <= tables


def test_upgrade_from_baseline_preserves_rows_and_expires_legacy_queue(tmp_path: Path):
    db_path = tmp_path / "upgrade.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0001")

    now = "2026-07-18T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            ("client-1", "Preserved client", now),
        )
        connection.execute(
            "INSERT INTO sites (id, client_id, name, created_at) VALUES (?, ?, ?, ?)",
            ("site-1", "client-1", "HQ", now),
        )
        connection.execute(
            """INSERT INTO agents
               (id, site_id, token_hash, hostname, os, os_version,
                agent_version, status, enrolled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("agent-1", "site-1", "hash", "PC1", "windows", "11", "0.1", "pending", now),
        )
        connection.execute(
            """INSERT INTO commands
               (id, agent_id, kind, payload, signature, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("command-1", "agent-1", "shell", "{}", "legacy-sig", "queued", now),
        )
        connection.commit()

    command.upgrade(config, "head")

    with sqlite3.connect(db_path) as connection:
        client_name = connection.execute(
            "SELECT name FROM clients WHERE id = 'client-1'"
        ).fetchone()[0]
        versions_raw = connection.execute(
            "SELECT command_envelope_versions FROM agents WHERE id = 'agent-1'"
        ).fetchone()[0]
        envelope_version, status = connection.execute(
            "SELECT envelope_version, status FROM commands WHERE id = 'command-1'"
        ).fetchone()

    assert client_name == "Preserved client"
    assert json.loads(versions_raw) == []
    assert envelope_version == "legacy-unversioned"
    assert status == "expired"


def test_downgrade_policy_is_forward_only(tmp_path: Path):
    url = sqlite_url(tmp_path / "forward-only.db")
    config = migration_config(url)
    command.upgrade(config, "head")
    with pytest.raises(RuntimeError, match="forward-only"):
        command.downgrade(config, "0001")


def test_unversioned_database_fails_startup_revision_check(tmp_path: Path):
    url = sqlite_url(tmp_path / "unversioned.db")
    with pytest.raises(SchemaRevisionMismatch, match="current=unversioned"):
        asyncio.run(_assert_current(url))


def test_behind_and_unknown_future_revisions_fail_startup_check(tmp_path: Path):
    db_path = tmp_path / "mismatch.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0001")
    with pytest.raises(SchemaRevisionMismatch, match="current=0001"):
        asyncio.run(_assert_current(url))

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE alembic_version SET version_num = 'future-revision'"
        )
        connection.commit()
    with pytest.raises(SchemaRevisionMismatch, match="current=future-revision"):
        asyncio.run(_assert_current(url))


@pytest.mark.skipif(
    not os.getenv("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL is only configured for the disposable CI database",
)
def test_fresh_postgresql_install_reaches_head():
    url = os.environ["TEST_POSTGRES_URL"]

    async def assert_empty() -> None:
        engine = create_async_engine(url)
        try:
            async with engine.connect() as connection:
                tables = await connection.run_sync(
                    lambda sync_connection: inspect(sync_connection).get_table_names()
                )
            assert tables == [], "TEST_POSTGRES_URL must point to an empty disposable database"
        finally:
            await engine.dispose()

    asyncio.run(assert_empty())
    command.upgrade(migration_config(url), "head")
    asyncio.run(_assert_current(url))
