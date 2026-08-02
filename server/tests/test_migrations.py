# SPDX-License-Identifier: AGPL-3.0-only
"""Alembic baseline, forward-upgrade, and startup revision tests."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.schema_revision import (
    SchemaRevisionMismatch,
    ensure_schema_current,
    expected_schema_heads,
)
from scripts import adopt_v011_schema


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
        command_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(commands)")
        }
        operator_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(operators)")
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
    assert {
        "alembic_version",
        "agents",
        "commands",
        "audit_events",
        "monitoring_policies",
        "monitoring_policy_revisions",
        "maintenance_windows",
        "check_results",
        "alerts",
        "alert_observations",
    } <= tables
    assert "agent_completed_at" in command_columns
    assert {
        "script_execution_scope",
        "script_execution_scope_id",
    } <= operator_columns
    assert {
        "ux_clients_name_normalized",
        "ux_sites_client_name_normalized",
        "ux_monitoring_policies_scope_name_normalized",
    } <= indexes


def test_cli_prefers_dotenv_database_over_alembic_sample_url(tmp_path: Path):
    """The checked-in rmm:rmm URL is documentation, never a runtime default."""
    db_path = tmp_path / "dotenv.db"
    (tmp_path / ".env").write_text(
        f"DATABASE_URL={sqlite_url(db_path)}\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("ALEMBIC_DATABASE_URL", None)
    environment.pop("DATABASE_URL", None)
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(SERVER_ROOT), environment.get("PYTHONPATH")))
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(SERVER_ROOT / "alembic.ini"),
            "upgrade",
            "head",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(db_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    expected_head = ScriptDirectory.from_config(
        Config(str(SERVER_ROOT / "alembic.ini"))
    ).get_current_head()
    assert revision == (expected_head,)


def test_forward_repair_restores_schema_skipped_by_incorrect_stamp(tmp_path: Path):
    db_path = tmp_path / "stamped-debug.db"
    config = migration_config(sqlite_url(db_path))
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
            (
                "agent-1",
                "site-1",
                "hash",
                "PC1",
                "windows",
                "11",
                "0.1",
                "pending",
                now,
            ),
        )
        connection.execute(
            """INSERT INTO commands
               (id, agent_id, kind, payload, signature, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "command-1",
                "agent-1",
                "shell",
                "{}",
                "legacy-sig",
                "queued",
                now,
            ),
        )
        connection.execute(
            """INSERT INTO audit_events
               (id, ts, ts_iso, actor, action, detail, prev_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "audit-1",
                now,
                now,
                "system",
                "legacy.event",
                "{}",
                "0" * 64,
                "1" * 64,
            ),
        )
        connection.commit()

    # Reproduce the historical mistake: the revision marker moved to the
    # enrollment revision while schema changes 0002-0011 never ran.
    command.stamp(config, "0011")
    command.upgrade(config, "head")
    asyncio.run(_assert_current(sqlite_url(db_path)))

    with sqlite3.connect(db_path) as connection:
        agent_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(agents)")
        }
        command_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(commands)")
        }
        audit_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(audit_events)")
        }
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        agent_state = connection.execute(
            "SELECT command_envelope_versions, trust_state "
            "FROM agents WHERE id = 'agent-1'"
        ).fetchone()
        command_state = connection.execute(
            "SELECT envelope_version, status FROM commands WHERE id = 'command-1'"
        ).fetchone()
        audit_state = connection.execute(
            "SELECT seq, hash_schema FROM audit_events WHERE id = 'audit-1'"
        ).fetchone()

    assert {
        "command_envelope_versions",
        "trust_state",
        "trust_state_reason",
        "trust_state_changed_at",
        "trust_state_changed_by",
        "credential_fingerprint",
        "credential_issued_at",
        "credential_expires_at",
        "name",
        "architecture",
        "environment",
        "labels",
        "owner_user_id",
        "enrolled_by_token_id",
        "ip_address",
        "revoked_at",
    } <= agent_columns
    assert {
        "envelope_version",
        "schema_version",
        "issued_at",
        "nonce",
        "signing_key_id",
        "stdout_truncated",
        "stderr_truncated",
        "stdout_total_bytes",
        "stderr_total_bytes",
        "agent_completed_at",
    } <= command_columns
    assert {
        "seq",
        "hash_schema",
        "actor_user_id",
        "enrollment_token_id",
        "organization_id",
        "source_ip",
        "user_agent",
    } <= audit_columns
    assert "anchor_publications" in tables
    assert {"ux_commands_agent_nonce", "ux_audit_events_seq"} <= indexes
    assert json.loads(agent_state[0]) == []
    assert agent_state[1] == "active"
    assert command_state == ("legacy-unversioned", "expired")
    assert audit_state == (1, 1)


def test_exact_unversioned_v011_schema_is_adopted_and_upgraded(tmp_path: Path):
    db_path = tmp_path / "v011.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0001")

    now = "2026-07-27T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TABLE alembic_version")
        connection.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            ("client-v011", "v0.1.1 client", now),
        )
        connection.execute(
            "INSERT INTO sites (id, client_id, name, created_at) VALUES (?, ?, ?, ?)",
            ("site-v011", "client-v011", "Legacy site", now),
        )
        connection.execute(
            """INSERT INTO agents
               (id, site_id, token_hash, hostname, os, os_version,
                agent_version, status, enrolled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "agent-v011",
                "site-v011",
                "legacy-hash",
                "LEGACY-PC",
                "windows",
                "11",
                "0.1.1",
                "online",
                now,
            ),
        )
        connection.commit()

    assert (
        adopt_v011_schema.run(
            url,
            stamp=True,
            allow_test_dialect=True,
        )
        == 0
    )
    command.upgrade(config, "head")
    asyncio.run(_assert_current(url))

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT hostname, agent_version, trust_state "
            "FROM agents WHERE id = 'agent-v011'"
        ).fetchone()
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    assert row == ("LEGACY-PC", "0.1.1", "active")
    # Derived rather than hardcoded: the point of the assertion is that an
    # adopted legacy database lands on the *current* head, not on one specific
    # revision number that every later migration would have to come edit.
    assert revision == expected_schema_heads()


def test_normalized_name_migration_refuses_ambiguous_existing_rows(tmp_path: Path):
    db_path = tmp_path / "duplicate-names.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "0012")
    now = "2026-07-29T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            [
                ("client-a", "North Clinic", now),
                ("client-b", " north clinic ", now),
            ],
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="duplicate client group"):
        command.upgrade(config, "head")


def test_v011_adoption_rejects_schema_drift_without_stamping(tmp_path: Path):
    db_path = tmp_path / "drifted-v011.db"
    url = sqlite_url(db_path)
    config = migration_config(url)
    command.upgrade(config, "0001")
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TABLE alembic_version")
        connection.execute(
            "ALTER TABLE agents ADD COLUMN unreviewed_secret TEXT"
        )
        connection.commit()

    assert (
        adopt_v011_schema.run(
            url,
            stamp=True,
            allow_test_dialect=True,
        )
        == 1
    )
    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "alembic_version" not in tables


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
        envelope_version, status, schema_version, issued_at, nonce = connection.execute(
            "SELECT envelope_version, status, schema_version, issued_at, nonce "
            "FROM commands WHERE id = 'command-1'"
        ).fetchone()

    assert client_name == "Preserved client"
    assert json.loads(versions_raw) == []
    assert envelope_version == "legacy-unversioned"
    assert status == "expired"
    assert schema_version is None
    assert issued_at is None
    assert nonce is None


def test_command_v2_nonce_is_unique_per_agent(tmp_path: Path):
    db_path = tmp_path / "nonce.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "head")

    now = "2026-07-18T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            ("client-1", "Client", now),
        )
        connection.execute(
            "INSERT INTO sites (id, client_id, name, created_at) VALUES (?, ?, ?, ?)",
            ("site-1", "client-1", "HQ", now),
        )
        for agent_id in ("agent-1", "agent-2"):
            connection.execute(
                """INSERT INTO agents
                   (id, site_id, token_hash, hostname, os, os_version,
                    agent_version, status, enrolled_at, command_envelope_versions)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (agent_id, "site-1", agent_id, agent_id, "windows", "11", "0.2", "online", now, '["command-v2"]'),
            )
        command_values = (
            "shell", "{}", "sig", "command-v2", 1, now, "same_nonce_value_1234567890", "queued", now, now
        )
        connection.execute(
            """INSERT INTO commands
               (id, agent_id, kind, payload, signature, envelope_version,
                schema_version, issued_at, nonce, status, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("command-1", "agent-1", *command_values),
        )
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO commands
                   (id, agent_id, kind, payload, signature, envelope_version,
                    schema_version, issued_at, nonce, status, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("command-2", "agent-1", *command_values),
            )
        connection.rollback()

        # The same nonce on a different agent is not a replay in that agent's scope.
        connection.execute(
            """INSERT INTO commands
               (id, agent_id, kind, payload, signature, envelope_version,
                schema_version, issued_at, nonce, status, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("command-3", "agent-2", *command_values),
        )


def test_downgrade_policy_is_forward_only(tmp_path: Path):
    url = sqlite_url(tmp_path / "forward-only.db")
    config = migration_config(url)
    command.upgrade(config, "head")
    with pytest.raises(RuntimeError, match="forward-only"):
        command.downgrade(config, "0001")


def test_result_pending_status_is_supported_after_upgrade(tmp_path: Path):
    db_path = tmp_path / "result-pending.db"
    config = migration_config(sqlite_url(db_path))
    command.upgrade(config, "head")

    now = "2026-07-26T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
            ("client-r", "Client", now),
        )
        connection.execute(
            "INSERT INTO sites (id, client_id, name, created_at) VALUES (?, ?, ?, ?)",
            ("site-r", "client-r", "HQ", now),
        )
        connection.execute(
            """INSERT INTO agents
               (id, site_id, token_hash, hostname, os, os_version,
                agent_version, status, enrolled_at, command_envelope_versions,
                trust_state)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "agent-r",
                "site-r",
                "hash-r",
                "PC",
                "windows",
                "11",
                "0.3",
                "online",
                now,
                '["command-v3"]',
                "active",
            ),
        )
        connection.execute(
            """INSERT INTO commands
               (id, agent_id, kind, payload, signature, envelope_version,
                status, created_at, agent_completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "command-r",
                "agent-r",
                "shell",
                "{}",
                "sig",
                "command-v3",
                "result_pending",
                now,
                now,
            ),
        )
        status_value, completed = connection.execute(
            "SELECT status, agent_completed_at FROM commands WHERE id = 'command-r'"
        ).fetchone()
    assert status_value == "result_pending"
    assert completed is not None


def test_script_permission_is_default_deny_after_upgrade(tmp_path: Path):
    db_path = tmp_path / "script-permission.db"
    command.upgrade(migration_config(sqlite_url(db_path)), "head")

    now = "2026-07-27T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO operators
               (id, email, password_hash, role, disabled, token_generation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "operator-script",
                "script@nodelink.test",
                "hash",
                "operator",
                0,
                0,
                now,
            ),
        )
        initial = connection.execute(
            """SELECT script_execution_scope, script_execution_scope_id
               FROM operators WHERE id = 'operator-script'"""
        ).fetchone()
        connection.execute(
            """UPDATE operators
               SET script_execution_scope = 'site',
                   script_execution_scope_id = 'site-1'
               WHERE id = 'operator-script'"""
        )
        granted = connection.execute(
            """SELECT script_execution_scope, script_execution_scope_id
               FROM operators WHERE id = 'operator-script'"""
        ).fetchone()
    assert initial == (None, None)
    assert granted == ("site", "site-1")


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
