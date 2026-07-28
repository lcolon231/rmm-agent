# SPDX-License-Identifier: AGPL-3.0-only
"""Safely adopt an unversioned public-v0.1.1 database into Alembic.

The public v0.1.1 server used ``Base.metadata.create_all`` and therefore has
no ``alembic_version`` table. Alembic revision 0001 is its schema baseline,
but stamping an arbitrary unversioned database would skip migrations and can
produce silent corruption.

This command compares the complete table/column/key/index shape with the
reviewed v0.1.1 fingerprint. It stamps revision 0001 only when the fingerprint
matches exactly. The command never runs later migrations; run
``python -m alembic upgrade head`` after a successful adoption.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402
from sqlalchemy import (  # noqa: E402
    Boolean,
    DateTime,
    Enum,
    Float,
    Integer,
    JSON,
    String,
    Text,
    inspect,
)
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402


SERVER_ROOT = Path(__file__).resolve().parents[1]
BASELINE_REVISION = "0001"

# This is the schema emitted by public tag v0.1.1 (commit
# 7cc39f221acc2f717eaa62fe1404865e1a6bb046), represented by Alembic 0001.
# Column order is intentionally ignored; all semantically relevant membership
# is compared as sets.
V011_COLUMNS: dict[str, dict[str, bool]] = {
    "clients": {"id": False, "name": False, "created_at": False},
    "operators": {
        "id": False,
        "email": False,
        "password_hash": False,
        "role": False,
        "disabled": False,
        "token_generation": False,
        "created_at": False,
    },
    "sites": {
        "id": False,
        "client_id": False,
        "name": False,
        "created_at": False,
    },
    "enrollment_tokens": {
        "id": False,
        "site_id": False,
        "token_hash": False,
        "label": True,
        "max_uses": False,
        "uses": False,
        "revoked": False,
        "expires_at": True,
        "created_at": False,
    },
    "agents": {
        "id": False,
        "site_id": False,
        "token_hash": False,
        "hostname": False,
        "os": False,
        "os_version": False,
        "agent_version": False,
        "status": False,
        "last_seen_at": True,
        "enrolled_at": False,
        "inventory": True,
    },
    "heartbeats": {
        "id": False,
        "agent_id": False,
        "ts": False,
        "cpu_percent": False,
        "mem_percent": False,
        "disk_percent": False,
        "uptime_seconds": False,
        "logged_in_user": True,
    },
    "commands": {
        "id": False,
        "agent_id": False,
        "kind": False,
        "payload": False,
        "signature": False,
        "status": False,
        "exit_code": True,
        "stdout": True,
        "stderr": True,
        "created_at": False,
        "dispatched_at": True,
        "completed_at": True,
        "expires_at": True,
    },
    "audit_events": {
        "id": False,
        "ts": False,
        "ts_iso": False,
        "actor": False,
        "action": False,
        "agent_id": True,
        "detail": False,
        "prev_hash": False,
        "event_hash": False,
    },
    "audit_anchors": {
        "id": False,
        "created_at": False,
        "event_count": False,
        "last_event_id": False,
        "merkle_root": False,
    },
}

V011_PRIMARY_KEYS = {table: ("id",) for table in V011_COLUMNS}
V011_INDEXES = {
    ("agents", "ix_agents_token_hash", ("token_hash",), False),
    ("audit_events", "ix_audit_events_agent_id", ("agent_id",), False),
    ("audit_events", "ix_audit_events_event_hash", ("event_hash",), False),
    ("audit_events", "ix_audit_events_ts", ("ts",), False),
    ("commands", "ix_commands_agent_id", ("agent_id",), False),
    ("commands", "ix_commands_status", ("status",), False),
    (
        "enrollment_tokens",
        "ix_enrollment_tokens_token_hash",
        ("token_hash",),
        False,
    ),
    ("heartbeats", "ix_heartbeats_agent_id", ("agent_id",), False),
    ("heartbeats", "ix_heartbeats_ts", ("ts",), False),
    ("operators", "ix_operators_email", ("email",), True),
}
V011_FOREIGN_KEYS = {
    ("agents", ("site_id",), "sites", ("id",), "CASCADE"),
    ("commands", ("agent_id",), "agents", ("id",), "CASCADE"),
    ("enrollment_tokens", ("site_id",), "sites", ("id",), "CASCADE"),
    ("heartbeats", ("agent_id",), "agents", ("id",), "CASCADE"),
    ("sites", ("client_id",), "clients", ("id",), "CASCADE"),
}
V011_POSTGRES_TYPES = {
    "clients": {
        "id": "varchar:36",
        "name": "varchar:200",
        "created_at": "datetime:tz",
    },
    "operators": {
        "id": "varchar:36",
        "email": "varchar:320",
        "password_hash": "varchar:255",
        "role": "enum:operatorrole:readonly,operator,admin",
        "disabled": "boolean",
        "token_generation": "integer",
        "created_at": "datetime:tz",
    },
    "sites": {
        "id": "varchar:36",
        "client_id": "varchar:36",
        "name": "varchar:200",
        "created_at": "datetime:tz",
    },
    "enrollment_tokens": {
        "id": "varchar:36",
        "site_id": "varchar:36",
        "token_hash": "varchar:64",
        "label": "varchar:200",
        "max_uses": "integer",
        "uses": "integer",
        "revoked": "boolean",
        "expires_at": "datetime:tz",
        "created_at": "datetime:tz",
    },
    "agents": {
        "id": "varchar:36",
        "site_id": "varchar:36",
        "token_hash": "varchar:64",
        "hostname": "varchar:255",
        "os": "varchar:100",
        "os_version": "varchar:100",
        "agent_version": "varchar:50",
        "status": "enum:agentstatus:pending,online,offline",
        "last_seen_at": "datetime:tz",
        "enrolled_at": "datetime:tz",
        "inventory": "json",
    },
    "heartbeats": {
        "id": "varchar:36",
        "agent_id": "varchar:36",
        "ts": "datetime:tz",
        "cpu_percent": "float",
        "mem_percent": "float",
        "disk_percent": "float",
        "uptime_seconds": "integer",
        "logged_in_user": "varchar:255",
    },
    "commands": {
        "id": "varchar:36",
        "agent_id": "varchar:36",
        "kind": "enum:commandkind:powershell,shell,collect_inventory",
        "payload": "json",
        "signature": "text",
        "status": (
            "enum:commandstatus:"
            "queued,dispatched,running,succeeded,failed,expired"
        ),
        "exit_code": "integer",
        "stdout": "text",
        "stderr": "text",
        "created_at": "datetime:tz",
        "dispatched_at": "datetime:tz",
        "completed_at": "datetime:tz",
        "expires_at": "datetime:tz",
    },
    "audit_events": {
        "id": "varchar:36",
        "ts": "datetime:tz",
        "ts_iso": "varchar:40",
        "actor": "varchar:255",
        "action": "varchar:100",
        "agent_id": "varchar:36",
        "detail": "json",
        "prev_hash": "varchar:64",
        "event_hash": "varchar:64",
    },
    "audit_anchors": {
        "id": "varchar:36",
        "created_at": "datetime:tz",
        "event_count": "integer",
        "last_event_id": "varchar:36",
        "merkle_root": "varchar:64",
    },
}


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _normalized_type(value: Any) -> str:
    if isinstance(value, Enum):
        return f"enum:{value.name}:{','.join(value.enums)}"
    if isinstance(value, Text):
        return "text"
    if isinstance(value, String):
        return f"varchar:{value.length}"
    if isinstance(value, DateTime):
        return "datetime:tz" if value.timezone else "datetime:naive"
    if isinstance(value, Boolean):
        return "boolean"
    if isinstance(value, Integer):
        return "integer"
    if isinstance(value, Float):
        return "float"
    if isinstance(value, JSON):
        return "json"
    return f"unsupported:{type(value).__name__}"


def _actual_signature(connection: Any) -> dict[str, Any]:
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    views = set(inspector.get_view_names())
    columns = {
        table: {
            str(column["name"]): bool(column["nullable"])
            for column in inspector.get_columns(table)
        }
        for table in tables
    }
    column_types = {
        table: {
            str(column["name"]): _normalized_type(column["type"])
            for column in inspector.get_columns(table)
        }
        for table in tables
    }
    column_defaults = {
        table: {
            str(column["name"]): column.get("default")
            for column in inspector.get_columns(table)
        }
        for table in tables
    }
    primary_keys = {
        table: tuple(
            sorted(inspector.get_pk_constraint(table).get("constrained_columns") or ())
        )
        for table in tables
    }
    indexes = {
        (
            table,
            str(index["name"]),
            tuple(index.get("column_names") or ()),
            bool(index.get("unique")),
        )
        for table in tables
        for index in inspector.get_indexes(table)
        if index.get("name")
    }
    foreign_keys = {
        (
            table,
            tuple(key.get("constrained_columns") or ()),
            str(key.get("referred_table")),
            tuple(key.get("referred_columns") or ()),
            str((key.get("options") or {}).get("ondelete") or "").upper(),
        )
        for table in tables
        for key in inspector.get_foreign_keys(table)
    }
    check_constraints = {
        (table, str(item.get("name") or ""), str(item.get("sqltext") or ""))
        for table in tables
        for item in inspector.get_check_constraints(table)
    }
    unique_constraints = {
        (
            table,
            str(item.get("name") or ""),
            tuple(item.get("column_names") or ()),
        )
        for table in tables
        for item in inspector.get_unique_constraints(table)
    }
    return {
        "tables": tables,
        "views": views,
        "columns": columns,
        "column_types": column_types,
        "column_defaults": column_defaults,
        "primary_keys": primary_keys,
        "indexes": indexes,
        "foreign_keys": foreign_keys,
        "check_constraints": check_constraints,
        "unique_constraints": unique_constraints,
    }


def schema_mismatches(connection: Any) -> list[str]:
    """Return stable, secret-free reasons the database is not exact v0.1.1."""
    actual = _actual_signature(connection)
    expected_tables = set(V011_COLUMNS)
    failures: list[str] = []

    if "alembic_version" in actual["tables"]:
        failures.append("database is already Alembic-versioned")
    if actual["views"]:
        failures.append(f"unexpected views: {', '.join(sorted(actual['views']))}")
    actual_tables = actual["tables"] - {"alembic_version"}
    missing_tables = expected_tables - actual_tables
    extra_tables = actual_tables - expected_tables
    if missing_tables:
        failures.append(f"missing tables: {', '.join(sorted(missing_tables))}")
    if extra_tables:
        failures.append(f"unexpected tables: {', '.join(sorted(extra_tables))}")

    for table in sorted(expected_tables & actual_tables):
        expected_columns = V011_COLUMNS[table]
        actual_columns = actual["columns"][table]
        if expected_columns != actual_columns:
            missing = set(expected_columns) - set(actual_columns)
            extra = set(actual_columns) - set(expected_columns)
            changed = {
                name
                for name in set(expected_columns) & set(actual_columns)
                if expected_columns[name] != actual_columns[name]
            }
            parts = []
            if missing:
                parts.append(f"missing={','.join(sorted(missing))}")
            if extra:
                parts.append(f"unexpected={','.join(sorted(extra))}")
            if changed:
                parts.append(f"nullability={','.join(sorted(changed))}")
            failures.append(f"{table} columns differ ({'; '.join(parts)})")
        expected_pk = V011_PRIMARY_KEYS[table]
        if actual["primary_keys"][table] != expected_pk:
            failures.append(f"{table} primary key differs")
        if connection.dialect.name == "postgresql":
            if actual["column_types"][table] != V011_POSTGRES_TYPES[table]:
                failures.append(f"{table} column types differ")
            unexpected_defaults = {
                name: value
                for name, value in actual["column_defaults"][table].items()
                if value is not None
            }
            if unexpected_defaults:
                failures.append(f"{table} server defaults differ")

    if actual["indexes"] != V011_INDEXES:
        failures.append("index fingerprint differs")
    if actual["foreign_keys"] != V011_FOREIGN_KEYS:
        failures.append("foreign-key fingerprint differs")
    if actual["check_constraints"]:
        failures.append("check-constraint fingerprint differs")
    if actual["unique_constraints"]:
        failures.append("unique-constraint fingerprint differs")
    return failures


def _stamp_connection(connection: Any) -> None:
    config = Config(str(SERVER_ROOT / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    context = MigrationContext.configure(connection)
    context.stamp(script, BASELINE_REVISION)


async def inspect_database(
    database_url: str,
    *,
    stamp: bool,
) -> tuple[str, list[str]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            dialect = connection.dialect.name
            failures = await connection.run_sync(schema_mismatches)
            if not failures and stamp:
                await connection.run_sync(_stamp_connection)
        return dialect, failures
    finally:
        await engine.dispose()


def run(
    database_url: str,
    *,
    stamp: bool,
    evidence_output: Path | None = None,
    allow_test_dialect: bool = False,
) -> int:
    dialect, failures = asyncio.run(
        inspect_database(
            database_url,
            stamp=stamp,
        )
    )
    if dialect != "postgresql" and not allow_test_dialect:
        failures.append(
            f"unsupported database dialect {dialect}; production adoption requires PostgreSQL"
        )

    status = "rejected" if failures else ("adopted" if stamp else "verified")
    evidence = {
        "format": "nodelink-v011-schema-adoption",
        "version": 1,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "source_release": "v0.1.1",
        "source_commit": "7cc39f221acc2f717eaa62fe1404865e1a6bb046",
        "baseline_revision": BASELINE_REVISION,
        "database_dialect": dialect,
        "status": status,
        "stamped": bool(stamp and not failures),
        "failures": failures,
    }
    if evidence_output is not None:
        _atomic_write_json(evidence_output, evidence)

    if failures:
        for failure in failures:
            print(f"adopt-v011-schema: FAIL {failure}", file=sys.stderr)
        return 1
    action = "stamped at 0001" if stamp else "matches v0.1.1 baseline (dry run)"
    print(f"adopt-v011-schema: OK - database {action}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--database-url",
        help="async SQLAlchemy URL (prefer --database-url-env to avoid process-list exposure)",
    )
    source.add_argument(
        "--database-url-env",
        default="NODELINK_V011_DATABASE_URL",
        metavar="NAME",
        help=(
            "environment variable containing the async SQLAlchemy URL "
            "(default: NODELINK_V011_DATABASE_URL)"
        ),
    )
    parser.add_argument(
        "--stamp",
        action="store_true",
        help="stamp exact matches at revision 0001; omit for a read-only check",
    )
    parser.add_argument(
        "--evidence-output",
        type=Path,
        help="atomically write a redacted JSON adoption record",
    )
    args = parser.parse_args()
    database_url = args.database_url
    if database_url is None:
        database_url = os.getenv(args.database_url_env)
        if not database_url:
            parser.error(
                f"environment variable {args.database_url_env!r} is not configured"
            )
    raise SystemExit(
        run(
            database_url,
            stamp=args.stamp,
            evidence_output=args.evidence_output,
        )
    )


if __name__ == "__main__":
    main()
