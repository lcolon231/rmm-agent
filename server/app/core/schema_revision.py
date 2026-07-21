# SPDX-License-Identifier: AGPL-3.0-only
"""Production startup guard for Alembic schema revision compatibility."""
from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncEngine


class SchemaRevisionMismatch(RuntimeError):
    pass


def alembic_config() -> Config:
    return Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))


def expected_schema_heads() -> tuple[str, ...]:
    return tuple(sorted(ScriptDirectory.from_config(alembic_config()).get_heads()))


async def current_schema_heads(engine: AsyncEngine) -> tuple[str, ...]:
    async with engine.connect() as connection:
        return await connection.run_sync(
            lambda sync_connection: tuple(
                sorted(MigrationContext.configure(sync_connection).get_current_heads())
            )
        )


async def ensure_schema_current(engine: AsyncEngine) -> None:
    expected = expected_schema_heads()
    current = await current_schema_heads(engine)
    if current != expected:
        current_label = ", ".join(current) if current else "unversioned"
        expected_label = ", ".join(expected)
        raise SchemaRevisionMismatch(
            "Database schema revision mismatch: "
            f"current={current_label}; expected={expected_label}. "
            "Run 'alembic upgrade head' before starting the server."
        )
