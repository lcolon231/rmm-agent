# SPDX-License-Identifier: AGPL-3.0-only
"""Local dev seed guard and SQL echo setting (docs/LOCAL-E2E.md).

The seed drops every table, so the guard is the only thing standing between a
mistyped DATABASE_URL and a wiped database.

Run just this file:  pytest tests/test_dev_seed.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_dev_seed.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402

from app.core.config import Settings  # noqa: E402
from scripts.dev_seed import SCENARIOS, refuse_reason  # noqa: E402

SQLITE = "sqlite+aiosqlite:///./dev.db"


def test_local_sqlite_in_development_is_allowed():
    assert refuse_reason(SQLITE, "development") is None


@pytest.mark.parametrize("url", [
    "postgresql+asyncpg://rmm:rmm@localhost:5432/rmm",
    "postgresql://postgres.ref:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres",
    "postgres://u:p@db.internal/rmm",
])
def test_non_sqlite_database_is_refused(url):
    assert refuse_reason(url, "development") is not None


@pytest.mark.parametrize("environment", ["production", "Production", "staging"])
def test_non_development_environment_is_refused(environment):
    assert refuse_reason(SQLITE, environment) is not None


def test_retention_scenario_is_registered():
    assert "retention" in SCENARIOS


def test_sql_echo_is_independent_of_debug():
    assert Settings(debug=True).sql_echo is False
    assert Settings(debug=False, sql_echo=True).sql_echo is True
