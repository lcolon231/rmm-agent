# SPDX-License-Identifier: AGPL-3.0-only
"""Storage-growth retention and observability tests (issue #114).

Behavior under test:
  - prune deletes heartbeats older than the telemetry window and keeps recent
    ones
  - prune clears command stdout/stderr past the output window but keeps the
    command row and its accountability metadata (exit code, truncation totals)
  - prune NEVER touches audit events or anchors, and the hash chain still
    verifies afterwards
  - a retention setting of 0 disables that class's pruning
  - storage_status reports per-class counts and raises threshold-breach flags

Run just this file:  pytest tests/test_retention.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_retention.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.main import app  # noqa: E402
from app.core import audit, retention  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    Client,
    Command,
    CommandKind,
    CommandStatus,
    Heartbeat,
    Operator,
    OperatorRole,
    Site,
)

NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def _agent(db) -> str:
    client = Client(name="C")
    db.add(client)
    await db.flush()
    site = Site(client_id=client.id, name="S")
    db.add(site)
    await db.flush()
    agent = Agent(site_id=site.id, token_hash="h", hostname="H")
    db.add(agent)
    await db.flush()
    return agent.id


def _heartbeat(agent_id, age_days) -> Heartbeat:
    return Heartbeat(agent_id=agent_id, ts=NOW - timedelta(days=age_days))


def _command(agent_id, age_days, with_output=True) -> Command:
    return Command(
        agent_id=agent_id,
        kind=CommandKind.shell,
        envelope_version="command-v2",
        status=CommandStatus.succeeded,
        exit_code=0,
        stdout="captured-output" if with_output else None,
        stderr="err" if with_output else None,
        stdout_total_bytes=15,
        completed_at=NOW - timedelta(days=age_days),
    )


@pytest.mark.asyncio
async def test_prune_deletes_old_heartbeats_keeps_recent(db):
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=40))  # older than 30d window
    db.add(_heartbeat(agent_id, age_days=5))   # recent
    await db.commit()

    result = await retention.prune_expired(
        db, settings, now=NOW
    )
    await db.commit()
    assert result.heartbeats_deleted == 1
    remaining = (await db.execute(select(func.count()).select_from(Heartbeat))).scalar_one()
    assert remaining == 1


@pytest.mark.asyncio
async def test_prune_clears_old_output_keeps_metadata_and_recent(db):
    agent_id = await _agent(db)
    old = _command(agent_id, age_days=120)   # older than 90d output window
    recent = _command(agent_id, age_days=10)
    db.add(old)
    db.add(recent)
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert result.command_outputs_cleared == 1

    await db.refresh(old)
    await db.refresh(recent)
    # Old command: text cleared, row + metadata intact.
    assert old.stdout is None and old.stderr is None
    assert old.exit_code == 0 and old.stdout_total_bytes == 15
    assert old.status == CommandStatus.succeeded
    # Recent command: untouched.
    assert recent.stdout == "captured-output"

    # Idempotent: a second prune clears nothing more.
    again = await retention.prune_expired(db, settings, now=NOW)
    assert again.command_outputs_cleared == 0


@pytest.mark.asyncio
async def test_prune_never_touches_audit_and_chain_verifies(db):
    await audit.record(db, action="test.one", detail={"a": 1})
    await audit.record(db, action="test.two", detail={"b": 2})
    await db.commit()
    before = (await db.execute(select(func.count()).select_from(AuditEvent))).scalar_one()

    # Prune with everything expired.
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=999))
    await db.commit()
    await retention.prune_expired(db, settings, now=NOW)
    await db.commit()

    after = (await db.execute(select(func.count()).select_from(AuditEvent))).scalar_one()
    assert after == before  # audit untouched
    ok, broken = await audit.verify_chain(db)
    assert ok, f"chain broke at {broken}"


@pytest.mark.asyncio
async def test_zero_retention_disables_pruning(db, monkeypatch):
    monkeypatch.setattr(settings, "telemetry_retention_days", 0)
    monkeypatch.setattr(settings, "command_output_retention_days", 0)
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=999))
    db.add(_command(agent_id, age_days=999))
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert result.heartbeats_deleted == 0
    assert result.command_outputs_cleared == 0


@pytest.mark.asyncio
async def test_storage_status_counts_and_alert_flags(db, monkeypatch):
    agent_id = await _agent(db)
    for _ in range(3):
        db.add(_heartbeat(agent_id, age_days=1))
    db.add(_command(agent_id, age_days=1))
    await audit.record(db, action="test.audit")
    await db.commit()

    # No breach with default thresholds.
    status = await retention.storage_status(db, settings)
    assert status["heartbeats"]["count"] == 3
    assert status["commands"]["count"] == 1
    assert status["commands"]["with_output"] == 1
    assert status["audit"]["event_count"] == 1
    assert status["alert"] is False

    # Lower the heartbeat threshold to force a breach.
    monkeypatch.setattr(settings, "heartbeat_backlog_alert", 2)
    breached = await retention.storage_status(db, settings)
    assert breached["heartbeats"]["backlog_alert"] is True
    assert breached["alert"] is True


@pytest_asyncio.fixture
async def api_client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(email="ro@nodelink.test", password_hash=hash_password("pw"),
                        role=OperatorRole.readonly))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post("/auth/login", json={"email": "ro@nodelink.test", "password": "pw"})
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


@pytest.mark.asyncio
async def test_storage_status_endpoint_readable_by_operator(api_client):
    r = await api_client.get("/storage/status")
    assert r.status_code == 200
    body = r.json()
    for key in ("heartbeats", "commands", "audit", "anchor_publication", "disk", "alert"):
        assert key in body
    assert "telemetry_retention_days" in body["retention_policy"]
