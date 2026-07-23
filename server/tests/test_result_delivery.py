# SPDX-License-Identifier: AGPL-3.0-only
"""Idempotent command-result delivery tests (issue #113, server side).

Behavior under test:
  - a completed result can be delivered more than once (at-least-once delivery);
    duplicates are acknowledged (204) without corrupting the recorded result
  - a duplicate delivery does not append a second command.completed audit event
  - the first delivered result wins; a later duplicate carrying different bytes
    does not overwrite it

Run just this file:  pytest tests/test_result_delivery.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_result_delivery.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    CommandStatus,
    Operator,
    OperatorRole,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(
            email="op@nodelink.test", password_hash=hash_password("pw"),
            role=OperatorRole.operator, can_execute_scripts=True,
        ))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post("/auth/login", json={"email": "op@nodelink.test", "password": "pw"})
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enroll(c):
    cl = (await c.post("/clients", json={"name": "C"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "S"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5})).json()
    enr = (await c.post("/enroll", json={
        "enrollment_token": et["token"], "hostname": "H", "os": "windows",
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
    })).json()
    return enr["agent_id"], enr["agent_token"]


async def _dispatch_and_pick_up(c, agent_id, token) -> str:
    await c.post(f"/agents/{agent_id}/commands", json={"kind": "shell", "payload": {"script": "echo hi"}})
    beat = await c.post(
        "/heartbeat",
        json={"supported_command_envelope_versions": [COMMAND_ENVELOPE_V2]},
        headers={"Authorization": f"Bearer {token}"},
    )
    return beat.json()["pending_commands"][0]["id"]


async def _submit(c, cmd_id, token, exit_code=0, stdout="ok"):
    return await c.post(
        f"/commands/{cmd_id}/result",
        json={"exit_code": exit_code, "stdout": stdout},
        headers={"Authorization": f"Bearer {token}"},
    )


async def _count_completed_events(cmd_id: str) -> int:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(AuditEvent).where(AuditEvent.action == "command.completed")
        )).scalars().all()
    return sum(1 for r in rows if r.detail.get("command_id") == cmd_id)


@pytest.mark.asyncio
async def test_duplicate_delivery_is_idempotent(client):
    agent_id, token = await _enroll(client)
    cmd_id = await _dispatch_and_pick_up(client, agent_id, token)

    first = await _submit(client, cmd_id, token, exit_code=0, stdout="real-output")
    assert first.status_code == 204

    # The agent, having missed the ack, retries the same result.
    dup = await _submit(client, cmd_id, token, exit_code=0, stdout="real-output")
    assert dup.status_code == 204

    # Exactly one completion event was recorded.
    assert await _count_completed_events(cmd_id) == 1


@pytest.mark.asyncio
async def test_first_result_wins_over_late_duplicate(client):
    agent_id, token = await _enroll(client)
    cmd_id = await _dispatch_and_pick_up(client, agent_id, token)

    await _submit(client, cmd_id, token, exit_code=0, stdout="first-and-authoritative")
    # A later duplicate carrying different bytes must not overwrite the record.
    await _submit(client, cmd_id, token, exit_code=1, stdout="tampered")

    async with AsyncSessionLocal() as db:
        cmd = (await db.execute(select(Command).where(Command.id == cmd_id))).scalar_one()
        assert cmd.status == CommandStatus.succeeded
        assert cmd.exit_code == 0
        assert cmd.stdout == "first-and-authoritative"


@pytest.mark.asyncio
async def test_terminal_command_count_unchanged_by_duplicate(client):
    agent_id, token = await _enroll(client)
    cmd_id = await _dispatch_and_pick_up(client, agent_id, token)
    await _submit(client, cmd_id, token)

    before = None
    async with AsyncSessionLocal() as db:
        before = (await db.execute(
            select(func.count()).select_from(Command).where(Command.status == CommandStatus.succeeded)
        )).scalar_one()
    await _submit(client, cmd_id, token)
    async with AsyncSessionLocal() as db:
        after = (await db.execute(
            select(func.count()).select_from(Command).where(Command.status == CommandStatus.succeeded)
        )).scalar_one()
    assert before == after == 1
