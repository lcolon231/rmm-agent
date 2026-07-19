# SPDX-License-Identifier: AGPL-3.0-only
"""Per-agent command concurrency and admission tests (issue #20).

Behavior under test:
  - dispatch is admitted up to max_outstanding_commands_per_agent; the next is
    refused 429 with a structured code, and freeing an outstanding slot
    (completion or expiry) admits again
  - terminal commands (succeeded/failed/expired) do not count against the cap
  - a heartbeat hands out at most max_commands_per_heartbeat commands, oldest
    first (FIFO), and the remainder drain on subsequent beats
  - the cap is per-agent (one agent full does not block another)

Run just this file:  pytest tests/test_command_admission.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_admission.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client(monkeypatch):
    # Small limits keep the tests fast and legible.
    monkeypatch.setattr(settings, "max_outstanding_commands_per_agent", 3)
    monkeypatch.setattr(settings, "max_commands_per_heartbeat", 2)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="adm@nodelink.test",
                password_hash=hash_password("pw"),
                role=OperatorRole.operator,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post("/auth/login", json={"email": "adm@nodelink.test", "password": "pw"})
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enroll(c) -> tuple[str, str]:
    cl = (await c.post("/clients", json={"name": "Adm Clinic"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 10})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": "PC-ADM",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            },
        )
    ).json()
    return enr["agent_id"], enr["agent_token"]


async def _dispatch(c, agent_id, script="echo hi"):
    return await c.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": script}},
    )


async def _beat(c, token):
    return await c.post(
        "/heartbeat",
        json={"supported_command_envelope_versions": [COMMAND_ENVELOPE_V2]},
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.asyncio
async def test_admission_caps_outstanding_commands(client):
    agent_id, token = await _enroll(client)

    for _ in range(3):  # limit is 3
        assert (await _dispatch(client, agent_id)).status_code == 200

    r = await _dispatch(client, agent_id)
    assert r.status_code == 429
    detail = r.json()["detail"]
    assert detail["code"] == "agent_command_queue_full"
    assert detail["limit"] == 3
    assert detail["outstanding"] == 3


@pytest.mark.asyncio
async def test_completing_a_command_frees_a_slot(client):
    agent_id, token = await _enroll(client)
    for _ in range(3):
        await _dispatch(client, agent_id)
    assert (await _dispatch(client, agent_id)).status_code == 429

    # Pick up one command and report it complete -> it becomes terminal.
    beat = await _beat(client, token)
    cmd_id = beat.json()["pending_commands"][0]["id"]
    r = await client.post(
        f"/commands/{cmd_id}/result",
        json={"exit_code": 0, "stdout": "ok"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 204

    # A slot is free again.
    assert (await _dispatch(client, agent_id)).status_code == 200


@pytest.mark.asyncio
async def test_heartbeat_batch_is_bounded_and_fifo(client):
    agent_id, token = await _enroll(client)
    # Raise the outstanding cap for this test so we can queue 5.
    settings.max_outstanding_commands_per_agent = 10
    ids = []
    for i in range(5):
        r = await _dispatch(client, agent_id, script=f"echo {i}")
        ids.append(r.json()["id"])

    # First beat delivers exactly the batch size (2), oldest first.
    first = await _beat(client, token)
    got1 = [c["id"] for c in first.json()["pending_commands"]]
    assert got1 == ids[:2]

    # Second beat delivers the next 2, then the last 1.
    got2 = [c["id"] for c in (await _beat(client, token)).json()["pending_commands"]]
    assert got2 == ids[2:4]
    got3 = [c["id"] for c in (await _beat(client, token)).json()["pending_commands"]]
    assert got3 == ids[4:]


@pytest.mark.asyncio
async def test_limit_is_per_agent(client):
    a1, _ = await _enroll(client)
    a2, _ = await _enroll(client)
    for _ in range(3):
        await _dispatch(client, a1)
    assert (await _dispatch(client, a1)).status_code == 429
    # A different agent is unaffected.
    assert (await _dispatch(client, a2)).status_code == 200
