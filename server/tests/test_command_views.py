# SPDX-License-Identifier: AGPL-3.0-only
"""Operator-facing command history and detail views (issue #32).

Covers pagination bounds, the bounded result/truncation evidence exposed by
the detail route, effective-expiry reporting ahead of the heartbeat sweep,
scope isolation between agents, and readonly access to the read routes.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_rmm.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import AuditEvent, Command, Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="views@nodelink.test",
                password_hash=hash_password("views-password"),
                role=OperatorRole.operator,
            )
        )
        db.add(
            Operator(
                email="ro@nodelink.test",
                password_hash=hash_password("ro-password"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "views@nodelink.test", "password": "views-password"},
        )
        c.headers.update(
            {"Authorization": f"Bearer {login.json()['access_token']}"}
        )
        yield c
    await engine.dispose()


async def _enroll(c) -> tuple[str, str]:
    """Return (agent_id, agent_token)."""
    cl = (await c.post("/clients", json={"name": "Clinic"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": "PC1",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            },
        )
    ).json()
    return enr["agent_id"], enr["agent_token"]


async def _dispatch(c, agent_id: str, script: str, ttl: int = 300) -> dict:
    r = await c.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": script}, "ttl_seconds": ttl},
    )
    assert r.status_code == 200
    return r.json()


@pytest.mark.asyncio
async def test_history_paginates_newest_first(client):
    agent_id, _ = await _enroll(client)
    ids = [(await _dispatch(client, agent_id, f"echo {i}"))["id"] for i in range(3)]

    page1 = (
        await client.get(f"/agents/{agent_id}/commands?page=1&page_size=2")
    ).json()
    assert page1["total"] == 3
    assert page1["page"] == 1
    assert page1["page_size"] == 2
    assert page1["outstanding"] == 3
    assert page1["outstanding_limit"] >= 1
    assert len(page1["items"]) == 2

    page2 = (
        await client.get(f"/agents/{agent_id}/commands?page=2&page_size=2")
    ).json()
    assert len(page2["items"]) == 1
    listed = [item["id"] for item in page1["items"] + page2["items"]]
    assert set(listed) == set(ids)
    # Newest first, and the oldest dispatch lands on the last page.
    assert listed[-1] == ids[0]

    # History rows carry status evidence but never result streams.
    assert "stdout" not in page1["items"][0]
    assert page1["items"][0]["status"] == "queued"

    # Pagination bounds are enforced, not clamped silently.
    assert (
        await client.get(f"/agents/{agent_id}/commands?page_size=101")
    ).status_code == 422
    assert (
        await client.get(f"/agents/{agent_id}/commands?page=0")
    ).status_code == 422


@pytest.mark.asyncio
async def test_detail_exposes_envelope_and_bounded_result(client):
    agent_id, token = await _enroll(client)
    cmd = await _dispatch(client, agent_id, "echo out")
    auth = {"Authorization": f"Bearer {token}"}

    # Agent picks the command up and reports a truncated result.
    hb = await client.post(
        "/heartbeat",
        json={
            "cpu_percent": 1.0,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
        headers=auth,
    )
    assert [c["id"] for c in hb.json()["pending_commands"]] == [cmd["id"]]
    r = await client.post(
        f"/commands/{cmd['id']}/result",
        json={
            "exit_code": 0,
            "stdout": "captured",
            "stderr": "",
            "stdout_truncated": True,
            "stderr_truncated": False,
            "stdout_total_bytes": 999_999,
            "stderr_total_bytes": 0,
        },
        headers=auth,
    )
    assert r.status_code == 204

    detail = (
        await client.get(f"/agents/{agent_id}/commands/{cmd['id']}")
    ).json()
    assert detail["status"] == "succeeded"
    assert detail["exit_code"] == 0
    assert detail["stdout"] == "captured"
    assert detail["stdout_truncated"] is True
    assert detail["stdout_total_bytes"] == 999_999
    assert detail["payload"] == {"script": "echo out"}
    # Signed-envelope evidence is part of the operator record.
    assert detail["envelope_version"] == COMMAND_ENVELOPE_V2
    assert detail["schema_version"] == 1
    assert detail["nonce"] == cmd["nonce"]
    assert detail["signature"] == cmd["signature"]
    assert detail["issued_at"] == cmd["issued_at"]
    assert detail["expires_at"] == cmd["expires_at"]
    assert detail["dispatched_at"] is not None
    assert detail["completed_at"] is not None

    # Reading a command's captured output is itself audited.
    async with AsyncSessionLocal() as db:
        ev = (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == "command_detail.viewed"
                )
            )
        ).scalars().all()
    assert len(ev) == 1
    assert ev[0].actor == "views@nodelink.test"
    assert ev[0].detail["command_id"] == cmd["id"]


@pytest.mark.asyncio
async def test_expired_work_reports_expired_before_heartbeat_sweep(client):
    agent_id, _ = await _enroll(client)
    cmd = await _dispatch(client, agent_id, "echo late")

    # Backdate expiry so the stored row is still queued but the window passed.
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Command).where(Command.id == cmd["id"]))
        ).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        await db.commit()

    listed = (await client.get(f"/agents/{agent_id}/commands")).json()
    assert listed["items"][0]["status"] == "expired"
    detail = (
        await client.get(f"/agents/{agent_id}/commands/{cmd['id']}")
    ).json()
    assert detail["status"] == "expired"

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Command).where(Command.id == cmd["id"]))
        ).scalar_one()
        # The view reported expiry without mutating the stored row.
        assert row.status.value == "queued"


@pytest.mark.asyncio
async def test_history_and_detail_are_scoped_to_the_agent(client):
    agent_a, _ = await _enroll(client)
    agent_b, _ = await _enroll(client)
    cmd = await _dispatch(client, agent_a, "echo scoped")

    r = await client.get(f"/agents/{agent_b}/commands/{cmd['id']}")
    assert r.status_code == 404
    assert (await client.get("/agents/missing/commands")).status_code == 404
    assert (
        await client.get(f"/agents/{agent_a}/commands/missing")
    ).status_code == 404


@pytest.mark.asyncio
async def test_readonly_can_view_but_not_dispatch(client):
    agent_id, _ = await _enroll(client)
    cmd = await _dispatch(client, agent_id, "echo ro")

    login = await client.post(
        "/auth/login", json={"email": "ro@nodelink.test", "password": "ro-password"}
    )
    ro = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert (
        await client.get(f"/agents/{agent_id}/commands", headers=ro)
    ).status_code == 200
    assert (
        await client.get(f"/agents/{agent_id}/commands/{cmd['id']}", headers=ro)
    ).status_code == 200
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo nope"}},
        headers=ro,
    )
    assert r.status_code == 403
