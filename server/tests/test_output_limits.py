# SPDX-License-Identifier: AGPL-3.0-only
"""Command output limit tests (issue #19).

Behavior under test:
  - results at the exact byte boundary are accepted; one byte over a stream
    cap or the combined cap is rejected 422 without being stored
  - limits count BYTES, not characters (multibyte content)
  - truncation metadata is persisted on the command, exposed via the API,
    and recorded in the command.completed audit detail
  - older agents that send no truncation fields leave them NULL (unknown)
  - dispatch refuses payloads over the 64 KiB cap

Run just this file:  pytest tests/test_output_limits.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_output_limits.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.schemas.schemas import (  # noqa: E402
    MAX_COMMAND_PAYLOAD_BYTES,
    MAX_RESULT_COMBINED_BYTES,
    MAX_RESULT_STREAM_BYTES,
)
from app.models.models import AuditEvent, Command, Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="limits@nodelink.test",
                password_hash=hash_password("limits-pass"),
                role=OperatorRole.operator,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "limits@nodelink.test", "password": "limits-pass"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enrolled_command(c) -> tuple[str, str, str]:
    """Provision, enroll, dispatch one command, pick it up. Returns
    (agent_token, command_id, agent_id)."""
    cl = (await c.post("/clients", json={"name": "Limit Clinic"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": "PC-LIM",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            },
        )
    ).json()
    cmd = (
        await c.post(
            f"/agents/{enr['agent_id']}/commands",
            json={"kind": "shell", "payload": {"script": "echo hi"}},
        )
    ).json()
    beat = await c.post(
        "/heartbeat",
        json={"supported_command_envelope_versions": [COMMAND_ENVELOPE_V2]},
        headers={"Authorization": f"Bearer {enr['agent_token']}"},
    )
    assert [x["id"] for x in beat.json()["pending_commands"]] == [cmd["id"]]
    return enr["agent_token"], cmd["id"], enr["agent_id"]


async def _post_result(c, token, command_id, body):
    return await c.post(
        f"/commands/{command_id}/result",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.asyncio
async def test_exact_boundary_accepted_and_truncation_persisted(client):
    token, cmd_id, _agent_id = await _enrolled_command(client)
    body = {
        "exit_code": 0,
        "stdout": "x" * MAX_RESULT_STREAM_BYTES,
        "stderr": "",
        "stdout_truncated": True,
        "stderr_truncated": False,
        "stdout_total_bytes": 10_000_000_000,  # >32-bit to prove BigInteger
        "stderr_total_bytes": 0,
    }
    r = await _post_result(client, token, cmd_id, body)
    assert r.status_code == 204

    async with AsyncSessionLocal() as db:
        cmd = (
            await db.execute(select(Command).where(Command.id == cmd_id))
        ).scalar_one()
    assert cmd.stdout_truncated is True
    assert cmd.stderr_truncated is False
    assert cmd.stdout_total_bytes == 10_000_000_000
    assert len(cmd.stdout) == MAX_RESULT_STREAM_BYTES

    # Exposed through the API and recorded in audit detail.
    listed = (await client.get(f"/agents/{_agent_id}/commands")).json()["items"]
    assert listed[0]["stdout_truncated"] is True
    detail = (
        await client.get(f"/agents/{_agent_id}/commands/{listed[0]['id']}")
    ).json()
    assert detail["stdout_total_bytes"] == 10_000_000_000
    async with AsyncSessionLocal() as db:
        ev = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "command.completed")
            )
        ).scalar_one()
    assert ev.detail["stdout_truncated"] is True
    assert ev.detail["stdout_total_bytes"] == 10_000_000_000


@pytest.mark.asyncio
async def test_over_limit_stream_rejected_and_not_stored(client):
    token, cmd_id, _ = await _enrolled_command(client)
    r = await _post_result(
        client, token, cmd_id,
        {"exit_code": 0, "stdout": "x" * (MAX_RESULT_STREAM_BYTES + 1)},
    )
    assert r.status_code == 422

    async with AsyncSessionLocal() as db:
        cmd = (
            await db.execute(select(Command).where(Command.id == cmd_id))
        ).scalar_one()
    assert cmd.stdout is None
    assert cmd.status.value == "dispatched"  # untouched by the rejected post


@pytest.mark.asyncio
async def test_combined_limit_enforced(client):
    token, cmd_id, _ = await _enrolled_command(client)
    # Each stream individually legal, sum over the combined cap.
    half = MAX_RESULT_COMBINED_BYTES // 2 + 1
    r = await _post_result(
        client, token, cmd_id,
        {"exit_code": 0, "stdout": "x" * half, "stderr": "y" * half},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_limits_count_bytes_not_characters(client):
    token, cmd_id, _ = await _enrolled_command(client)
    # '€' is 3 bytes: fewer characters than the cap, more bytes than it.
    over_in_bytes = "€" * (MAX_RESULT_STREAM_BYTES // 3 + 1)
    assert len(over_in_bytes) < MAX_RESULT_STREAM_BYTES
    r = await _post_result(client, token, cmd_id, {"exit_code": 0, "stdout": over_in_bytes})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_legacy_result_without_metadata_stays_unknown(client):
    token, cmd_id, agent_id = await _enrolled_command(client)
    r = await _post_result(client, token, cmd_id, {"exit_code": 1, "stderr": "boom"})
    assert r.status_code == 204
    listed = (await client.get(f"/agents/{agent_id}/commands")).json()["items"]
    assert listed[0]["stdout_truncated"] is None
    assert listed[0]["stderr_truncated"] is None


@pytest.mark.asyncio
async def test_dispatch_payload_size_cap(client):
    _token, _cmd, agent_id = await _enrolled_command(client)
    big_script = "x" * (MAX_COMMAND_PAYLOAD_BYTES + 1)
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": big_script}},
    )
    assert r.status_code == 422
