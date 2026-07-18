"""End-to-end API tests for the NodeLink RMM backend.

Runs entirely in-process against an ephemeral SQLite database, so no Postgres
is required for CI. Exercises the full agent lifecycle and the audit chain's
tamper-evidence.

Run with:  pytest -q
"""
from __future__ import annotations

import base64
import os

import pytest
import pytest_asyncio

# Point config at an ephemeral sqlite DB before importing the app.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_rmm.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import canonical_command_bytes, hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V1  # noqa: E402
from app.core import audit  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    # Seed an operator and log in, so management calls in these tests are
    # authenticated. Agent-facing endpoints (enroll/heartbeat) don't use this.
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="e2e@nodelink.test",
                password_hash=hash_password("e2e-password"),
                role=OperatorRole.operator,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login", json={"email": "e2e@nodelink.test", "password": "e2e-password"}
        )
        token = login.json()["access_token"]
        c.headers.update({"Authorization": f"Bearer {token}"})
        yield c
    await engine.dispose()


async def _enroll(c) -> tuple[str, str, str]:
    """Return (agent_id, agent_token, command_public_key)."""
    cl = (await c.post("/clients", json={"name": "Test Clinic"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": "PC1",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V1],
            },
        )
    ).json()
    return enr["agent_id"], enr["agent_token"], enr["command_public_key"]


@pytest.mark.asyncio
async def test_enroll_and_heartbeat(client):
    agent_id, token, _ = await _enroll(client)
    auth = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/heartbeat",
        json={
            "cpu_percent": 10.0,
            "mem_percent": 20.0,
            "disk_percent": 30.0,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V1],
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["pending_commands"] == []

    agent = (await client.get(f"/agents/{agent_id}")).json()
    assert agent["status"] == "online"


@pytest.mark.asyncio
async def test_bad_token_rejected(client):
    await _enroll(client)
    r = await client.post(
        "/heartbeat", json={"cpu_percent": 1.0}, headers={"Authorization": "Bearer nope"}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_command_dispatch_pickup_and_signature(client):
    agent_id, token, pub_pem = await _enroll(client)
    auth = {"Authorization": f"Bearer {token}"}

    disp = (
        await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "powershell", "payload": {"script": "Get-Date"}},
        )
    ).json()
    assert disp["signature"]

    # Command is delivered on the next heartbeat.
    ack = (
        await client.post(
            "/heartbeat",
            json={
                "cpu_percent": 5.0,
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V1],
            },
            headers=auth,
        )
    ).json()
    assert len(ack["pending_commands"]) == 1
    cmd = ack["pending_commands"][0]

    # The agent's signature check must pass.
    pub = load_pem_public_key(pub_pem.encode())
    assert cmd["envelope_version"] == COMMAND_ENVELOPE_V1
    msg = canonical_command_bytes(
        cmd["envelope_version"], cmd["id"], agent_id, cmd["kind"], cmd["payload"]
    )
    pub.verify(base64.b64decode(cmd["signature"]), msg)  # raises if invalid

    # Report a result and confirm status transition.
    r = await client.post(
        f"/commands/{cmd['id']}/result",
        json={"exit_code": 0, "stdout": "ok", "stderr": ""},
        headers=auth,
    )
    assert r.status_code == 204
    cmds = (await client.get(f"/agents/{agent_id}/commands")).json()
    assert cmds[0]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_tampered_signature_rejected_by_agent(client):
    agent_id, token, pub_pem = await _enroll(client)
    auth = {"Authorization": f"Bearer {token}"}
    await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "powershell", "payload": {"script": "whoami"}},
    )
    ack = (
        await client.post(
            "/heartbeat",
            json={
                "cpu_percent": 1.0,
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V1],
            },
            headers=auth,
        )
    ).json()
    cmd = ack["pending_commands"][0]

    pub = load_pem_public_key(pub_pem.encode())
    # Tamper with the payload the agent would execute.
    forged = canonical_command_bytes(
        cmd["envelope_version"],
        cmd["id"],
        agent_id,
        cmd["kind"],
        {"script": "rm -rf /"},
    )
    with pytest.raises(Exception):
        pub.verify(base64.b64decode(cmd["signature"]), forged)


@pytest.mark.asyncio
async def test_enrollment_negotiation_rejects_unknown_without_consuming_token(client):
    cl = (await client.post("/clients", json={"name": "Version Clinic"})).json()
    st = (await client.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await client.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    base = {"enrollment_token": et["token"], "hostname": "PC2", "os": "windows"}

    rejected = await client.post(
        "/enroll",
        json={**base, "supported_command_envelope_versions": ["command-v2"]},
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "no_common_command_envelope_version"

    accepted = await client.post(
        "/enroll",
        json={
            **base,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V1],
        },
    )
    assert accepted.status_code == 200
    assert accepted.json()["command_envelope_version"] == COMMAND_ENVELOPE_V1


@pytest.mark.asyncio
async def test_capability_downgrade_withholds_queued_command(client):
    agent_id, token, _ = await _enroll(client)
    auth = {"Authorization": f"Bearer {token}"}
    queued = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo safe"}},
    )
    assert queued.status_code == 200

    downgraded = await client.post(
        "/heartbeat",
        json={"supported_command_envelope_versions": []},
        headers=auth,
    )
    assert downgraded.status_code == 200
    assert downgraded.json()["pending_commands"] == []

    refused = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo no"}},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "agent_command_envelope_version_unsupported"

    restored = await client.post(
        "/heartbeat",
        json={"supported_command_envelope_versions": [COMMAND_ENVELOPE_V1]},
        headers=auth,
    )
    assert [c["id"] for c in restored.json()["pending_commands"]] == [queued.json()["id"]]


@pytest.mark.asyncio
async def test_floating_point_command_payload_is_rejected(client):
    agent_id, _, _ = await _enroll(client)
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"ratio": 1.5}},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_oversized_command_payload_is_rejected(client):
    agent_id, _, _ = await _enroll(client)
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "x" * (61 * 1024)}},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_audit_chain_detects_tampering(client):
    agent_id, _, _ = await _enroll(client)
    ok, _ = (await client.get("/audit/verify")).json().values()
    assert ok is True

    # Tamper directly in the DB, then re-verify.
    from sqlalchemy import update
    from app.models.models import AuditEvent

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(AuditEvent)
            .where(AuditEvent.action == "agent.enrolled")
            .values(actor="attacker")
        )
        await db.commit()

    async with AsyncSessionLocal() as db:
        intact, broken = await audit.verify_chain(db)
    assert intact is False
    assert broken is not None
