# SPDX-License-Identifier: AGPL-3.0-only
"""Agent trust-state tests: quarantine, restore, and revocation.

Behavior under test (issue #15):
  - quarantine: agent still authenticates and beats, but gets no commands, no
    signing keys, and no telemetry/inventory is recorded; result submission is
    refused; dispatch to it is refused
  - restore: quarantined agents return to full service; revoked agents cannot
    be restored (revocation is terminal)
  - revoke: the agent token stops authenticating entirely (same 401 as an
    unknown token), queued work is expired, dispatch is refused
  - authorization: quarantine/restore need operator; revoke needs admin;
    readonly can do neither; every transition demands a reason and is audited
  - re-enrollment after revocation mints a working new identity while the old
    token stays dead

Run just this file:  pytest tests/test_agent_trust.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_agent_trust.db")
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
from app.models.models import (  # noqa: E402
    AuditEvent,
    Heartbeat,
    Operator,
    OperatorRole,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        for email, password, role in (
            ("trust-admin@nodelink.test", "admin-pass", OperatorRole.admin),
            ("trust-op@nodelink.test", "op-pass", OperatorRole.operator),
            ("trust-viewer@nodelink.test", "viewer-pass", OperatorRole.readonly),
        ):
            db.add(Operator(email=email, password_hash=hash_password(password),
                            role=role, can_execute_scripts=True))  # script grant (#111)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _auth(c, email, password) -> dict:
    r = await c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth) -> tuple[str, str]:
    """Provision client/site/token and enroll one agent. Returns (id, token)."""
    cl = (await c.post("/clients", json={"name": "Trust Clinic"}, headers=op_auth)).json()
    st = (
        await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth)
    ).json()
    et = (
        await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5}, headers=op_auth)
    ).json()
    r = await c.post(
        "/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-TRUST",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert r.status_code == 200
    body = r.json()
    return body["agent_id"], body["agent_token"]


def _beat_body() -> dict:
    return {
        "cpu_percent": 10.0,
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        "inventory": {"hostname": "PC-TRUST"},
    }


async def _beat(c, agent_token):
    return await c.post(
        "/heartbeat", json=_beat_body(), headers={"Authorization": f"Bearer {agent_token}"}
    )


async def _audit_actions() -> list[str]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(AuditEvent.action).order_by(AuditEvent.ts))).scalars()
        return list(rows)


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_quarantined_agent_beats_but_gets_nothing(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, agent_token = await _enroll(client, op)

    # Queue a command while the agent is still trusted.
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo hi"}},
        headers=op,
    )
    assert r.status_code == 200

    r = await client.post(
        f"/agents/{agent_id}/quarantine", json={"reason": "suspicious beaconing"}, headers=op
    )
    assert r.status_code == 200
    body = r.json()
    assert body["trust_state"] == "quarantined"
    assert body["trust_state_reason"] == "suspicious beaconing"
    assert body["trust_state_changed_by"] == "trust-op@nodelink.test"

    # The agent still authenticates, but the ack is a bare minimum: no queued
    # command, no signing-key bundle, and the state is disclosed to the agent.
    r = await _beat(client, agent_token)
    assert r.status_code == 200
    ack = r.json()
    assert ack["trust_state"] == "quarantined"
    assert ack["pending_commands"] == []
    assert ack["command_public_keys"] == {}

    # No telemetry or inventory was recorded for the quarantined beat.
    async with AsyncSessionLocal() as db:
        beats = (
            await db.execute(select(Heartbeat).where(Heartbeat.agent_id == agent_id))
        ).scalars().all()
    assert beats == []


@pytest.mark.asyncio
async def test_quarantined_agent_cannot_submit_results(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, agent_token = await _enroll(client, op)

    cmd = (
        await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "shell", "payload": {"script": "echo hi"}},
            headers=op,
        )
    ).json()
    # Agent picks the command up while trusted (it is now in-flight)...
    r = await _beat(client, agent_token)
    assert [c["id"] for c in r.json()["pending_commands"]] == [cmd["id"]]

    # ...the operator quarantines mid-flight, so the result is refused.
    r = await client.post(
        f"/agents/{agent_id}/quarantine", json={"reason": "compromise suspected"}, headers=op
    )
    assert r.status_code == 200
    r = await client.post(
        f"/commands/{cmd['id']}/result",
        json={"exit_code": 0, "stdout": "pwned"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "agent_quarantined"


@pytest.mark.asyncio
async def test_dispatch_to_quarantined_agent_is_refused(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, _ = await _enroll(client, op)
    await client.post(f"/agents/{agent_id}/quarantine", json={"reason": "containment"}, headers=op)

    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo hi"}},
        headers=op,
    )
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "agent_not_trusted"
    assert r.json()["detail"]["trust_state"] == "quarantined"


@pytest.mark.asyncio
async def test_restore_returns_agent_to_service(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, agent_token = await _enroll(client, op)

    await client.post(f"/agents/{agent_id}/quarantine", json={"reason": "containment"}, headers=op)
    r = await client.post(
        f"/agents/{agent_id}/restore", json={"reason": "false positive"}, headers=op
    )
    assert r.status_code == 200
    assert r.json()["trust_state"] == "active"

    # Full service is back: command dispatch works and the beat delivers it.
    cmd = (
        await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "shell", "payload": {"script": "echo hi"}},
            headers=op,
        )
    ).json()
    r = await _beat(client, agent_token)
    assert r.json()["trust_state"] == "active"
    assert [c["id"] for c in r.json()["pending_commands"]] == [cmd["id"]]


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_revoked_agent_fails_authentication_like_unknown_token(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, agent_token = await _enroll(client, op)

    r = await client.post(
        f"/agents/{agent_id}/revoke", json={"reason": "endpoint stolen"}, headers=admin
    )
    assert r.status_code == 200
    assert r.json()["trust_state"] == "revoked"

    # Same status and detail as a token that never existed — no oracle.
    revoked = await _beat(client, agent_token)
    unknown = await client.post(
        "/heartbeat", json=_beat_body(), headers={"Authorization": "Bearer no-such-token"}
    )
    assert revoked.status_code == unknown.status_code == 401
    assert revoked.json() == unknown.json()

    # Result submission dies with the same 401 (auth happens first).
    r = await client.post(
        "/commands/whatever/result",
        json={"exit_code": 0},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_revoke_expires_outstanding_commands_and_blocks_dispatch(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, agent_token = await _enroll(client, op)

    queued = (
        await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "shell", "payload": {"script": "echo queued"}},
            headers=op,
        )
    ).json()
    dispatched = (
        await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "shell", "payload": {"script": "echo dispatched"}},
            headers=op,
        )
    ).json()
    # Move the second command to dispatched via a beat.
    r = await _beat(client, agent_token)
    assert len(r.json()["pending_commands"]) == 2  # both go out; both then expire
    del dispatched

    await client.post(f"/agents/{agent_id}/revoke", json={"reason": "compromised"}, headers=admin)

    cmds = (await client.get(f"/agents/{agent_id}/commands", headers=op)).json()["items"]
    assert {c["status"] for c in cmds} == {"expired"}
    assert queued["id"] in {c["id"] for c in cmds}

    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo more"}},
        headers=op,
    )
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "agent_not_trusted"


@pytest.mark.asyncio
async def test_revocation_is_terminal(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, _ = await _enroll(client, op)

    await client.post(f"/agents/{agent_id}/revoke", json={"reason": "gone"}, headers=admin)

    # Restore, quarantine, and re-revoke all conflict.
    for action, hdrs in (("restore", op), ("quarantine", op), ("revoke", admin)):
        r = await client.post(
            f"/agents/{agent_id}/{action}", json={"reason": "should fail"}, headers=hdrs
        )
        assert r.status_code == 409, action
        assert r.json()["detail"]["code"] == "agent_trust_state_conflict", action


@pytest.mark.asyncio
async def test_reenrollment_after_revocation_creates_working_new_identity(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, old_token = await _enroll(client, op)
    await client.post(f"/agents/{agent_id}/revoke", json={"reason": "rebuilt"}, headers=admin)

    new_id, new_token = await _enroll(client, op)
    assert new_id != agent_id
    assert (await _beat(client, new_token)).status_code == 200
    assert (await _beat(client, old_token)).status_code == 401


# --------------------------------------------------------------------------- #
# Authorization and input validation
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_role_requirements(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    viewer = await _auth(client, "trust-viewer@nodelink.test", "viewer-pass")
    agent_id, _ = await _enroll(client, op)

    # readonly may neither quarantine nor revoke.
    for action in ("quarantine", "restore", "revoke"):
        r = await client.post(
            f"/agents/{agent_id}/{action}", json={"reason": "nope"}, headers=viewer
        )
        assert r.status_code == 403, action

    # operator may not revoke (admin-only, irreversible).
    r = await client.post(f"/agents/{agent_id}/revoke", json={"reason": "nope"}, headers=op)
    assert r.status_code == 403

    # admin may revoke.
    r = await client.post(f"/agents/{agent_id}/revoke", json={"reason": "device stolen"}, headers=admin)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_reason_is_mandatory(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, _ = await _enroll(client, op)

    for body in ({}, {"reason": ""}, {"reason": "  "}, {"reason": "x" * 501}):
        r = await client.post(f"/agents/{agent_id}/quarantine", json=body, headers=op)
        assert r.status_code == 422, body

    # Agent state untouched by the rejected calls.
    agent = (await client.get(f"/agents/{agent_id}", headers=op)).json()
    assert agent["trust_state"] == "active"


@pytest.mark.asyncio
async def test_unknown_agent_404(client):
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    for action in ("quarantine", "restore"):
        r = await client.post(f"/agents/nope/{action}", json={"reason": "does not exist"}, headers=op)
        assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Audit evidence
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_trust_transitions_are_audited(client):
    admin = await _auth(client, "trust-admin@nodelink.test", "admin-pass")
    op = await _auth(client, "trust-op@nodelink.test", "op-pass")
    agent_id, _ = await _enroll(client, op)

    await client.post(f"/agents/{agent_id}/quarantine", json={"reason": "contain: r1"}, headers=op)
    await client.post(f"/agents/{agent_id}/restore", json={"reason": "cleared: r2"}, headers=op)
    await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "echo hi"}},
        headers=op,
    )
    await client.post(f"/agents/{agent_id}/revoke", json={"reason": "stolen: r3"}, headers=admin)

    actions = await _audit_actions()
    for expected in (
        "agent.quarantined",
        "agent.restored",
        "agent.revoked",
        "agent.commands_expired_on_revoke",
    ):
        assert expected in actions, actions

    async with AsyncSessionLocal() as db:
        ev = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "agent.revoked"))
        ).scalar_one()
    assert ev.actor == "trust-admin@nodelink.test"
    assert ev.agent_id == agent_id
    assert ev.detail["reason"] == "stolen: r3"
    assert ev.detail["previous_trust_state"] == "active"

    # The chain still verifies with the new events on it.
    r = await client.get("/audit/verify", headers=op)
    assert r.json()["intact"] is True
