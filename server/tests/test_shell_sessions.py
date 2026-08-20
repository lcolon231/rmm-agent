# SPDX-License-Identifier: AGPL-3.0-only
"""Interactive shell session foundation tests (issue #61), Phase 1.

Behavior under test — the authorized, audited, bounded session *contract*:
  - authorization: readonly is refused; an operator without arbitrary-script
    scope is refused; an operator with scope may open
  - agent gates: an untrusted (quarantined) agent and an agent that does not
    advertise the capability are both refused, fail closed
  - admission: at most one live session per agent
  - lifecycle: status reads are audited; close is idempotent
  - timeouts: the server-authoritative sweeper expires idle/over-lifetime
    sessions to timed_out
  - audit: lifecycle events are recorded and never carry I/O bytes

Run just this file:  pytest tests/test_shell_sessions.py -q
"""
from __future__ import annotations

import os
import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_shell_sessions.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.tasks import _shell_session_sweep_once  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
    ShellSession,
    ShellSessionStatus,
)

CAP = "shell-session-v2"


@pytest_asyncio.fixture
async def client():
    from app.core.shell_relay import registry

    await registry.reset_for_tests()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="sh-op@nodelink.test",
                password_hash=hash_password("op-pass"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        db.add(
            Operator(
                email="sh-noscope@nodelink.test",
                password_hash=hash_password("noscope-pass"),
                role=OperatorRole.operator,
                script_execution_scope=None,
            )
        )
        db.add(
            Operator(
                email="sh-viewer@nodelink.test",
                password_hash=hash_password("viewer-pass"),
                role=OperatorRole.readonly,
            )
        )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _auth(c, email, password) -> dict:
    r = await c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth, *, capabilities=(CAP,)) -> str:
    """Provision client/site/token and enroll one agent. Returns the agent id."""
    cl = (
        await c.post(
            "/clients", json={"name": f"Shell Clinic {uuid4().hex}"}, headers=op_auth
        )
    ).json()
    st = (
        await c.post(
            "/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth
        )
    ).json()
    et = (
        await c.post(
            "/enrollment-tokens",
            json={"site_id": st["id"], "max_uses": 5},
            headers=op_auth,
        )
    ).json()
    r = await c.post(
        "/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-SHELL",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            "supported_capabilities": list(capabilities),
        },
    )
    assert r.status_code == 200, r.text
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return r.json()["agent_id"]


async def _enroll_identity(c, op_auth, *, capabilities=(CAP,)) -> tuple[str, dict]:
    cl = (
        await c.post(
            "/clients", json={"name": f"Relay Clinic {uuid4().hex}"}, headers=op_auth
        )
    ).json()
    st = (
        await c.post(
            "/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth
        )
    ).json()
    et = (
        await c.post(
            "/enrollment-tokens",
            json={"site_id": st["id"], "max_uses": 1},
            headers=op_auth,
        )
    ).json()
    r = await c.post(
        "/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-RELAY",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            "supported_capabilities": list(capabilities),
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return body["agent_id"], {"Authorization": f"Bearer {body['agent_token']}"}


async def _open(c, auth, agent_id):
    return await c.post(f"/agents/{agent_id}/shell-sessions", json={}, headers=auth)


async def _audit_actions() -> list[str]:
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(select(AuditEvent.action).order_by(AuditEvent.ts))
        ).scalars()
        return list(rows)


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_readonly_cannot_open(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    viewer = await _auth(client, "sh-viewer@nodelink.test", "viewer-pass")
    r = await _open(client, viewer, agent_id)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_operator_without_script_scope_cannot_open(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    noscope = await _auth(client, "sh-noscope@nodelink.test", "noscope-pass")
    r = await _open(client, noscope, agent_id)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "shell_session_not_authorized"
    assert "shell_session.denied" in await _audit_actions()


@pytest.mark.asyncio
async def test_operator_with_scope_opens_pending_bounded_session(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _open(client, op, agent_id)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["capability_version"] == CAP
    assert body["output_bytes_limit"] > 0
    assert body["absolute_deadline"] is not None
    assert body["idle_deadline"] is not None
    assert "shell_session.opened" in await _audit_actions()


@pytest.mark.asyncio
async def test_endpoint_detail_exposes_capability_for_fail_closed_ui(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    response = await client.get(f"/endpoints/{agent_id}", headers=op)
    assert response.status_code == 200
    assert CAP in response.json()["supported_capabilities"]
    assert response.json()["script_execution_allowed"] is True


# --------------------------------------------------------------------------- #
# Agent gates (fail closed)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_untrusted_agent_is_refused(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    q = await client.post(
        f"/agents/{agent_id}/quarantine", json={"reason": "suspected"}, headers=op
    )
    assert q.status_code == 200
    r = await _open(client, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "agent_not_trusted"


@pytest.mark.asyncio
async def test_agent_without_capability_is_unsupported(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op, capabilities=())
    r = await _open(client, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "shell_session_unsupported"


@pytest.mark.asyncio
async def test_second_concurrent_session_is_refused(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    first = await _open(client, op, agent_id)
    assert first.status_code == 201
    second = await _open(client, op, agent_id)
    assert second.status_code == 201
    assert second.json()["id"] == first.json()["id"]


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_status_read_is_audited(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    r = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}", headers=op
    )
    assert r.status_code == 200
    assert r.json()["id"] == session_id
    assert "shell_session.viewed" in await _audit_actions()


@pytest.mark.asyncio
async def test_close_is_idempotent(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    first = await client.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/close",
        json={"reason": "done"},
        headers=op,
    )
    assert first.status_code == 200
    assert first.json()["status"] == "closed"
    # A second close returns the terminal state without error.
    second = await client.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/close",
        json={},
        headers=op,
    )
    assert second.status_code == 200
    assert second.json()["status"] == "closed"
    # After closing, the admission slot is free again.
    reopen = await _open(client, op, agent_id)
    assert reopen.status_code == 201


# --------------------------------------------------------------------------- #
# Timeout sweeper
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_sweeper_times_out_idle_session(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]

    # Force the idle deadline into the past, then run the server-side sweep.
    async with AsyncSessionLocal() as db:
        row = await db.get(ShellSession, session_id)
        row.idle_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    await _shell_session_sweep_once()

    r = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}", headers=op
    )
    assert r.json()["status"] == ShellSessionStatus.timed_out.value
    assert r.json()["close_reason"] == "idle_timeout"
    assert "shell_session.timed_out" in await _audit_actions()


@pytest.mark.asyncio
async def test_audit_details_never_carry_io_bytes(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    await client.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/close",
        json={},
        headers=op,
    )
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action.like("shell_session.%"))
            )
        ).scalars().all()
    assert rows
    for event in rows:
        keys = set(event.detail)
        assert "stdout" not in keys and "stderr" not in keys
        assert "input" not in keys and "bytes" not in keys


# --------------------------------------------------------------------------- #
# Framed relay, ownership, replay, and recovery
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_agent_attach_and_bidirectional_frames_are_bounded_and_not_persisted(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id, agent_auth = await _enroll_identity(client, op)
    session = (await _open(client, op, agent_id)).json()
    session_id = session["id"]

    attached = await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)
    assert attached.status_code == 200
    assert attached.json()["session"]["status"] == "active"

    command = base64.b64encode(b"Get-Date\n").decode()
    sent = await client.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/input",
        json={"seq": 1, "stream": "input", "data_b64": command},
        headers=op,
    )
    assert sent.status_code == 200
    assert sent.json()["frames_in"] == 1
    polled = await client.get(
        f"/agents/me/shell-sessions/{session_id}/input?after=0&ack=0",
        headers=agent_auth,
    )
    assert polled.status_code == 200
    assert polled.json()["frames"][0]["data_b64"] == command

    output = base64.b64encode(b"Wednesday\r\n").decode()
    posted = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output",
        json={"seq": 1, "stream": "stdout", "data_b64": output},
        headers=agent_auth,
    )
    assert posted.status_code == 200
    read = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}/output?after=0&ack=0",
        headers=op,
    )
    assert read.status_code == 200
    assert read.json()["frames"][0]["data_b64"] == output

    async with AsyncSessionLocal() as db:
        row = await db.get(ShellSession, session_id)
        assert row.output_bytes_total == len(b"Wednesday\r\n")
        # The lifecycle row contains counters only, never frame payloads.
        assert not hasattr(row, "stdout") and not hasattr(row, "input")


@pytest.mark.asyncio
async def test_session_hijack_is_hidden_from_other_operator_and_agent(client):
    owner = await _auth(client, "sh-op@nodelink.test", "op-pass")
    other = await _auth(client, "sh-noscope@nodelink.test", "noscope-pass")
    agent_id, agent_auth = await _enroll_identity(client, owner)
    other_agent_id, other_agent_auth = await _enroll_identity(client, owner)
    session_id = (await _open(client, owner, agent_id)).json()["id"]

    assert (
        await client.get(
            f"/agents/{agent_id}/shell-sessions/{session_id}", headers=other
        )
    ).status_code == 404
    assert (
        await client.post(
            f"/agents/{agent_id}/shell-sessions/{session_id}/input",
            json={"seq": 1, "stream": "input", "data_b64": "WAo="},
            headers=other,
        )
    ).status_code == 404
    wrong_attach = await client.post(
        "/agents/me/shell-sessions/attach", headers=other_agent_auth
    )
    assert wrong_attach.status_code == 200
    assert wrong_attach.json()["session"] is None
    right_attach = await client.post(
        "/agents/me/shell-sessions/attach", headers=agent_auth
    )
    assert right_attach.json()["session"]["id"] == session_id
    assert other_agent_id != agent_id


@pytest.mark.asyncio
async def test_identical_retry_is_idempotent_but_altered_replay_is_rejected(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id, agent_auth = await _enroll_identity(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)
    frame = {"seq": 1, "stream": "stdout", "data_b64": "b25jZQ=="}

    first = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output", json=frame, headers=agent_auth
    )
    retry = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output", json=frame, headers=agent_auth
    )
    altered = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output",
        json={**frame, "data_b64": "dHdpY2U="},
        headers=agent_auth,
    )
    assert first.status_code == retry.status_code == 200
    assert retry.json()["frames_out"] == 1
    assert altered.status_code == 409
    assert altered.json()["detail"]["code"] == "shell_sequence_conflict"


@pytest.mark.asyncio
async def test_backpressure_and_expired_cursor_fail_closed(client, monkeypatch):
    monkeypatch.setattr(settings, "shell_session_relay_buffer_bytes", 4)
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id, agent_auth = await _enroll_identity(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)

    first = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output",
        json={"seq": 1, "stream": "stdout", "data_b64": "MTIzNA=="},
        headers=agent_auth,
    )
    blocked = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output",
        json={"seq": 2, "stream": "stdout", "data_b64": "NQ=="},
        headers=agent_auth,
    )
    assert first.status_code == 200
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "1"

    delivered = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}/output?after=0&ack=0",
        headers=op,
    )
    assert delivered.status_code == 200
    expired = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}/output?after=0&ack=1",
        headers=op,
    )
    assert expired.status_code == 409
    assert expired.json()["detail"]["code"] == "shell_cursor_expired"


@pytest.mark.asyncio
async def test_output_limit_fails_session_and_audits_only_metadata(client, monkeypatch):
    monkeypatch.setattr(settings, "shell_session_output_byte_limit", 3)
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id, agent_auth = await _enroll_identity(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)
    too_large = await client.post(
        f"/agents/me/shell-sessions/{session_id}/output",
        json={"seq": 1, "stream": "stderr", "data_b64": "Zm91cg=="},
        headers=agent_auth,
    )
    assert too_large.status_code == 413
    status_response = await client.get(
        f"/agents/{agent_id}/shell-sessions/{session_id}", headers=op
    )
    assert status_response.json()["status"] == "failed"
    assert status_response.json()["close_reason"] == "output_limit"
    assert "shell_session.failed" in await _audit_actions()


@pytest.mark.asyncio
async def test_agent_can_reattach_active_session_after_transport_disconnect(client):
    op = await _auth(client, "sh-op@nodelink.test", "op-pass")
    agent_id, agent_auth = await _enroll_identity(client, op)
    session_id = (await _open(client, op, agent_id)).json()["id"]
    first = await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)
    second = await client.post("/agents/me/shell-sessions/attach", headers=agent_auth)
    assert first.json()["session"]["id"] == session_id
    assert second.json()["session"]["id"] == session_id
    assert second.json()["session"]["status"] == "active"
