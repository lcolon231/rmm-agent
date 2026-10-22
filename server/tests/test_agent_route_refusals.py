# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal branches on agent, update, session, and export routes (issue #284).

Each test drives one ``raise HTTPException`` that the rest of the suite never
reached and pins both the status and the coded detail, so a refusal cannot
silently turn into a success or change its contract:

  - agent credentials: a reattach replaying the nonce that already rotated
  - monitoring ingest: inactive agent, offline (server-owned) check, results
    from the future, missing or out-of-range numeric values, and an idempotency
    key that loses a race to a different payload
  - a command result for a command the agent was never sent
  - agent self-update: signing unavailable, unknown channel filter, advancing a
    completed release, and the halt rule firing on advance and on resume
  - shell sessions: unknown agent, admission, frame decoding, non-live session,
    missing relay, and an untrusted agent polling input
  - support chat, assistant body limit, and evidence export lookups
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_agent_route_refusals.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import agent_updates as updates  # noqa: E402
from app.core import monitoring as monitoring_core  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.shell_relay import registry  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentTrustState,
    AgentUpdateAttempt,
    AgentUpdateAttemptStatus,
    AgentUpdateRelease,
    AgentUpdateReleaseState,
    CheckResult,
    CheckResultStatus,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)
from tests._tenancy import grant_all_memberships  # noqa: E402

_ADMIN = ("refusals-admin@nodelink.test", "refusals-admin-pass")
_OPERATOR = ("refusals-op@nodelink.test", "refusals-op-pass")
_SHELL_CAP = "shell-session-v2"
_UPDATE_CAP = "agent-self-update-v1"


@pytest_asyncio.fixture
async def client():
    await registry.reset_for_tests()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email=_ADMIN[0],
                    password_hash=hash_password(_ADMIN[1]),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=_OPERATOR[0],
                    password_hash=hash_password(_OPERATOR[1]),
                    role=OperatorRole.operator,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
            ]
        )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        c.headers.update(await _login(c, *_ADMIN))
        yield c
    await registry.reset_for_tests()
    await engine.dispose()


async def _login(c, email: str, password: str) -> dict:
    response = await c.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _enroll(c, *, capabilities=()) -> tuple[str, str]:
    """Enroll one Windows agent and return (agent_id, agent_token)."""
    org = (await c.post("/clients", json={"name": f"Refusal {uuid4().hex}"})).json()
    site = (await c.post("/sites", json={"client_id": org["id"], "name": "HQ"})).json()
    token = (await c.post("/enrollment-tokens", json={"site_id": site["id"]})).json()
    enrolled = await c.post(
        "/enroll",
        json={
            "enrollment_token": token["token"],
            "hostname": f"REFUSE-{uuid4().hex[:8]}",
            "os": "windows",
            "os_version": "10.0.19045",
            "agent_version": "0.1.0",
            "architecture": "amd64",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert enrolled.status_code == 200, enrolled.text
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    body = enrolled.json()
    return body["agent_id"], body["agent_token"]


async def _set_agent(agent_id: str, **fields) -> None:
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        for key, value in fields.items():
            setattr(agent, key, value)
        await db.commit()


def _assert_refused(response: httpx.Response, status_code: int, code: str) -> None:
    assert response.status_code == status_code, response.text
    assert response.json()["detail"]["code"] == code


# --------------------------------------------------------------------------- #
# Agent credentials
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_reattach_replaying_the_rotated_nonce_is_refused(client):
    agent_id, expired_token = await _enroll(client)
    await _set_agent(
        agent_id,
        credential_expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    nonce = f"nonce-{uuid4().hex}"
    first = await client.post(
        "/agents/credentials/reattach",
        json={"rotation_nonce": nonce},
        headers=_auth(expired_token),
    )
    assert first.status_code == 200, first.text

    # The expired bearer now sits in the overlap slot, so it still resolves; a
    # verbatim replay of the nonce that already rotated it must not rotate again.
    replay = await client.post(
        "/agents/credentials/reattach",
        json={"rotation_nonce": nonce},
        headers=_auth(expired_token),
    )
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid agent token"}


# --------------------------------------------------------------------------- #
# Monitoring result ingest
# --------------------------------------------------------------------------- #
def _cpu_check() -> dict:
    return {
        "key": "cpu",
        "type": "cpu",
        "enabled": True,
        "schedule": {"interval_seconds": 60},
        "threshold": {"op": "gte", "warning": 80, "critical": 95},
        "params": {},
    }


def _offline_check() -> dict:
    return {
        "key": "offline",
        "type": "offline",
        "enabled": True,
        "schedule": {"interval_seconds": 30},
        "threshold": {"op": "gte", "warning": 60, "critical": 120},
        "params": {},
    }


async def _monitored_agent(c) -> tuple[str, str, dict]:
    """Enroll an agent under a cpu + offline policy; return (id, token, policy)."""
    agent_id, token = await _enroll(c)
    response = await c.post(
        "/monitoring/policies",
        json={
            "name": f"Refusals {uuid4().hex[:8]}",
            "scope": "agent",
            "scope_id": agent_id,
            "checks": [_cpu_check(), _offline_check()],
            "change_note": "Refusal coverage",
        },
    )
    assert response.status_code == 201, response.text
    return agent_id, token, response.json()


def _result(policy: dict, **overrides) -> dict:
    result = {
        "id": uuid4().hex,
        "policy_id": policy["id"],
        "policy_revision_id": policy["revisions"][0]["id"],
        "check_key": "cpu",
        "status": "warning",
        "value": 85,
        "detail": {"reason": "threshold_evaluated"},
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    result.update(overrides)
    return result


async def _submit(c, token: str, *results: dict) -> httpx.Response:
    return await c.post(
        "/agents/me/monitoring/results",
        json={"results": list(results)},
        headers=_auth(token),
    )


@pytest.mark.asyncio
async def test_monitoring_results_from_an_inactive_agent_are_refused(client):
    agent_id, token, policy = await _monitored_agent(client)
    await _set_agent(agent_id, trust_state=AgentTrustState.quarantined)
    _assert_refused(await _submit(client, token, _result(policy)), 403, "agent_not_active")


@pytest.mark.parametrize(
    ("overrides", "status_code", "code"),
    [
        pytest.param(
            {"check_key": "offline", "status": "ok", "value": None},
            422,
            "offline_check_is_server_owned",
            id="offline-check-is-server-owned",
        ),
        pytest.param(
            {
                "evaluated_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=10)
                ).isoformat()
            },
            422,
            "monitoring_result_from_future",
            id="from-the-future",
        ),
        pytest.param(
            {"value": None},
            422,
            "monitoring_result_value_required",
            id="numeric-value-missing",
        ),
        pytest.param(
            {"value": 150},
            422,
            "monitoring_result_value_out_of_range",
            id="percentage-out-of-range",
        ),
    ],
)
@pytest.mark.asyncio
async def test_monitoring_result_validation_refusals(
    client, overrides, status_code, code
):
    _, token, policy = await _monitored_agent(client)
    response = await _submit(client, token, _result(policy, **overrides))
    _assert_refused(response, status_code, code)


@pytest.mark.asyncio
async def test_monitoring_result_losing_a_race_to_a_different_payload_conflicts(
    client, monkeypatch
):
    agent_id, token, policy = await _monitored_agent(client)
    submitted = _result(policy)
    original = monitoring_core.record_check_result

    async def racing_writer_commits_first(db, **kwargs):
        # A concurrent request commits the same idempotency key with a different
        # status between this request's pre-check and its insert.
        async with AsyncSessionLocal() as other:
            other.add(
                CheckResult(
                    id=submitted["id"],
                    agent_id=agent_id,
                    policy_id=submitted["policy_id"],
                    policy_revision_id=submitted["policy_revision_id"],
                    check_key="cpu",
                    status=CheckResultStatus.critical,
                    value=submitted["value"],
                    detail=submitted["detail"],
                    evaluated_at=datetime.fromisoformat(submitted["evaluated_at"]),
                )
            )
            await other.commit()
        return await original(db, **kwargs)

    monkeypatch.setattr(monitoring_core, "record_check_result", racing_writer_commits_first)
    response = await _submit(client, token, submitted)
    _assert_refused(response, 409, "monitoring_result_id_conflict")


# --------------------------------------------------------------------------- #
# Command results
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_result_for_an_unknown_command_is_not_found(client):
    _, token = await _enroll(client)
    response = await client.post(
        f"/commands/{uuid4()}/result",
        json={"exit_code": 0, "stdout": "orphaned"},
        headers=_auth(token),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Command not found"}


# --------------------------------------------------------------------------- #
# Agent self-update releases
# --------------------------------------------------------------------------- #
def _release_body(**overrides) -> dict:
    body = {
        "version": "0.2.0",
        "channel": "stable",
        "platform": "windows/amd64",
        "artifact_url": "https://releases.example/rmm-agent-0.2.0.exe",
        "artifact_sha256": "a" * 64,
        "artifact_size_bytes": 12_345_678,
        "min_supported_version": "0.1.0",
        "failure_threshold_percent": 50,
        "min_attempts_before_halt": 2,
    }
    body.update(overrides)
    return body


async def _publish(c) -> dict:
    response = await c.post("/agent-updates/releases", json=_release_body())
    assert response.status_code == 201, response.text
    return response.json()


async def _record_failed_attempts(c, release_id: str, count: int) -> None:
    """Store enough resolved failures for the halt rule to condemn the release."""
    agent_ids = [(await _enroll(c, capabilities=(_UPDATE_CAP,)))[0] for _ in range(count)]
    async with AsyncSessionLocal() as db:
        db.add_all(
            AgentUpdateAttempt(
                release_id=release_id,
                agent_id=agent_id,
                status=AgentUpdateAttemptStatus.failed,
                from_version="0.1.0",
                to_version="0.2.0",
                reason="health_check_failed",
            )
            for agent_id in agent_ids
        )
        await db.commit()


@pytest.mark.asyncio
async def test_publish_without_a_signing_key_is_unavailable(client, monkeypatch):
    def no_signing_key(manifest):
        raise FileNotFoundError("signing key missing")

    monkeypatch.setattr(updates, "sign_manifest", no_signing_key)
    response = await client.post("/agent-updates/releases", json=_release_body())
    _assert_refused(response, 503, "agent_update_signing_unavailable")

    listed = await client.get("/agent-updates/releases")
    assert listed.status_code == 200
    assert listed.json()["releases"] == []


@pytest.mark.asyncio
async def test_listing_releases_by_an_unknown_channel_is_rejected(client):
    response = await client.get("/agent-updates/releases", params={"channel": "nightly"})
    _assert_refused(response, 400, "agent_update_channel_invalid")


@pytest.mark.asyncio
async def test_completed_release_cannot_be_advanced(client):
    release = await _publish(client)
    async with AsyncSessionLocal() as db:
        row = await db.get(AgentUpdateRelease, release["id"])
        row.state = AgentUpdateReleaseState.completed
        row.rollout_percent = 100
        await db.commit()

    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
    )
    _assert_refused(response, 409, "agent_update_release_completed")


@pytest.mark.asyncio
async def test_advancing_a_failing_release_halts_it_instead(client):
    release = await _publish(client)
    await _record_failed_attempts(client, release["id"], 2)

    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 50},
    )
    _assert_refused(response, 409, "agent_update_release_halted")
    assert response.json()["detail"]["reason"] == "failure_threshold_exceeded"

    detail = (await client.get(f"/agent-updates/releases/{release['id']}")).json()
    assert detail["state"] == "halted"
    assert detail["halted_reason"] == "failure_threshold_exceeded"


@pytest.mark.asyncio
async def test_resume_requires_a_paused_release(client):
    release = await _publish(client)
    response = await client.post(f"/agent-updates/releases/{release['id']}/resume")
    _assert_refused(response, 409, "agent_update_release_not_paused")


@pytest.mark.asyncio
async def test_resuming_a_failing_release_halts_it_instead(client):
    release = await _publish(client)
    paused = await client.post(f"/agent-updates/releases/{release['id']}/pause")
    assert paused.status_code == 200, paused.text
    await _record_failed_attempts(client, release["id"], 2)

    response = await client.post(f"/agent-updates/releases/{release['id']}/resume")
    _assert_refused(response, 409, "agent_update_release_halted")
    assert response.json()["detail"]["reason"] == "failure_threshold_exceeded"

    detail = (await client.get(f"/agent-updates/releases/{release['id']}")).json()
    assert detail["state"] == "halted"


# --------------------------------------------------------------------------- #
# Shell sessions
# --------------------------------------------------------------------------- #
async def _open_shell(c, agent_id: str, headers: dict | None = None) -> httpx.Response:
    return await c.post(f"/agents/{agent_id}/shell-sessions", json={}, headers=headers)


async def _live_shell(c) -> tuple[str, str, str]:
    """Open a pending shell session; return (agent_id, agent_token, session_id)."""
    agent_id, token = await _enroll(c, capabilities=(_SHELL_CAP,))
    opened = await _open_shell(c, agent_id)
    assert opened.status_code == 201, opened.text
    return agent_id, token, opened.json()["id"]


async def _send_input(c, agent_id: str, session_id: str, frame: dict) -> httpx.Response:
    return await c.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/input", json=frame
    )


@pytest.mark.asyncio
async def test_shell_open_for_an_unknown_agent_is_not_found(client):
    response = await _open_shell(client, str(uuid4()))
    assert response.status_code == 404
    assert response.json() == {"detail": "Agent not found"}


@pytest.mark.asyncio
async def test_second_operator_cannot_open_a_shell_beside_a_live_one(
    client, monkeypatch
):
    monkeypatch.setattr(settings, "shell_session_max_concurrent_per_agent", 1)
    agent_id, _, _ = await _live_shell(client)
    other = await _login(client, *_OPERATOR)
    response = await _open_shell(client, agent_id, headers=other)
    _assert_refused(response, 409, "shell_session_already_active")


@pytest.mark.parametrize(
    ("frame", "status_code", "code"),
    [
        pytest.param(
            {"seq": 1, "stream": "stdout", "data_b64": "ZGly"},
            422,
            "shell_stream_invalid",
            id="operator-cannot-write-agent-stream",
        ),
        pytest.param(
            {"seq": 1, "stream": "input", "data_b64": "not base64!"},
            422,
            "shell_frame_base64_invalid",
            id="invalid-base64",
        ),
        pytest.param(
            {"seq": 1, "stream": "input", "data_b64": ""},
            422,
            "shell_frame_empty",
            id="empty-input-without-eof",
        ),
        pytest.param(
            # 12 decoded bytes against the 8-byte limit patched in below.
            {"seq": 1, "stream": "input", "data_b64": "AAAAAAAAAAAAAAAA"},
            413,
            "shell_frame_too_large",
            id="frame-over-byte-limit",
        ),
    ],
)
@pytest.mark.asyncio
async def test_shell_input_frame_decoding_refusals(
    client, monkeypatch, frame, status_code, code
):
    monkeypatch.setattr(settings, "shell_session_max_frame_bytes", 8)
    agent_id, _, session_id = await _live_shell(client)
    response = await _send_input(client, agent_id, session_id, frame)
    _assert_refused(response, status_code, code)


@pytest.mark.asyncio
async def test_shell_input_to_a_closed_session_is_refused(client):
    agent_id, _, session_id = await _live_shell(client)
    closed = await client.post(
        f"/agents/{agent_id}/shell-sessions/{session_id}/close", json={}
    )
    assert closed.status_code == 200, closed.text

    response = await _send_input(
        client, agent_id, session_id, {"seq": 1, "stream": "input", "data_b64": "ZGly"}
    )
    _assert_refused(response, 409, "shell_session_not_live")


@pytest.mark.asyncio
async def test_shell_input_without_a_relay_is_refused(client):
    agent_id, _, session_id = await _live_shell(client)
    # The in-memory relay is lost (e.g. a server restart) while the row is live.
    await registry.reset_for_tests()

    response = await _send_input(
        client, agent_id, session_id, {"seq": 1, "stream": "input", "data_b64": "ZGly"}
    )
    _assert_refused(response, 409, "shell_relay_unavailable")


@pytest.mark.asyncio
async def test_untrusted_agent_cannot_poll_shell_input(client):
    agent_id, token, session_id = await _live_shell(client)
    await _set_agent(agent_id, trust_state=AgentTrustState.quarantined)

    response = await client.get(
        f"/agents/me/shell-sessions/{session_id}/input", headers=_auth(token)
    )
    _assert_refused(response, 409, "agent_not_trusted")


# --------------------------------------------------------------------------- #
# Support chat, assistant, evidence export
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_technician_chat_for_an_unknown_agent_is_not_found(client):
    response = await client.post("/support/conversations", json={"agent_id": str(uuid4())})
    assert response.status_code == 404
    assert response.json() == {"detail": "Agent not found"}


@pytest.mark.asyncio
async def test_unknown_support_conversation_is_not_found(client):
    response = await client.get(f"/support/conversations/{uuid4()}")
    assert response.status_code == 404
    assert response.json() == {"detail": "Conversation not found"}


@pytest.mark.asyncio
async def test_oversized_assistant_body_is_rejected_before_parsing(client):
    oversized = b'{"client_id": "' + b"x" * 20_001 + b'"}'
    response = await client.post(
        "/assistant/conversations",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    _assert_refused(response, 413, "assistant_input_limit")
    # The refusal never echoes the submitted bytes.
    assert "xxxx" not in response.text


@pytest.mark.asyncio
async def test_evidence_export_for_an_unknown_tenant_is_not_found(client):
    response = await client.get(
        "/evidence/bundles/export", params={"organization_id": str(uuid4())}
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Tenant not found"}
