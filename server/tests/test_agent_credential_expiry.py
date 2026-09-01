# SPDX-License-Identifier: AGPL-3.0-only
"""Expiring agent credentials, renewal, and bounded reattach (#125, #223).

Covers the server side of the bounded-lifetime bearer model: enrollment issues a
finite lifetime, expired credentials are refused, renewal rotates atomically
with a bounded overlap so the superseded credential keeps working, a dropped
renewal response is recoverable via retry, a verbatim replay (same nonce) is
rejected, and recently lapsed active identities can reattach while quarantined,
revoked, unknown, and stale credentials remain indistinguishable and refused.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_rmm.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentTrustState,
    AuditEvent,
    Operator,
    OperatorRole,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="creds@nodelink.test",
                password_hash=hash_password("creds-password"),
                role=OperatorRole.admin,
                is_platform_admin=True,
            )
        )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "creds@nodelink.test", "password": "creds-password"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enroll(c) -> tuple[str, str]:
    """Enroll one agent and return (agent_id, agent_token)."""
    cl = (await c.post("/clients", json={"name": f"Clinic {uuid4().hex}"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enrolled = (
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
    return enrolled["agent_id"], enrolled["agent_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


_HEARTBEAT = {"supported_command_envelope_versions": [COMMAND_ENVELOPE_V2]}


async def _heartbeat_status(c, token: str) -> int:
    return (await c.post("/heartbeat", json=_HEARTBEAT, headers=_auth(token))).status_code


async def _reattach(c, token: str):
    return await c.post(
        "/agents/credentials/reattach",
        json={"rotation_nonce": f"nonce-{uuid4().hex}"},
        headers=_auth(token),
    )


async def _set_agent(agent_id: str, **fields) -> None:
    async with AsyncSessionLocal() as db:
        agent = (
            await db.execute(select(Agent).where(Agent.id == agent_id))
        ).scalar_one()
        for key, value in fields.items():
            setattr(agent, key, value)
        await db.commit()


@pytest.mark.asyncio
async def test_enrollment_issues_a_finite_lifetime(client):
    agent_id, token = await _enroll(client)
    async with AsyncSessionLocal() as db:
        agent = (
            await db.execute(select(Agent).where(Agent.id == agent_id))
        ).scalar_one()
    assert agent.credential_expires_at is not None
    expires_at = agent.credential_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expected = datetime.now(timezone.utc) + timedelta(
        seconds=settings.agent_credential_lifetime_seconds
    )
    # Within a minute of the configured lifetime from now.
    assert abs((expires_at - expected).total_seconds()) < 60
    assert await _heartbeat_status(client, token) == 200


@pytest.mark.asyncio
async def test_expired_credential_is_refused(client):
    agent_id, token = await _enroll(client)
    await _set_agent(
        agent_id,
        credential_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert await _heartbeat_status(client, token) == 401


@pytest.mark.asyncio
async def test_expired_active_credential_reattaches_and_audits_distinctly(client):
    agent_id, expired_token = await _enroll(client)
    await _set_agent(
        agent_id,
        credential_expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    assert await _heartbeat_status(client, expired_token) == 401

    recovered = await _reattach(client, expired_token)
    assert recovered.status_code == 200, recovered.text
    body = recovered.json()
    assert body["agent_id"] == agent_id
    assert body["agent_token"] != expired_token
    assert body["credential_generation"] == 2
    assert await _heartbeat_status(client, body["agent_token"]) == 200

    async with AsyncSessionLocal() as db:
        actions = (
            await db.execute(
                select(AuditEvent.action).where(AuditEvent.agent_id == agent_id)
            )
        ).scalars().all()
    assert actions.count("agent.credential_reattached") == 1
    assert "agent.credential_renewed" not in actions


@pytest.mark.asyncio
async def test_lost_reattach_response_can_retry_on_overlap(client):
    agent_id, expired_token = await _enroll(client)
    await _set_agent(
        agent_id,
        credential_expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    # The first response is notionally lost. The agent still holds the expired
    # bearer, now preserved in the short overlap slot, and retries reattach.
    first = await _reattach(client, expired_token)
    assert first.status_code == 200
    retry = await _reattach(client, expired_token)
    assert retry.status_code == 200, retry.text
    assert await _heartbeat_status(client, retry.json()["agent_token"]) == 200


@pytest.mark.asyncio
async def test_reattach_refuses_revoked_and_quarantined_agents(client):
    for trust_state in (AgentTrustState.revoked, AgentTrustState.quarantined):
        agent_id, token = await _enroll(client)
        fields = {
            "credential_expires_at": datetime.now(timezone.utc)
            - timedelta(minutes=5),
            "trust_state": trust_state,
        }
        if trust_state == AgentTrustState.revoked:
            fields["revoked_at"] = datetime.now(timezone.utc)
        await _set_agent(agent_id, **fields)

        refused = await _reattach(client, token)
        refused_again = await _reattach(client, token)
        unknown = await _reattach(client, f"unknown-{uuid4().hex}")
        assert refused.status_code == refused_again.status_code == unknown.status_code == 401
        assert refused.json() == refused_again.json() == unknown.json()


@pytest.mark.asyncio
async def test_reattach_outside_window_matches_unknown_refusal(client):
    agent_id, token = await _enroll(client)
    await _set_agent(
        agent_id,
        credential_expires_at=datetime.now(timezone.utc)
        - timedelta(seconds=settings.agent_credential_reattach_window_seconds + 1),
    )

    expired = await _reattach(client, token)
    unknown = await _reattach(client, f"unknown-{uuid4().hex}")
    assert expired.status_code == unknown.status_code == 401
    assert expired.json() == unknown.json() == {"detail": "Invalid agent token"}


@pytest.mark.asyncio
async def test_renewal_rotates_with_bounded_overlap(client):
    agent_id, old_token = await _enroll(client)
    renewed = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": f"nonce-{uuid4().hex}"},
        headers=_auth(old_token),
    )
    assert renewed.status_code == 200, renewed.text
    body = renewed.json()
    new_token = body["agent_token"]
    assert new_token != old_token
    assert body["credential_generation"] == 2
    assert body["overlap_expires_at"] is not None

    # During the overlap window both credentials authenticate.
    assert await _heartbeat_status(client, new_token) == 200
    assert await _heartbeat_status(client, old_token) == 200

    # Once the overlap lapses the superseded credential is refused; the current
    # one still works. The server never accepts a credential past its bound.
    await _set_agent(
        agent_id,
        previous_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert await _heartbeat_status(client, old_token) == 401
    assert await _heartbeat_status(client, new_token) == 200


@pytest.mark.asyncio
async def test_lost_response_retry_is_loss_safe(client):
    agent_id, t0 = await _enroll(client)
    # First renewal succeeds server-side but the agent never sees the response,
    # so it keeps t0 and never learns t1.
    first = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": f"nonce-{uuid4().hex}"},
        headers=_auth(t0),
    )
    assert first.status_code == 200

    # The agent retries with a fresh nonce on the credential it still holds (t0,
    # now valid via the overlap window) and obtains a usable credential.
    retry = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": f"nonce-{uuid4().hex}"},
        headers=_auth(t0),
    )
    assert retry.status_code == 200, retry.text
    t2 = retry.json()["agent_token"]
    assert await _heartbeat_status(client, t2) == 200
    # The held credential kept working across the retry — no unrecoverable split.
    assert await _heartbeat_status(client, t0) == 200


@pytest.mark.asyncio
async def test_replayed_nonce_is_rejected(client):
    _, token = await _enroll(client)
    nonce = f"nonce-{uuid4().hex}"
    first = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": nonce},
        headers=_auth(token),
    )
    assert first.status_code == 200
    # A verbatim replay reuses the same nonce on the still-valid overlap token.
    replay = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": nonce},
        headers=_auth(token),
    )
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == "rotation_nonce_reused"


@pytest.mark.asyncio
async def test_revoked_identity_cannot_renew(client):
    agent_id, token = await _enroll(client)
    await _set_agent(
        agent_id,
        trust_state=AgentTrustState.revoked,
        revoked_at=datetime.now(timezone.utc),
    )
    renew = await client.post(
        "/agents/credentials/renew",
        json={"rotation_nonce": f"nonce-{uuid4().hex}"},
        headers=_auth(token),
    )
    assert renew.status_code == 401
