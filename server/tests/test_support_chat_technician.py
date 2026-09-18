# SPDX-License-Identifier: AGPL-3.0-only
import os
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_support_chat_technician.db")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DEBUG", "false")

import httpx
import pytest

from app.core.config import settings
from app.core.database import AsyncSessionLocal, Base, engine
from app.core.ratelimit import support_chat_limiter, support_chat_open_limiter, support_chat_send_limiter
from app.core.security import hash_password, hash_token
from app.main import app
from app.models.models import (
    Agent,
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
    SupportConversation,
    SupportConversationStatus,
    SupportParty,
)
from app.schemas.schemas import HeartbeatAck


@pytest.fixture
async def technician_env(monkeypatch):
    monkeypatch.setattr(settings, "support_chat_base_url", "https://support.example.test")
    for limiter in (support_chat_limiter, support_chat_send_limiter, support_chat_open_limiter):
        limiter.reset()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        tenant = Client(name="Technician chat tenant")
        other = Client(name="Other tenant")
        db.add_all([tenant, other])
        await db.flush()
        site = Site(client_id=tenant.id, name="HQ")
        db.add(site)
        await db.flush()
        agents = [
            Agent(site_id=site.id, hostname=f"CHAT-{index}", token_hash=hash_token(f"agent-{index}"),
                  supported_capabilities=["support-chat-v1"] if index != 1 else [])
            for index in range(3)
        ]
        technician = Operator(
            email="tech@nodelink.test",
            password_hash=hash_password("pw"),
            role=OperatorRole.operator,
        )
        outsider = Operator(
            email="outsider@nodelink.test",
            password_hash=hash_password("pw"),
            role=OperatorRole.operator,
        )
        db.add_all([*agents, technician, outsider])
        await db.flush()
        db.add_all([
            OperatorClientMembership(
                operator_id=technician.id,
                client_id=tenant.id,
                role=ClientRole.client_operator,
                granted_by="test",
                reason="test",
            ),
            OperatorClientMembership(
                operator_id=outsider.id,
                client_id=other.id,
                role=ClientRole.client_operator,
                granted_by="test",
                reason="test",
            ),
        ])
        await db.commit()
        agent_ids = [agent.id for agent in agents]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://test/api/v1",
    ) as api:
        yield api, agent_ids
    await engine.dispose()


async def login(api, email="tech@nodelink.test"):
    response = await api.post("/auth/login", json={"email": email, "password": "pw"})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_heartbeat_ack_chat_launch_defaults_to_none():
    assert HeartbeatAck().chat_launch_requested is None


async def test_technician_open_refuses_unsupported_and_cross_tenant(technician_env):
    api, agent_ids = technician_env
    tech = await login(api)
    refused = await api.post(
        "/support/conversations",
        headers=tech,
        json={"agent_id": agent_ids[1]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "support_chat_unsupported"

    outsider = await login(api, "outsider@nodelink.test")
    hidden = await api.post(
        "/support/conversations",
        headers=outsider,
        json={"agent_id": agent_ids[0]},
    )
    assert hidden.status_code == 404


async def test_technician_launch_rides_heartbeat_until_notice_acknowledged(technician_env):
    api, agent_ids = technician_env
    tech = await login(api)
    opened = await api.post(
        "/support/conversations",
        headers=tech,
        json={"agent_id": agent_ids[0]},
    )
    assert opened.status_code == 201, opened.text
    conversation_id = opened.json()["conversation_id"]
    assert opened.json()["opened_by"] == "technician"

    agent_auth = {"Authorization": "Bearer agent-0"}
    first = await api.post("/heartbeat", headers=agent_auth, json={})
    assert first.status_code == 200, first.text
    launch_url = first.json()["chat_launch_requested"]
    parsed = urlsplit(launch_url)
    token = parse_qs(parsed.fragment)["t"][0]
    assert parsed.path == "/chat" and not parsed.query
    second = await api.post("/heartbeat", headers=agent_auth, json={})
    assert second.json()["chat_launch_requested"] == launch_url

    async with AsyncSessionLocal() as db:
        conversation = await db.get(SupportConversation, conversation_id)
        assert conversation.opened_by == SupportParty.technician
        assert conversation.status == SupportConversationStatus.open
        assert conversation.notice_acknowledged_at is None

    acknowledged = await api.post(
        f"/support/chat/{conversation_id}/notice",
        headers={"Authorization": "Bearer " + token},
        json={"notice_version": settings.support_chat_notice_version},
    )
    assert acknowledged.status_code == 200, acknowledged.text
    cleared = await api.post("/heartbeat", headers=agent_auth, json={})
    assert cleared.json()["chat_launch_requested"] is None


async def test_end_user_open_never_populates_heartbeat_launch(technician_env):
    api, _ = technician_env
    opened = await api.post(
        "/support/agent/conversations",
        headers={"Authorization": "Bearer agent-2"},
    )
    assert opened.status_code == 200, opened.text
    heartbeat = await api.post(
        "/heartbeat",
        headers={"Authorization": "Bearer agent-2"},
        json={},
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["chat_launch_requested"] is None
