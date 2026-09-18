# SPDX-License-Identifier: AGPL-3.0-only
import os
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_support_chat.db")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DEBUG", "false")

import httpx
import pytest
from sqlalchemy import select, func
from app.main import app
from app.core.config import Settings, settings
from app.core.database import Base, engine, AsyncSessionLocal
from app.core.security import hash_token, hash_password
from app.core import support_chat as core
from app.core.ratelimit import support_chat_limiter, support_chat_send_limiter, support_chat_open_limiter
from app.models.models import (
    Agent,
    AgentTrustState,
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
    SupportConversation,
    SupportConversationStatus,
    SupportMessage,
)


@pytest.fixture
async def env(monkeypatch):
    monkeypatch.setattr(settings, "support_chat_base_url", "https://support.example.test")
    for limiter in (support_chat_limiter, support_chat_send_limiter, support_chat_open_limiter):
        limiter.reset()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        client = Client(name="Chat tenant")
        db.add(client)
        await db.flush()
        site = Site(client_id=client.id, name="HQ")
        db.add(site)
        await db.flush()
        agents = [Agent(site_id=site.id, hostname=f"CHAT-{i}", token_hash=hash_token(f"agent-{i}")) for i in range(2)]
        db.add_all(agents)
        await db.commit()
        ids = [a.id for a in agents]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://t/api/v1") as api:
        yield api, ids, client.id
    await engine.dispose()


async def opened(api, agent=0):
    response = await api.post("/support/agent/conversations", headers={"Authorization": f"Bearer agent-{agent}"})
    assert response.status_code == 200, response.text
    data = response.json()
    url = urlsplit(data["url"])
    assert not url.query
    token = parse_qs(url.fragment)["t"][0]
    return "/support/chat/" + data["conversation_id"], {"Authorization": "Bearer " + token}, data["conversation_id"]


async def acknowledge(api, path, headers):
    response = await api.post(path + "/notice", headers=headers, json={"notice_version": settings.support_chat_notice_version})
    assert response.status_code == 200, response.text


async def test_notice_gate_records_version_and_scrubs_before_storage(env, caplog):
    api, ids, tenant = env
    path, auth, cid = await opened(api)
    refused = await api.post(path + "/messages", headers=auth, json={"body": "hello"})
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "support_chat_notice_required"
    assert (await api.post(path + "/notice", headers=auth, json={"notice_version": "wrong"})).status_code == 409
    await acknowledge(api, path, auth)
    secret = "Bearer very-secret-chat-credential-12345"
    sent = await api.post(path + "/messages", headers=auth, json={"body": secret})
    assert sent.status_code == 200, sent.text
    assert "very-secret-chat" not in sent.text
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        assert row.agent_id == ids[0] and row.client_id == tenant
        assert row.notice_version == settings.support_chat_notice_version
        assert row.notice_acknowledged_at
        assert row.token_hash == hash_token(auth["Authorization"].split()[1])
        message = await db.scalar(select(SupportMessage))
        assert "very-secret-chat" not in message.body
        assert "very-secret-chat" not in row.subject
    assert secret not in caplog.text
    assert auth["Authorization"] not in caplog.text


async def test_scoped_expiring_tokens_refresh_and_old_token_refusal(env):
    api, _, _ = env
    path, auth, cid = await opened(api)
    other, _, _ = await opened(api, 1)
    assert (await api.get(other + "/messages", headers=auth)).status_code == 403
    assert (await api.get(path + "/messages")).status_code == 401
    rotated = await api.post(path + "/refresh", headers=auth)
    assert rotated.status_code == 200
    assert rotated.headers["cache-control"] == "no-store"
    assert (await api.get(path + "/messages", headers=auth)).status_code == 403
    auth = {"Authorization": "Bearer " + rotated.json()["token"]}
    assert (await api.get(path + "/messages", headers=auth)).status_code == 200
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        row.token_expires_at = core.now() - timedelta(seconds=1)
        await db.commit()
    for method, action in ((api.get, "messages"), (api.post, "refresh")):
        assert (await method(path + "/" + action, headers=auth)).status_code == 401


async def test_reopen_is_one_conversation_rotates_token_and_resets_consent(env):
    api, _, _ = env
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    await api.post(path + "/messages", headers=auth, json={"body": "hello"})
    newpath, newauth, newid = await opened(api)
    assert newpath == path and newid == cid
    assert (await api.get(path + "/messages", headers=auth)).status_code == 403
    result = (await api.get(path + "/messages", headers=newauth)).json()
    assert not result["notice_acknowledged"] and result["messages"] == []
    async with AsyncSessionLocal() as db:
        assert await db.scalar(select(func.count()).select_from(SupportConversation)) == 1


async def test_cursor_returns_unseen_tail_idempotently(env):
    api, _, _ = env
    path, auth, _ = await opened(api)
    await acknowledge(api, path, auth)
    for i in range(3):
        assert (await api.post(path + "/messages", headers=auth, json={"body": f"message {i}"})).json()["seq"] == i + 1
    first = await api.get(path + "/messages?after=1", headers=auth)
    repeat = await api.get(path + "/messages?after=1", headers=auth)
    assert first.json() == repeat.json()
    assert [m["seq"] for m in first.json()["messages"]] == [2, 3]
    assert (await api.get(path + "/messages?after=3", headers=auth)).json()["messages"] == []


@pytest.mark.parametrize("trust", [AgentTrustState.quarantined, AgentTrustState.revoked])
async def test_untrusted_agent_cannot_open_or_continue(env, trust):
    api, ids, _ = env
    path, auth, _ = await opened(api)
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, ids[0])
        agent.trust_state = trust
        await db.commit()
    assert (await api.post("/support/agent/conversations", headers={"Authorization": "Bearer agent-0"})).status_code in (401, 403)
    assert (await api.get(path + "/messages", headers=auth)).status_code == 403


async def test_agent_credentials_cannot_authorize_chat_and_chat_cannot_open(env):
    api, _, _ = env
    path, auth, _ = await opened(api)
    assert (await api.post("/support/agent/conversations", headers=auth)).status_code == 401
    assert (await api.post("/support/agent/conversations")).status_code == 401
    assert (await api.get(path + "/messages", headers={"Authorization": "Bearer agent-0"})).status_code == 403


async def test_message_byte_and_count_bounds(env, monkeypatch):
    api, _, _ = env
    path, auth, _ = await opened(api)
    await acknowledge(api, path, auth)
    oversized = await api.post(path + "/messages", headers=auth, json={"body": "é" * 2049})
    assert oversized.json()["detail"]["code"] == "support_chat_message_too_large"
    monkeypatch.setattr(settings, "support_chat_max_messages", 1)
    assert (await api.post(path + "/messages", headers=auth, json={"body": "a" * 4096})).status_code == 200
    capped = await api.post(path + "/messages", headers=auth, json={"body": "another"})
    assert capped.json()["detail"]["code"] == "support_chat_message_limit"


async def test_idle_boundary_closes_without_accepting_more_messages(env, monkeypatch):
    api, _, _ = env
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        boundary = core.utc(row.created_at) + timedelta(seconds=settings.support_chat_idle_close_seconds)
    monkeypatch.setattr(core, "now", lambda: boundary - timedelta(seconds=1))
    # Extend token independently so this tests idle, not TTL.
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        row.token_expires_at = boundary + timedelta(minutes=10)
        await db.commit()
    assert (await api.get(path + "/messages", headers=auth)).json()["status"] == "open"
    monkeypatch.setattr(core, "now", lambda: boundary)
    assert (await api.get(path + "/messages", headers=auth)).json()["status"] == "closed"
    assert (await api.post(path + "/messages", headers=auth, json={"body": "late"})).status_code == 409
    assert (await api.post(path + "/refresh", headers=auth)).status_code == 409
    _, _, fresh = await opened(api)
    assert fresh != cid


async def test_limits_requests_and_origin_is_required_for_configuration(env, monkeypatch):
    api, _, _ = env
    path, auth, _ = await opened(api)
    token = auth["Authorization"].split()[1]
    for _ in range(90): support_chat_limiter.record_failure(hash_token(token))
    assert (await api.get(path + "/messages", headers=auth)).status_code == 429
    monkeypatch.setattr(settings, "support_chat_base_url", None)
    assert (await api.post("/support/agent/conversations", headers={"Authorization": "Bearer agent-1"})).status_code == 503


@pytest.mark.parametrize("field,value", [("support_chat_max_open_per_agent", 2), ("support_chat_token_ttl_seconds", 901), ("support_chat_idle_close_seconds", 0), ("support_chat_retention_days", -1)])
def test_configuration_bounds(field, value):
    from pydantic import ValidationError
    with pytest.raises(ValidationError): Settings(**{field: value})


# --- Operator (technician) side (#235) --------------------------------------

@pytest.fixture
async def ops(env):
    """env plus a technician (member of the chat tenant) and an outsider operator
    (member of a different tenant only), for the operator routes."""
    api, ids, tenant = env
    async with AsyncSessionLocal() as db:
        tech = Operator(email="tech@nodelink.test", password_hash=hash_password("pw"), role=OperatorRole.operator)
        outsider = Operator(email="outsider@nodelink.test", password_hash=hash_password("pw"), role=OperatorRole.operator)
        other = Client(name="Other tenant")
        db.add_all([tech, outsider, other])
        await db.flush()
        db.add(OperatorClientMembership(operator_id=tech.id, client_id=tenant, role=ClientRole.client_operator, granted_by="test-seed", reason="test-seed"))
        db.add(OperatorClientMembership(operator_id=outsider.id, client_id=other.id, role=ClientRole.client_operator, granted_by="test-seed", reason="test-seed"))
        await db.commit()
    return api, ids, tenant


async def login(api, email="tech@nodelink.test", password="pw"):
    response = await api.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


async def test_operator_sees_conversation_and_badge_clears_on_open(ops):
    api, _, cid_tenant = ops
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    await api.post(path + "/messages", headers=auth, json={"body": "my vpn keeps dropping"})
    tech = await login(api)
    assert (await api.get("/support/unread-count", headers=tech)).json()["unread"] == 1
    listing = (await api.get("/support/conversations", headers=tech)).json()["conversations"]
    assert len(listing) == 1
    assert listing[0]["id"] == cid and listing[0]["endpoint"] == "CHAT-0"
    assert listing[0]["unread"] == 1 and listing[0]["status"] == "open"
    transcript = (await api.get(f"/support/conversations/{cid}", headers=tech)).json()
    assert [m["sender"] for m in transcript["messages"]] == ["end_user"]
    assert transcript["messages"][0]["body"] == "my vpn keeps dropping"
    # Opening the transcript marks the messages read, clearing the nav badge.
    assert (await api.get("/support/unread-count", headers=tech)).json()["unread"] == 0


async def test_empty_state_for_operator_with_no_visible_conversations(ops):
    api, _, _ = ops
    tech = await login(api)
    assert (await api.get("/support/conversations", headers=tech)).json()["conversations"] == []
    assert (await api.get("/support/unread-count", headers=tech)).json()["unread"] == 0


async def test_operator_reply_reaches_user_with_identity(ops):
    api, _, _ = ops
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    await api.post(path + "/messages", headers=auth, json={"body": "hi"})
    tech = await login(api)
    reply = await api.post(f"/support/conversations/{cid}/messages", headers=tech, json={"body": "hello from support"})
    assert reply.status_code == 200, reply.text
    assert reply.json()["sender"] == "technician"
    # The reply reaches the end user's browser on its next poll.
    tail = (await api.get(path + "/messages?after=0", headers=auth)).json()["messages"]
    assert any(m["sender"] == "technician" and m["body"] == "hello from support" for m in tail)
    # Participant identity is visible on the technician message.
    transcript = (await api.get(f"/support/conversations/{cid}", headers=tech)).json()
    tech_msgs = [m for m in transcript["messages"] if m["sender"] == "technician"]
    assert tech_msgs and tech_msgs[0]["operator_email"] == "tech@nodelink.test"


async def test_cross_tenant_operator_gets_404_and_empty_list(ops):
    api, _, _ = ops
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    await api.post(path + "/messages", headers=auth, json={"body": "hi"})
    outsider = await login(api, "outsider@nodelink.test")
    assert (await api.get("/support/conversations", headers=outsider)).json()["conversations"] == []
    assert (await api.get("/support/unread-count", headers=outsider)).json()["unread"] == 0
    assert (await api.get(f"/support/conversations/{cid}", headers=outsider)).status_code == 404
    assert (await api.post(f"/support/conversations/{cid}/messages", headers=outsider, json={"body": "x"})).status_code == 404
    assert (await api.post(f"/support/conversations/{cid}/close", headers=outsider)).status_code == 404


async def test_technician_can_reply_to_idle_open_conversation(ops):
    api, _, _ = ops
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    await api.post(path + "/messages", headers=auth, json={"body": "my vpn keeps dropping"})
    # Push the conversation past the idle window without closing it (the common
    # case for a technician answering later); the DB status stays open.
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        row.last_message_at = core.now() - timedelta(seconds=settings.support_chat_idle_close_seconds + 60)
        await db.commit()
    tech = await login(api)
    # The end user's stale session is treated as closed...
    assert (await api.post(path + "/messages", headers=auth, json={"body": "hello?"})).status_code == 409
    # ...but the technician can still reply, which re-activates the conversation.
    reply = await api.post(f"/support/conversations/{cid}/messages", headers=tech, json={"body": "sorry for the delay"})
    assert reply.status_code == 200, reply.text
    assert reply.json()["sender"] == "technician"


async def test_operator_close_invalidates_end_user_token(ops):
    api, _, _ = ops
    path, auth, cid = await opened(api)
    await acknowledge(api, path, auth)
    tech = await login(api)
    assert (await api.post(f"/support/conversations/{cid}/close", headers=tech)).status_code == 200
    assert (await api.get(path + "/messages", headers=auth)).status_code == 403
    async with AsyncSessionLocal() as db:
        row = await db.get(SupportConversation, cid)
        assert row.status == SupportConversationStatus.closed and row.closed_by_operator_id and row.token_hash == ""
