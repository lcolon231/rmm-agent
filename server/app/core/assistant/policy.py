# SPDX-License-Identifier: AGPL-3.0-only
"""Server-owned limits, encryption and permission rechecks."""
import base64
import json
import os
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from sqlalchemy import select

from app.api.deps import get_current_operator
from app.core.config import settings
from app.core.redaction import scrub_text
from app.core.tenant_scope import agent_client_filter, assert_agent_visible, assert_client_visible
from app.models.models import Agent, AgentTrustState, AssistantConversation, Client, Site

MAX_TOOLS = 6
MAX_SECONDS = 45
MAX_INPUT_BYTES = 65536
MAX_RESULT_BYTES = 12288
MAX_RESPONSE_BYTES = 131072
MAX_USAGE = 40000
MAX_OUTPUT_TOKENS = 2048
RETENTION_DAYS = 30


def now():
    return datetime.now(timezone.utc)


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def history_cipher():
    try:
        key = base64.b64decode(settings.assistant_history_key.get_secret_value(), altchars=b"-_", validate=True)
        if len(key) != 32:
            raise ValueError
        return AESGCM(key)
    except Exception:
        raise HTTPException(503, detail={"code": "assistant_unconfigured"}) from None


def availability(operator):
    if not settings.assistant_enabled:
        return "disabled"
    pilot = {x.strip() for x in settings.assistant_pilot_operator_ids.split(",") if x.strip()}
    if pilot and operator.id not in pilot:
        return "disabled"
    if (settings.assistant_provider != "openai" or not settings.assistant_model.strip()
            or not settings.assistant_api_key or not settings.assistant_api_key.get_secret_value().strip()):
        return "unconfigured"
    try:
        history_cipher()
    except HTTPException:
        return "unconfigured"
    return "available"


def require_available(operator):
    state = availability(operator)
    if state != "available":
        raise HTTPException(503, detail={"code": f"assistant_{state}"})


def clean_text(value, limit=4000):
    # Exact application credentials are removed even if they lack a known shape.
    value = str(value)
    for secret in (settings.assistant_api_key, settings.assistant_history_key, settings.secret_key):
        secret = secret.get_secret_value() if hasattr(secret, "get_secret_value") else secret
        if secret:
            value = value.replace(secret, "[redacted]")
    value = re.sub(r"sk-[A-Za-z0-9_-]+", "[redacted]", value)
    return scrub_text(value)[:limit]


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), default=str)


def seal(run, conversation, body):
    nonce = os.urandom(12)
    aad = f"{run.id}:{conversation.id}:{conversation.operator_id}:{conversation.client_id}".encode()
    return nonce + history_cipher().encrypt(nonce, encoded(body).encode(), aad)


def unseal(run, conversation):
    aad = f"{run.id}:{conversation.id}:{conversation.operator_id}:{conversation.client_id}".encode()
    try:
        return json.loads(history_cipher().decrypt(run.body[:12], run.body[12:], aad))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, detail={"code": "assistant_history_unavailable"}) from None


async def authorize(db, authorization, conversation_id=None, client_id=None):
    # No cached operator or identity-map grants across provider waits.
    db.expire_all()
    operator = await get_current_operator(authorization=authorization, db=db)
    require_available(operator)
    conversation = None
    if conversation_id:
        conversation = await db.scalar(select(AssistantConversation).where(
            AssistantConversation.id == conversation_id,
            AssistantConversation.operator_id == operator.id,
            AssistantConversation.expires_at > now(),
        ))
        if conversation is None:
            raise HTTPException(404, "Conversation not found")
        client_id = conversation.client_id
    if client_id:
        if await db.get(Client, client_id) is None:
            raise HTTPException(404, "Client not found")
        await assert_client_visible(operator, client_id, db)
    return operator, conversation


async def endpoint(db, operator, client_id, endpoint_id):
    agent = await db.scalar(select(Agent).join(Site).where(
        Agent.id == endpoint_id, Site.client_id == client_id,
        Agent.trust_state != AgentTrustState.revoked,
    ).execution_options(populate_existing=True))
    if agent is None:
        raise HTTPException(404, "Endpoint not found")
    await assert_agent_visible(operator, agent, db)
    return agent


async def check_targets(db, operator, client_id, target_ids):
    targets = set(target_ids)
    if not targets:
        return
    visible = set((await db.execute(select(Agent.id).join(Site).where(
        Agent.id.in_(targets), Site.client_id == client_id, agent_client_filter(operator),
        Agent.trust_state != AgentTrustState.revoked,
    ))).scalars().all())
    if targets != visible:
        raise HTTPException(404, "Referenced endpoints are no longer accessible")
