# SPDX-License-Identifier: AGPL-3.0-only
from uuid import UUID
from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent
from app.core import support_chat as core
from app.core.config import settings
from app.core.database import get_db
from app.core.ratelimit import support_chat_limiter, support_chat_open_limiter, support_chat_send_limiter
from app.core.security import hash_token
from app.models.models import Agent, AgentTrustState, SupportConversation, SupportMessage
from app.schemas.support_chat import MessageIn, MessageOut, NoticeIn


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"


agent_router = APIRouter(prefix="/support/agent", dependencies=[Depends(no_store)])
router = APIRouter(prefix="/support/chat", dependencies=[Depends(no_store)])


def limit(limiter, key):
    if limiter.retry_after(key) is not None:
        core.fail("rate_limited", 429)
    limiter.record_failure(key)


@agent_router.post("/conversations")
async def open_chat(agent: Agent = Depends(get_current_agent), db: AsyncSession = Depends(get_db)):
    agent = await db.scalar(select(Agent).where(Agent.id == agent.id).with_for_update().execution_options(populate_existing=True))
    if agent.trust_state != AgentTrustState.active:
        core.fail("agent_untrusted", 403)
    limit(support_chat_open_limiter, agent.id)
    return await core.open_conversation(db, agent)


async def authorized(conversation_id: UUID, authorization: str | None = Header(default=None), db: AsyncSession = Depends(get_db)):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 128:
        core.fail("token_required", 401)
    conversation = await db.scalar(select(SupportConversation).where(SupportConversation.id == str(conversation_id)).with_for_update())
    if conversation is None:
        core.fail("token_invalid", 403)
    core.verify(conversation, token)
    agent = await db.get(Agent, conversation.agent_id)
    if agent is None or agent.trust_state != AgentTrustState.active:
        core.fail("token_invalid", 403)
    limit(support_chat_limiter, hash_token(token))
    return conversation


@router.get("/{conversation_id}/messages")
async def messages(after: int = Query(default=0, ge=0), conversation=Depends(authorized), db: AsyncSession = Depends(get_db)):
    closed = conversation.status == "closed" or core.is_idle(conversation)
    acknowledged = conversation.notice_version == settings.support_chat_notice_version and conversation.notice_acknowledged_at is not None
    # Do not disclose a transcript in a newly opened browser before consent.
    tail = [] if not acknowledged else (await db.scalars(select(SupportMessage).where(
        SupportMessage.conversation_id == conversation.id, SupportMessage.seq > after,
    ).order_by(SupportMessage.seq).limit(settings.support_chat_max_messages))).all()
    return {"status": "closed" if closed else "open", "notice_version": settings.support_chat_notice_version,
            "notice_acknowledged": acknowledged, "retention_days": settings.support_chat_retention_days,
            "token_expires_at": conversation.token_expires_at,
            "messages": [MessageOut.model_validate(m) for m in tail]}


@router.post("/{conversation_id}/notice")
async def notice(body: NoticeIn, conversation=Depends(authorized)):
    core.require_open(conversation)
    if body.notice_version != settings.support_chat_notice_version:
        core.fail("notice_version", 409)
    if conversation.notice_version != body.notice_version or not conversation.notice_acknowledged_at:
        conversation.notice_version = body.notice_version
        conversation.notice_acknowledged_at = core.now()
    return {"notice_acknowledged": True}


@router.post("/{conversation_id}/messages", response_model=MessageOut)
async def send(body: MessageIn, conversation=Depends(authorized), db: AsyncSession = Depends(get_db)):
    limit(support_chat_send_limiter, conversation.id)
    return await core.append_message(db, conversation, body.body)


@router.post("/{conversation_id}/refresh")
async def refresh(conversation=Depends(authorized)):
    core.require_open(conversation)
    token = core.rotate(conversation)
    return {"token": token, "token_expires_at": conversation.token_expires_at}
