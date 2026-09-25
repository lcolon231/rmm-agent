# SPDX-License-Identifier: AGPL-3.0-only
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent, require_role
from app.core import support_chat as core
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.core.ratelimit import support_chat_limiter, support_chat_open_limiter, support_chat_send_limiter
from app.core.security import hash_token
from app.core.tenant_scope import assert_client_action, assert_client_visible, client_id_filter
from app.core.tenant_scope import assert_agent_visible
from app.models.models import (
    Agent,
    AgentTrustState,
    ClientRole,
    Operator,
    OperatorRole,
    SupportConversation,
    SupportConversationStatus,
    SupportMessage,
    SupportParty,
)
from app.schemas.support_chat import MessageIn, MessageOut, NoticeIn
from app.schemas.support_chat import TechnicianConversationOpenIn


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"


agent_router = APIRouter(prefix="/support/agent", dependencies=[Depends(no_store)])
router = APIRouter(prefix="/support/chat", dependencies=[Depends(no_store)])


def evidence(request: Request, actor: str, actor_user_id: str | None = None):
    return {
        "actor": actor,
        "actor_user_id": actor_user_id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


# The person at the endpoint is unauthenticated beyond the conversation-scoped
# token, so the chain names the role rather than an identity it cannot prove.
END_USER = "support_chat:end_user"


def limit(limiter, key):
    if limiter.retry_after(key) is not None:
        core.fail("rate_limited", 429)
    limiter.record_failure(key)


@agent_router.post("/conversations")
async def open_chat(request: Request, agent: Agent = Depends(get_current_agent), db: AsyncSession = Depends(get_db)):
    agent = await db.scalar(select(Agent).where(Agent.id == agent.id).with_for_update().execution_options(populate_existing=True))
    if agent.trust_state != AgentTrustState.active:
        core.fail("agent_untrusted", 403)
    limit(support_chat_open_limiter, agent.id)
    return await core.open_conversation(db, agent, **evidence(request, f"agent:{agent.id}"))


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
async def notice(body: NoticeIn, request: Request, conversation=Depends(authorized), db: AsyncSession = Depends(get_db)):
    core.require_open(conversation)
    if body.notice_version != settings.support_chat_notice_version:
        core.fail("notice_version", 409)
    if conversation.notice_version != body.notice_version or not conversation.notice_acknowledged_at:
        conversation.notice_version = body.notice_version
        conversation.notice_acknowledged_at = core.now()
        await core.audit_notice_acknowledged(db, conversation, **evidence(request, END_USER))
    return {"notice_acknowledged": True}


@router.post("/{conversation_id}/messages", response_model=MessageOut)
async def send(body: MessageIn, conversation=Depends(authorized), db: AsyncSession = Depends(get_db)):
    limit(support_chat_send_limiter, conversation.id)
    return await core.append_message(db, conversation, body.body)


@router.post("/{conversation_id}/refresh")
async def refresh(request: Request, conversation=Depends(authorized), db: AsyncSession = Depends(get_db)):
    core.require_open(conversation)
    token = core.rotate(conversation)
    await core.audit_token_minted(db, conversation, "refresh", **evidence(request, END_USER))
    return {"token": token, "token_expires_at": conversation.token_expires_at}


# --- Operator (technician) router -------------------------------------------
# Same tenant model as shell_sessions: an operator only sees conversations on
# endpoints in their client memberships. A cross-tenant or missing conversation
# is a 404, never a 403, so the boundary does not confirm existence.
operator_router = APIRouter(prefix="/support", tags=["support-chat"])

NOT_FOUND = "Conversation not found"
SUPPORT_CHAT_CAPABILITY = "support-chat-v1"
# Technician-initiated launch requires the agent to act on the heartbeat's
# chat_launch_requested field (issue #236). support-chat-v1 (#234) only covers
# the end-user pipe launch, so gating the button on it lit up an enabled-but-dead
# control for any agent that predated the heartbeat handler. Gate on the launch
# capability, which only #236+ agents advertise.
SUPPORT_CHAT_LAUNCH_CAPABILITY = "support-chat-launch-v1"


@operator_router.post("/conversations", status_code=201)
async def open_technician_chat(
    body: TechnicianConversationOpenIn,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    agent = await db.scalar(
        select(Agent)
        .where(Agent.id == body.agent_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if agent is None:
        raise HTTPException(404, detail="Agent not found")
    await assert_agent_visible(
        operator,
        agent,
        db,
        minimum=ClientRole.client_operator,
        detail="Agent not found",
    )
    if agent.trust_state != AgentTrustState.active:
        core.fail("agent_untrusted", 409)
    if SUPPORT_CHAT_LAUNCH_CAPABILITY not in (agent.supported_capabilities or []):
        core.fail("unsupported", 409)
    limit(support_chat_open_limiter, agent.id)
    conversation = await core.open_technician_conversation(
        db, agent, **evidence(request, operator.email, operator.id)
    )
    return {
        "conversation_id": conversation.id,
        "status": conversation.status,
        "opened_by": conversation.opened_by,
    }


def _summary(conversation, endpoint, unread):
    return {
        "id": conversation.id,
        "agent_id": conversation.agent_id,
        "endpoint": endpoint,
        "subject": conversation.subject,
        "status": conversation.status,
        "opened_by": conversation.opened_by,
        "last_message_at": conversation.last_message_at,
        "created_at": conversation.created_at,
        "unread": unread,
    }


@operator_router.get("/unread-count")
async def unread_count(operator: Operator = Depends(require_role(OperatorRole.operator)), db: AsyncSession = Depends(get_db)):
    # Filters on the conversation's denormalized client_id, joining messages to
    # conversations only -- never through agents -- so the nav can poll it cheaply.
    total = await db.scalar(
        select(func.count())
        .select_from(SupportMessage)
        .join(SupportConversation, SupportMessage.conversation_id == SupportConversation.id)
        .where(
            SupportMessage.sender == SupportParty.end_user,
            SupportMessage.read_at.is_(None),
            client_id_filter(operator, SupportConversation.client_id),
        )
    )
    return {"unread": int(total or 0)}


@operator_router.get("/conversations")
async def list_conversations(operator: Operator = Depends(require_role(OperatorRole.operator)), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(SupportConversation, Agent.hostname)
        .join(Agent, Agent.id == SupportConversation.agent_id, isouter=True)
        .where(client_id_filter(operator, SupportConversation.client_id))
        # Open conversations first, then most-recent activity.
        .order_by(
            (SupportConversation.status == SupportConversationStatus.closed),
            func.coalesce(SupportConversation.last_message_at, SupportConversation.created_at).desc(),
        )
    )).all()
    unread_rows = (await db.execute(
        select(SupportMessage.conversation_id, func.count())
        .join(SupportConversation, SupportMessage.conversation_id == SupportConversation.id)
        .where(
            SupportMessage.sender == SupportParty.end_user,
            SupportMessage.read_at.is_(None),
            client_id_filter(operator, SupportConversation.client_id),
        )
        .group_by(SupportMessage.conversation_id)
    )).all()
    unread = {conversation_id: count for conversation_id, count in unread_rows}
    return {"conversations": [_summary(c, hostname, unread.get(c.id, 0)) for c, hostname in rows]}


async def _visible_conversation(conversation_id, operator, db, *, minimum=None):
    conversation = await db.scalar(
        select(SupportConversation).where(SupportConversation.id == str(conversation_id)).with_for_update()
    )
    if conversation is None:
        raise HTTPException(404, detail=NOT_FOUND)
    if minimum is None:
        await assert_client_visible(operator, conversation.client_id, db, detail=NOT_FOUND)
    else:
        await assert_client_action(operator, conversation.client_id, db, minimum=minimum, detail=NOT_FOUND)
    return conversation


@operator_router.get("/conversations/{conversation_id}")
async def transcript(conversation_id: UUID, operator: Operator = Depends(require_role(OperatorRole.operator)), db: AsyncSession = Depends(get_db)):
    conversation = await _visible_conversation(conversation_id, operator, db)
    rows = (await db.execute(
        select(SupportMessage, Operator.email)
        .join(Operator, Operator.id == SupportMessage.operator_id, isouter=True)
        .where(SupportMessage.conversation_id == conversation.id)
        .order_by(SupportMessage.seq)
    )).all()
    # Opening the transcript marks the end user's delivered messages read, which
    # is what clears the nav badge.
    now = core.now()
    for message, _ in rows:
        if message.sender == SupportParty.end_user and message.read_at is None:
            message.read_at = now
    await db.flush()
    return {
        "id": conversation.id,
        "agent_id": conversation.agent_id,
        "endpoint": await db.scalar(select(Agent.hostname).where(Agent.id == conversation.agent_id)),
        "subject": conversation.subject,
        "status": conversation.status,
        "opened_by": conversation.opened_by,
        "messages": [
            {
                "seq": message.seq,
                "sender": message.sender,
                # Participant identity on every message (docs/ROADMAP.md:158): the
                # technician's email on their replies, the endpoint user otherwise.
                "operator_email": email if message.sender == SupportParty.technician else None,
                "body": message.body,
                "created_at": message.created_at,
            }
            for message, email in rows
        ],
    }


@operator_router.post("/conversations/{conversation_id}/messages", response_model=MessageOut)
async def reply(conversation_id: UUID, body: MessageIn, request: Request, operator: Operator = Depends(require_role(OperatorRole.operator)), db: AsyncSession = Depends(get_db)):
    conversation = await _visible_conversation(conversation_id, operator, db, minimum=ClientRole.client_operator)
    message = await core.append_message(db, conversation, body.body, sender=SupportParty.technician, operator_id=operator.id)
    await core.join(db, conversation, operator, **evidence(request, operator.email, operator.id))
    return message


@operator_router.post("/conversations/{conversation_id}/close")
async def close_conversation(conversation_id: UUID, request: Request, operator: Operator = Depends(require_role(OperatorRole.operator)), db: AsyncSession = Depends(get_db)):
    conversation = await _visible_conversation(conversation_id, operator, db, minimum=ClientRole.client_operator)
    await core.close(
        db,
        conversation,
        reason="operator",
        operator_id=operator.id,
        **evidence(request, operator.email, operator.id),
    )
    await db.flush()
    return {"status": "closed"}
