# SPDX-License-Identifier: AGPL-3.0-only
"""Chat write boundary. Callers own transactions and acquire row locks first."""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlencode, urlsplit

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.config import settings
from app.core.redaction import scrub_text
from app.core.security import hash_token
from app.models.models import Agent, Site, SupportConversation, SupportConversationStatus, SupportMessage, SupportParty


def now():
    return datetime.now(timezone.utc)


def utc(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def fail(code, status=400):
    raise HTTPException(status, detail={"code": "support_chat_" + code})


def base_url():
    base = (settings.support_chat_base_url or "").rstrip("/")
    parsed = urlsplit(base)
    local = settings.debug and parsed.hostname in ("localhost", "127.0.0.1")
    if (not parsed.hostname or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment or (parsed.scheme != "https" and not (local and parsed.scheme == "http"))):
        fail("not_configured", 503)
    return base


def rotate(conversation):
    token = secrets.token_urlsafe(32)
    conversation.token_hash = hash_token(token)
    conversation.token_expires_at = now() + timedelta(seconds=settings.support_chat_token_ttl_seconds)
    return token


def technician_launch_url(conversation):
    """Return a reconstructable credential URL without storing plaintext."""
    if not conversation.token_expires_at or utc(conversation.token_expires_at) <= now():
        conversation.token_expires_at = now() + timedelta(
            seconds=settings.support_chat_token_ttl_seconds
        )
    material = (
        f"support-chat-launch-v1:{conversation.id}:"
        f"{utc(conversation.token_expires_at).isoformat()}"
    ).encode("utf-8")
    digest = hmac.new(
        settings.secret_key.encode("utf-8"), material, hashlib.sha256
    ).digest()
    token = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    conversation.token_hash = hash_token(token)
    return base_url() + "/chat#" + urlencode(
        {"c": conversation.id, "t": token, "expires": conversation.token_expires_at.isoformat()}
    )


def verify(conversation, token):
    if not hmac.compare_digest(hash_token(token), conversation.token_hash):
        fail("token_invalid", 403)
    if utc(conversation.token_expires_at) <= now():
        fail("token_expired", 401)


async def message_count(db, conversation_id):
    return int(await db.scalar(select(func.count()).select_from(SupportMessage).where(SupportMessage.conversation_id == conversation_id)) or 0)


# Lifecycle audit (issue #237). Every event carries identifiers, counts, and
# versions only: a message body, subject, or chat token never enters the chain,
# so transcripts can age out under retention while the record that a
# conversation happened, who joined it, and when it closed is kept forever.

async def audit_opened(db, conversation, **evidence):
    await audit.record(
        db,
        action="support_chat.opened",
        agent_id=conversation.agent_id,
        detail={
            "conversation_id": conversation.id,
            "opened_by": SupportParty(conversation.opened_by).value,
            "message_count": await message_count(db, conversation.id),
        },
        **evidence,
    )


async def audit_token_minted(db, conversation, reason, **evidence):
    await audit.record(
        db,
        action="support_chat.token_minted",
        agent_id=conversation.agent_id,
        detail={
            "conversation_id": conversation.id,
            "reason": reason,
            "token_expires_at": utc(conversation.token_expires_at).isoformat(),
            "message_count": await message_count(db, conversation.id),
        },
        **evidence,
    )


async def audit_notice_acknowledged(db, conversation, **evidence):
    await audit.record(
        db,
        action="support_chat.notice_acknowledged",
        agent_id=conversation.agent_id,
        detail={
            "conversation_id": conversation.id,
            "notice_version": conversation.notice_version,
            "message_count": await message_count(db, conversation.id),
        },
        **evidence,
    )


async def join(db, conversation, operator, **evidence):
    """Audit a technician's first reply in a conversation as joining it.

    Called after the reply is appended, so a refused reply never records a join.
    """
    replies = await db.scalar(select(func.count()).select_from(SupportMessage).where(
        SupportMessage.conversation_id == conversation.id,
        SupportMessage.operator_id == operator.id,
    ))
    if replies != 1:
        return
    await audit.record(
        db,
        action="support_chat.technician_joined",
        agent_id=conversation.agent_id,
        detail={
            "conversation_id": conversation.id,
            "message_count": await message_count(db, conversation.id),
        },
        **evidence,
    )


async def close(db, conversation, *, reason, operator_id=None, **evidence):
    """Close a conversation, invalidate its token, and audit it. Idempotent.

    Only a technician closes a conversation; there is no idle auto-close, so an
    unanswered request is never dropped. The end user contacting support again
    continues an open conversation, or starts a new one once this has closed.
    """
    if conversation.status == SupportConversationStatus.closed:
        return False
    conversation.status = SupportConversationStatus.closed
    conversation.closed_at = now()
    conversation.closed_by_operator_id = operator_id
    conversation.token_hash = ""  # invalidate the end user's chat token
    evidence.setdefault("agent_id", conversation.agent_id)
    await audit.record(
        db,
        action="support_chat.closed",
        detail={
            "conversation_id": conversation.id,
            "reason": reason,
            "message_count": await message_count(db, conversation.id),
        },
        **evidence,
    )
    return True


def require_open(conversation):
    if conversation.status != SupportConversationStatus.open:
        fail("conversation_closed", 409)


async def open_conversation(db: AsyncSession, agent: Agent, **evidence):
    origin = base_url()
    # The caller locks the agent, serializing even the first open (no chat row yet).
    # An open conversation is continued however long it has been quiet; only a
    # technician's close ends it, after which the next contact starts a new one.
    active = list((await db.scalars(select(SupportConversation).where(
        SupportConversation.agent_id == agent.id,
        SupportConversation.status == SupportConversationStatus.open,
    ).with_for_update())).all())
    if len(active) > settings.support_chat_max_open_per_agent:
        fail("open_limit")
    created = not active
    if active:
        conversation = active[0]
    else:
        client_id = await db.scalar(select(Site.client_id).where(Site.id == agent.site_id))
        if client_id is None:
            fail("agent_unassigned", 409)
        conversation = SupportConversation(agent_id=agent.id, client_id=client_id)
        db.add(conversation)
    token = rotate(conversation)
    # Reopening is a new browser context, with a fresh disclosure acknowledgment.
    conversation.notice_version = None
    conversation.notice_acknowledged_at = None
    await db.flush()
    if created:
        await audit_opened(db, conversation, **evidence)
    await audit_token_minted(db, conversation, "open", **evidence)
    # A fragment never reaches access logs or the Referer header.
    url = origin + "/chat#" + urlencode({"c": conversation.id, "t": token, "expires": conversation.token_expires_at.isoformat()})
    return {"conversation_id": conversation.id, "url": url, "token_expires_at": conversation.token_expires_at}


async def open_technician_conversation(
    db: AsyncSession, agent: Agent, **evidence
) -> SupportConversation:
    """Open or reuse the single conversation for an endpoint."""
    base_url()
    active = list(
        (
            await db.scalars(
                select(SupportConversation)
                .where(
                    SupportConversation.agent_id == agent.id,
                    SupportConversation.status == SupportConversationStatus.open,
                )
                .with_for_update()
            )
        ).all()
    )
    if len(active) > settings.support_chat_max_open_per_agent:
        fail("open_limit")
    if active:
        return active[0]

    client_id = await db.scalar(select(Site.client_id).where(Site.id == agent.site_id))
    if client_id is None:
        fail("agent_unassigned", 409)
    conversation = SupportConversation(
        agent_id=agent.id,
        client_id=client_id,
        opened_by=SupportParty.technician,
    )
    # Supply non-null values for the initial INSERT; after the generated ID is
    # available the random token is replaced by the reconstructable one.
    rotate(conversation)
    db.add(conversation)
    await db.flush()
    technician_launch_url(conversation)
    await db.flush()
    await audit_opened(db, conversation, **evidence)
    await audit_token_minted(db, conversation, "technician_launch", **evidence)
    return conversation


async def append_message(db, conversation, body, *, sender=SupportParty.end_user, operator_id=None):
    if conversation.status is not SupportConversationStatus.open:
        fail("conversation_closed", 409)
    # The consent notice gates the end user's first message; a technician reply
    # is not consenting to recording, so it is not subject to that gate.
    if sender is SupportParty.end_user and (conversation.notice_version != settings.support_chat_notice_version or not conversation.notice_acknowledged_at):
        fail("notice_required", 409)
    if not body.strip():
        fail("message_empty")
    if len(body.encode("utf-8")) > settings.support_chat_max_message_bytes:
        fail("message_too_large")
    scrubbed = scrub_text(body)
    if len(scrubbed.encode("utf-8")) > settings.support_chat_max_message_bytes:
        fail("message_too_large")
    count = await db.scalar(select(func.count()).select_from(SupportMessage).where(SupportMessage.conversation_id == conversation.id))
    if count >= settings.support_chat_max_messages:
        fail("message_limit")
    seq = (await db.scalar(select(func.max(SupportMessage.seq)).where(SupportMessage.conversation_id == conversation.id)) or 0) + 1
    message = SupportMessage(conversation_id=conversation.id, seq=seq, sender=sender, operator_id=operator_id, body=scrubbed)
    db.add(message)
    conversation.last_message_at = now()
    if not conversation.subject:
        conversation.subject = scrubbed[:120]
    await db.flush()
    return message
