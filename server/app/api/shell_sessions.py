# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticated, bounded interactive shell transport (issue #61)."""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent, require_role
from app.core import audit
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.core.script_authorization import authorize_command
from app.core.tenant_scope import assert_agent_visible
from app.core.shell_relay import (
    Backpressure,
    CursorExpired,
    RelayClosed,
    RelayFrame,
    SequenceConflict,
    registry,
)
from app.models.models import (
    Agent,
    AgentTrustState,
    ClientRole,
    CommandKind,
    Operator,
    OperatorRole,
    ShellSession,
    ShellSessionStatus,
)
from app.schemas.shell_sessions import (
    ShellAgentAttachOut,
    ShellAgentComplete,
    ShellFrameBatch,
    ShellFrameIn,
    ShellFrameOut,
    ShellSessionClose,
    ShellSessionOpen,
    ShellSessionOut,
)

# v1 was lifecycle advertisement only. v2 means the agent implements attach,
# framed I/O, acknowledgements, reconnect, and bounded output.
SHELL_SESSION_CAPABILITY = "shell-session-v2"

router = APIRouter(
    tags=["shell-sessions"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)
agent_router = APIRouter(tags=["agent-shell-sessions"])

_LIVE_STATES = (ShellSessionStatus.pending, ShellSessionStatus.active)
_TERMINAL_STATES = (
    ShellSessionStatus.closed,
    ShellSessionStatus.timed_out,
    ShellSessionStatus.denied,
    ShellSessionStatus.failed,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_evidence(request: Request, operator: Operator) -> dict[str, Any]:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def _agent_evidence(request: Request, agent: Agent) -> dict[str, Any]:
    return {
        "actor": f"agent:{agent.id}",
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def _decode_frame(body: ShellFrameIn, allowed_streams: set[str]) -> RelayFrame:
    if body.stream not in allowed_streams:
        raise HTTPException(422, detail={"code": "shell_stream_invalid"})
    try:
        decoded = base64.b64decode(body.data_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, detail={"code": "shell_frame_base64_invalid"})
    if not decoded and not body.eof and body.stream != "control":
        raise HTTPException(422, detail={"code": "shell_frame_empty"})
    if len(decoded) > settings.shell_session_max_frame_bytes:
        raise HTTPException(413, detail={"code": "shell_frame_too_large"})
    return RelayFrame(
        seq=body.seq,
        stream=body.stream,
        data_b64=body.data_b64,
        eof=body.eof,
        byte_length=len(decoded),
    )


def _frames_out(frames: list[RelayFrame]) -> list[ShellFrameOut]:
    return [
        ShellFrameOut(
            seq=frame.seq,
            stream=frame.stream,
            data_b64=frame.data_b64,
            eof=frame.eof,
            byte_length=frame.byte_length,
        )
        for frame in frames
    ]


def _touch(row: ShellSession) -> None:
    now = _now()
    row.last_activity_at = now
    idle = now + timedelta(seconds=settings.shell_session_idle_timeout_seconds)
    absolute = row.absolute_deadline
    if absolute is not None and absolute.tzinfo is None:
        absolute = absolute.replace(tzinfo=timezone.utc)
    row.idle_deadline = min(idle, absolute) if absolute else idle


async def _record_denied(
    db: AsyncSession,
    agent: Agent,
    *,
    reason: str,
    policy: str,
    evidence: dict[str, Any],
) -> None:
    await audit.record(
        db,
        action="shell_session.denied",
        agent_id=agent.id,
        detail={
            "session_id": None,
            "reason": reason,
            "policy": policy,
            "trust_state": agent.trust_state.value,
        },
        **evidence,
    )
    await db.commit()


async def _get_session(db: AsyncSession, agent_id: str, session_id: str) -> ShellSession:
    row = (
        await db.execute(
            select(ShellSession).where(
                ShellSession.id == session_id,
                ShellSession.agent_id == agent_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Shell session not found")
    return row


def _require_owner(row: ShellSession, operator: Operator) -> None:
    # Return 404 so a second operator cannot use this endpoint as a session-ID
    # oracle. Admins can inspect lifecycle evidence through the audit log.
    if row.operator_id != operator.id:
        raise HTTPException(404, detail="Shell session not found")


def _require_live(row: ShellSession) -> None:
    if row.status not in _LIVE_STATES:
        raise HTTPException(409, detail={"code": "shell_session_not_live"})


async def _relay_for(row: ShellSession):
    relay = await registry.get(row.id)
    if relay is None:
        raise HTTPException(409, detail={"code": "shell_relay_unavailable"})
    return relay


def _relay_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, Backpressure):
        return HTTPException(
            429,
            detail={"code": exc.code},
            headers={"Retry-After": "1"},
        )
    if isinstance(exc, CursorExpired):
        return HTTPException(409, detail={"code": exc.code})
    if isinstance(exc, (SequenceConflict, RelayClosed)):
        return HTTPException(409, detail={"code": exc.code})
    raise exc


@router.post(
    "/agents/{agent_id}/shell-sessions",
    response_model=ShellSessionOut,
    status_code=status.HTTP_201_CREATED,
)
async def open_shell_session(
    agent_id: str,
    body: ShellSessionOpen,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, detail="Agent not found")
    await assert_agent_visible(
        operator, agent, db,
        minimum=ClientRole.client_operator, detail="Agent not found",
    )
    evidence = _request_evidence(request, operator)
    authorization = authorize_command(operator, agent, CommandKind.powershell)
    if not authorization.allowed:
        await _record_denied(
            db,
            agent,
            reason="shell_session_not_authorized",
            policy=authorization.policy,
            evidence=evidence,
        )
        raise HTTPException(403, detail={"code": "shell_session_not_authorized"})
    if agent.trust_state != AgentTrustState.active:
        await _record_denied(
            db, agent, reason="agent_not_trusted", policy="trust_state", evidence=evidence
        )
        raise HTTPException(409, detail={"code": "agent_not_trusted"})
    if SHELL_SESSION_CAPABILITY not in (agent.supported_capabilities or []):
        await _record_denied(
            db,
            agent,
            reason="shell_session_unsupported",
            policy="capability",
            evidence=evidence,
        )
        raise HTTPException(409, detail={"code": "shell_session_unsupported"})
    live_rows = (
        await db.execute(
            select(ShellSession)
            .where(
                ShellSession.agent_id == agent_id,
                ShellSession.status.in_(_LIVE_STATES),
            )
            .order_by(ShellSession.created_at)
            .limit(settings.shell_session_max_concurrent_per_agent)
        )
    ).scalars().all()
    # A repeated open by the owner is an idempotent reconnect. This covers a
    # lost create response and lets the dashboard recover its live session
    # after a browser transport interruption without creating a second shell.
    if live_rows and live_rows[0].operator_id == operator.id:
        return live_rows[0]
    if len(live_rows) >= settings.shell_session_max_concurrent_per_agent:
        await _record_denied(
            db,
            agent,
            reason="shell_session_already_active",
            policy="admission",
            evidence=evidence,
        )
        raise HTTPException(409, detail={"code": "shell_session_already_active"})

    now = _now()
    row = ShellSession(
        agent_id=agent_id,
        operator_id=operator.id,
        actor_email=operator.email,
        status=ShellSessionStatus.pending,
        capability_version=SHELL_SESSION_CAPABILITY,
        created_at=now,
        last_activity_at=now,
        absolute_deadline=now + timedelta(seconds=settings.shell_session_max_lifetime_seconds),
        idle_deadline=now + timedelta(seconds=settings.shell_session_idle_timeout_seconds),
        output_bytes_limit=settings.shell_session_output_byte_limit,
    )
    db.add(row)
    await db.flush()
    await registry.create(
        row.id,
        max_input_bytes=settings.shell_session_input_buffer_bytes,
        max_output_bytes=settings.shell_session_relay_buffer_bytes,
        max_frames=settings.shell_session_relay_max_frames,
    )
    await audit.record(
        db,
        action="shell_session.opened",
        agent_id=agent.id,
        detail={
            "session_id": row.id,
            "capability_version": row.capability_version,
            "output_bytes_limit": row.output_bytes_limit,
            "absolute_deadline": row.absolute_deadline.isoformat(),
            "idle_deadline": row.idle_deadline.isoformat(),
        },
        **evidence,
    )
    return row


@router.get("/agents/{agent_id}/shell-sessions/{session_id}", response_model=ShellSessionOut)
async def get_shell_session(
    agent_id: str,
    session_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_session(db, agent_id, session_id)
    _require_owner(row, operator)
    await audit.record(
        db,
        action="shell_session.viewed",
        agent_id=agent_id,
        detail={"session_id": row.id, "status": row.status.value},
        **_request_evidence(request, operator),
    )
    return row


@router.post("/agents/{agent_id}/shell-sessions/{session_id}/input", response_model=ShellSessionOut)
async def send_shell_input(
    agent_id: str,
    session_id: str,
    body: ShellFrameIn,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_session(db, agent_id, session_id)
    _require_owner(row, operator)
    _require_live(row)
    frame = _decode_frame(body, {"input", "control"})
    relay = await _relay_for(row)
    try:
        accepted = await relay.append("input", frame)
    except Exception as exc:
        raise _relay_http_error(exc)
    if accepted:
        row.client_last_seq = frame.seq
        row.frames_in += 1
        _touch(row)
    return row


@router.get(
    "/agents/{agent_id}/shell-sessions/{session_id}/output",
    response_model=ShellFrameBatch,
)
async def read_shell_output(
    agent_id: str,
    session_id: str,
    after: int = Query(0, ge=0),
    ack: int = Query(0, ge=0),
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_session(db, agent_id, session_id)
    _require_owner(row, operator)
    if row.status in _TERMINAL_STATES:
        return ShellFrameBatch(session=row, frames=[])
    relay = await _relay_for(row)
    try:
        frames = await relay.read(
            "output",
            after=after,
            ack=ack,
            limit=64,
            timeout=settings.shell_session_poll_timeout_seconds,
        )
    except Exception as exc:
        raise _relay_http_error(exc)
    return ShellFrameBatch(session=row, frames=_frames_out(frames))


@router.post("/agents/{agent_id}/shell-sessions/{session_id}/close", response_model=ShellSessionOut)
async def close_shell_session(
    agent_id: str,
    session_id: str,
    body: ShellSessionClose,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_session(db, agent_id, session_id)
    _require_owner(row, operator)
    if row.status in _TERMINAL_STATES:
        return row
    row.status = ShellSessionStatus.closed
    row.close_reason = (body.reason or "operator_closed")[:64]
    row.closed_at = _now()
    await registry.close(row.id)
    await audit.record(
        db,
        action="shell_session.closed",
        agent_id=agent_id,
        detail={
            "session_id": row.id,
            "status": row.status.value,
            "reason": row.close_reason,
            "output_bytes_total": row.output_bytes_total,
            "frames_in": row.frames_in,
            "frames_out": row.frames_out,
        },
        **_request_evidence(request, operator),
    )
    return row


@agent_router.post("/agents/me/shell-sessions/attach", response_model=ShellAgentAttachOut)
async def attach_shell_session(
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            select(ShellSession)
            .where(ShellSession.agent_id == agent.id, ShellSession.status.in_(_LIVE_STATES))
            .order_by(ShellSession.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return ShellAgentAttachOut(session=None)
    if agent.trust_state != AgentTrustState.active:
        return ShellAgentAttachOut(session=None)
    relay = await registry.get(row.id)
    if row.status == ShellSessionStatus.active and relay is None:
        row.status = ShellSessionStatus.failed
        row.close_reason = "relay_unavailable"
        row.closed_at = _now()
        await audit.record(
            db,
            action="shell_session.failed",
            agent_id=agent.id,
            detail={
                "session_id": row.id,
                "reason": row.close_reason,
                "output_bytes_total": row.output_bytes_total,
                "output_bytes_limit": row.output_bytes_limit,
                "frames_in": row.frames_in,
                "frames_out": row.frames_out,
            },
            **_agent_evidence(request, agent),
        )
        return ShellAgentAttachOut(session=None)
    if relay is None:
        relay = await registry.create(
            row.id,
            input_seq=row.client_last_seq,
            output_seq=row.agent_last_seq,
            max_input_bytes=settings.shell_session_input_buffer_bytes,
            max_output_bytes=settings.shell_session_relay_buffer_bytes,
            max_frames=settings.shell_session_relay_max_frames,
        )
    if row.status == ShellSessionStatus.pending:
        row.status = ShellSessionStatus.active
        row.activated_at = _now()
        _touch(row)
        await audit.record(
            db,
            action="shell_session.activated",
            agent_id=agent.id,
            detail={"session_id": row.id, "capability_version": row.capability_version},
            **_agent_evidence(request, agent),
        )
    return ShellAgentAttachOut(session=row)


async def _get_agent_session(db: AsyncSession, agent: Agent, session_id: str) -> ShellSession:
    if agent.trust_state != AgentTrustState.active:
        raise HTTPException(409, detail={"code": "agent_not_trusted"})
    row = await _get_session(db, agent.id, session_id)
    _require_live(row)
    return row


@agent_router.get(
    "/agents/me/shell-sessions/{session_id}/input",
    response_model=ShellFrameBatch,
)
async def read_shell_input(
    session_id: str,
    after: int = Query(0, ge=0),
    ack: int = Query(0, ge=0),
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_agent_session(db, agent, session_id)
    relay = await _relay_for(row)
    try:
        frames = await relay.read(
            "input",
            after=after,
            ack=ack,
            limit=64,
            timeout=settings.shell_session_poll_timeout_seconds,
        )
    except Exception as exc:
        raise _relay_http_error(exc)
    return ShellFrameBatch(session=row, frames=_frames_out(frames))


@agent_router.post(
    "/agents/me/shell-sessions/{session_id}/output",
    response_model=ShellSessionOut,
)
async def send_shell_output(
    session_id: str,
    body: ShellFrameIn,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_agent_session(db, agent, session_id)
    frame = _decode_frame(body, {"stdout", "stderr", "control"})
    limit = row.output_bytes_limit or settings.shell_session_output_byte_limit
    if frame.seq > row.agent_last_seq and row.output_bytes_total + frame.byte_length > limit:
        row.status = ShellSessionStatus.failed
        row.close_reason = "output_limit"
        row.closed_at = _now()
        await registry.close(row.id)
        await audit.record(
            db,
            action="shell_session.failed",
            agent_id=agent.id,
            detail={
                "session_id": row.id,
                "reason": row.close_reason,
                "output_bytes_total": row.output_bytes_total,
                "output_bytes_limit": limit,
                "frames_in": row.frames_in,
                "frames_out": row.frames_out,
            },
            **_agent_evidence(request, agent),
        )
        await db.commit()
        raise HTTPException(413, detail={"code": "shell_output_limit"})
    relay = await _relay_for(row)
    try:
        accepted = await relay.append("output", frame)
    except Exception as exc:
        raise _relay_http_error(exc)
    if accepted:
        row.agent_last_seq = frame.seq
        row.frames_out += 1
        row.output_bytes_total += frame.byte_length
        _touch(row)
    return row


@agent_router.post(
    "/agents/me/shell-sessions/{session_id}/complete",
    response_model=ShellSessionOut,
)
async def complete_shell_session(
    session_id: str,
    body: ShellAgentComplete,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_session(db, agent.id, session_id)
    if row.status in _TERMINAL_STATES:
        return row
    row.status = (
        ShellSessionStatus.failed if body.status == "failed" else ShellSessionStatus.closed
    )
    row.close_reason = (body.reason or "agent_completed")[:64]
    row.closed_at = _now()
    await registry.close(row.id)
    detail = {
        "session_id": row.id,
        "reason": row.close_reason,
        "output_bytes_total": row.output_bytes_total,
        "frames_in": row.frames_in,
        "frames_out": row.frames_out,
    }
    if row.status == ShellSessionStatus.failed:
        detail["output_bytes_limit"] = row.output_bytes_limit
    else:
        detail["status"] = row.status.value
    if row.status == ShellSessionStatus.failed:
        await audit.record(
            db,
            action="shell_session.failed",
            agent_id=agent.id,
            detail=detail,
            **_agent_evidence(request, agent),
        )
    else:
        await audit.record(
            db,
            action="shell_session.closed",
            agent_id=agent.id,
            detail=detail,
            **_agent_evidence(request, agent),
        )
    return row
