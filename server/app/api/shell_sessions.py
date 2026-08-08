# SPDX-License-Identifier: AGPL-3.0-only
"""Operator-facing interactive shell session lifecycle (issue #61), Phase 1.

This module lands the authorized, audited, bounded session *contract*: open,
status, and close, with fail-closed authorization, an agent-capability gate, and
single-active-session admission. The live streaming frame relay (input/output
long-poll and the agent attach path) is a later phase; until an agent advertises
the capability and attaches, a session stays ``pending`` and the operator sees a
clearly bounded, non-streaming state.

Authorization mirrors command dispatch: an interactive shell is at least as
privileged as running an arbitrary script, so it requires the same explicit
script-execution scope on the operator, a trusted agent, and the advertised
capability. Nothing here ever stores or logs streamed I/O bytes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.core.script_authorization import authorize_command
from app.models.models import (
    Agent,
    AgentTrustState,
    CommandKind,
    Operator,
    OperatorRole,
    ShellSession,
    ShellSessionStatus,
)
from app.schemas.shell_sessions import (
    ShellSessionClose,
    ShellSessionOpen,
    ShellSessionOut,
)

# The agent capability that authorizes a session. An agent that does not
# advertise this fails closed as "unsupported" rather than being offered a shell.
SHELL_SESSION_CAPABILITY = "shell-session-v1"

router = APIRouter(
    tags=["shell-sessions"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)

# The non-terminal states that hold the single-active-session admission slot.
_LIVE_STATES = (ShellSessionStatus.pending, ShellSessionStatus.active)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_evidence(request: Request, operator: Operator) -> dict[str, Any]:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


async def _record_denied(
    db: AsyncSession,
    agent: Agent,
    *,
    reason: str,
    policy: str,
    evidence: dict[str, Any],
) -> None:
    """Audit a fail-closed open refusal, then commit so the record survives the
    HTTPException rollback. No session row is created on denial."""
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
    """Open a bounded, authorized shell session against an agent.

    Fail-closed order: authorize (arbitrary-script scope), require a trusted
    agent, require the advertised capability, then admit at most one live
    session per agent. Every refusal is audited before the error is raised.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    evidence = _request_evidence(request, operator)

    # A shell session is at least as powerful as running an arbitrary script, so
    # it requires the same explicit script-execution authorization.
    decision = authorize_command(operator, agent, CommandKind.powershell)
    if not decision.allowed:
        await _record_denied(
            db, agent, reason=decision.reason, policy=decision.policy, evidence=evidence
        )
        raise HTTPException(
            status_code=403,
            detail={"code": "shell_session_not_authorized"},
        )

    # Trust gate: never open a live channel to an agent we no longer fully trust.
    if agent.trust_state != AgentTrustState.active:
        await _record_denied(
            db, agent, reason="agent_not_trusted", policy="trust_gate", evidence=evidence
        )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_not_trusted",
                "trust_state": agent.trust_state.value,
            },
        )

    # Capability gate: the agent must advertise interactive-shell support.
    capabilities = agent.supported_capabilities or []
    if SHELL_SESSION_CAPABILITY not in capabilities:
        await _record_denied(
            db,
            agent,
            reason="shell_session_unsupported",
            policy="capability_gate",
            evidence=evidence,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "shell_session_unsupported",
                "required_capability": SHELL_SESSION_CAPABILITY,
            },
        )

    # Admission: at most one live (pending or active) session per agent.
    live = (
        await db.execute(
            select(func.count())
            .select_from(ShellSession)
            .where(
                ShellSession.agent_id == agent_id,
                ShellSession.status.in_(_LIVE_STATES),
            )
        )
    ).scalar_one()
    if live >= settings.shell_session_max_concurrent_per_agent:
        await _record_denied(
            db,
            agent,
            reason="shell_session_already_active",
            policy="admission",
            evidence=evidence,
        )
        raise HTTPException(
            status_code=409,
            detail={"code": "shell_session_already_active"},
        )

    now = _now()
    session_row = ShellSession(
        agent_id=agent_id,
        operator_id=operator.id,
        actor_email=operator.email,
        status=ShellSessionStatus.pending,
        capability_version=SHELL_SESSION_CAPABILITY,
        created_at=now,
        last_activity_at=now,
        absolute_deadline=now
        + timedelta(seconds=settings.shell_session_max_lifetime_seconds),
        idle_deadline=now
        + timedelta(seconds=settings.shell_session_idle_timeout_seconds),
        output_bytes_limit=settings.shell_session_output_byte_limit,
    )
    db.add(session_row)
    await db.flush()

    await audit.record(
        db,
        action="shell_session.opened",
        agent_id=agent.id,
        detail={
            "session_id": session_row.id,
            "capability_version": session_row.capability_version,
            "output_bytes_limit": session_row.output_bytes_limit,
            "absolute_deadline": session_row.absolute_deadline.isoformat(),
            "idle_deadline": session_row.idle_deadline.isoformat(),
        },
        **evidence,
    )
    return session_row


async def _get_session(
    db: AsyncSession, agent_id: str, session_id: str
) -> ShellSession:
    session_row = (
        await db.execute(
            select(ShellSession).where(
                ShellSession.id == session_id,
                ShellSession.agent_id == agent_id,
            )
        )
    ).scalar_one_or_none()
    if session_row is None:
        raise HTTPException(status_code=404, detail="Shell session not found")
    return session_row


@router.get(
    "/agents/{agent_id}/shell-sessions/{session_id}",
    response_model=ShellSessionOut,
)
async def get_shell_session(
    agent_id: str,
    session_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Read a session's lifecycle state. The read itself is audited."""
    session_row = await _get_session(db, agent_id, session_id)
    await audit.record(
        db,
        action="shell_session.viewed",
        agent_id=agent_id,
        detail={"session_id": session_row.id, "status": session_row.status.value},
        **_request_evidence(request, operator),
    )
    return session_row


@router.post(
    "/agents/{agent_id}/shell-sessions/{session_id}/close",
    response_model=ShellSessionOut,
)
async def close_shell_session(
    agent_id: str,
    session_id: str,
    body: ShellSessionClose,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Close a session. Idempotent: closing an already-terminal session returns
    its current state without re-auditing."""
    session_row = await _get_session(db, agent_id, session_id)
    if session_row.status in (
        ShellSessionStatus.closed,
        ShellSessionStatus.timed_out,
        ShellSessionStatus.denied,
        ShellSessionStatus.failed,
    ):
        return session_row

    session_row.status = ShellSessionStatus.closed
    session_row.close_reason = (body.reason or "operator_closed")[:64]
    session_row.closed_at = _now()
    await audit.record(
        db,
        action="shell_session.closed",
        agent_id=agent_id,
        detail={
            "session_id": session_row.id,
            "status": session_row.status.value,
            "reason": session_row.close_reason,
            "output_bytes_total": session_row.output_bytes_total,
            "frames_in": session_row.frames_in,
            "frames_out": session_row.frames_out,
        },
        **_request_evidence(request, operator),
    )
    return session_row
