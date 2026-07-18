"""Agent-facing endpoints: enrollment, heartbeat, command pickup/result.

These routes are called by the Go agent. Human/dashboard routes live in
management.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent
from app.core import audit
from app.core.command_envelope import (
    COMMAND_ENVELOPE_V1,
    SUPPORTED_COMMAND_ENVELOPE_VERSIONS,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    generate_token,
    hash_token,
    public_key_pem,
)
from app.core.timeutil import ensure_utc
from app.models.models import (
    Agent,
    AgentStatus,
    Command,
    CommandStatus,
    EnrollmentToken,
)
from app.schemas.schemas import (
    CommandOut,
    CommandResult,
    EnrollRequest,
    EnrollResponse,
    HeartbeatAck,
    HeartbeatIn,
)

router = APIRouter(tags=["agent"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(body: EnrollRequest, db: AsyncSession = Depends(get_db)):
    """Claim an agent identity using a site enrollment token.

    The plaintext agent token is returned exactly once here; the agent must
    persist it. Server keeps only the hash.
    """
    selected_version = select_command_envelope_version(
        body.supported_command_envelope_versions
    )
    if selected_version is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "no_common_command_envelope_version",
                "server_supported": list(SUPPORTED_COMMAND_ENVELOPE_VERSIONS),
            },
        )

    result = await db.execute(
        select(EnrollmentToken).where(
            EnrollmentToken.token_hash == hash_token(body.enrollment_token)
        )
    )
    etoken = result.scalar_one_or_none()
    if etoken is None or not etoken.is_usable:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment token is invalid, expired, or exhausted",
        )

    agent_token = generate_token()
    agent = Agent(
        site_id=etoken.site_id,
        token_hash=hash_token(agent_token),
        hostname=body.hostname,
        os=body.os,
        os_version=body.os_version,
        agent_version=body.agent_version,
        command_envelope_versions=body.supported_command_envelope_versions,
        status=AgentStatus.pending,
    )
    db.add(agent)
    etoken.uses += 1
    await db.flush()

    await audit.record(
        db,
        action="agent.enrolled",
        actor=f"installer:{etoken.id}",
        agent_id=agent.id,
        detail={
            "hostname": body.hostname,
            "os": body.os,
            "site_id": etoken.site_id,
            "command_envelope_version": selected_version,
            "supported_command_envelope_versions": body.supported_command_envelope_versions,
        },
    )

    return EnrollResponse(
        agent_id=agent.id,
        agent_token=agent_token,
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
        command_public_key=public_key_pem(),
        command_envelope_version=selected_version,
    )


@router.post("/heartbeat", response_model=HeartbeatAck)
async def heartbeat(
    body: HeartbeatIn,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Record a telemetry sample and hand back any queued commands.

    Without a persistent WebSocket, this doubles as the command-poll: the ack
    carries commands that are queued and not yet expired.
    """
    from app.models.models import Heartbeat  # local import avoids cycle noise

    now = _now()
    db.add(
        Heartbeat(
            agent_id=agent.id,
            cpu_percent=body.cpu_percent,
            mem_percent=body.mem_percent,
            disk_percent=body.disk_percent,
            uptime_seconds=body.uptime_seconds,
            logged_in_user=body.logged_in_user,
        )
    )
    agent.last_seen_at = now
    agent.status = AgentStatus.online
    previous_versions = list(agent.command_envelope_versions or [])
    agent.command_envelope_versions = body.supported_command_envelope_versions
    if body.inventory is not None:
        agent.inventory = body.inventory

    if previous_versions != body.supported_command_envelope_versions:
        await audit.record(
            db,
            action="agent.command_envelope_capabilities_changed",
            actor=f"agent:{agent.id}",
            agent_id=agent.id,
            detail={
                "previous": previous_versions,
                "current": body.supported_command_envelope_versions,
            },
        )

    # Expire stale commands, then fetch what's still deliverable.
    pending: list[Command] = []
    if COMMAND_ENVELOPE_V1 in body.supported_command_envelope_versions:
        result = await db.execute(
            select(Command).where(
                Command.agent_id == agent.id,
                Command.status == CommandStatus.queued,
                Command.envelope_version == COMMAND_ENVELOPE_V1,
            )
        )
        for cmd in result.scalars().all():
            expires = ensure_utc(cmd.expires_at)
            if expires and expires < now:
                cmd.status = CommandStatus.expired
                continue
            cmd.status = CommandStatus.dispatched
            cmd.dispatched_at = now
            pending.append(cmd)

    return HeartbeatAck(
        ok=True,
        pending_commands=[CommandOut.model_validate(c) for c in pending],
    )


@router.post("/commands/{command_id}/result", status_code=status.HTTP_204_NO_CONTENT)
async def submit_result(
    command_id: str,
    body: CommandResult,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Agent reports the outcome of a command it executed."""
    result = await db.execute(
        select(Command).where(
            Command.id == command_id, Command.agent_id == agent.id
        )
    )
    cmd = result.scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")

    cmd.exit_code = body.exit_code
    cmd.stdout = body.stdout
    cmd.stderr = body.stderr
    cmd.status = (
        CommandStatus.succeeded if body.exit_code == 0 else CommandStatus.failed
    )
    cmd.completed_at = _now()

    await audit.record(
        db,
        action="command.completed",
        actor=f"agent:{agent.id}",
        agent_id=agent.id,
        detail={
            "command_id": cmd.id,
            "kind": cmd.kind.value,
            "exit_code": body.exit_code,
            "status": cmd.status.value,
        },
    )
