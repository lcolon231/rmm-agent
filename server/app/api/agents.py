# SPDX-License-Identifier: AGPL-3.0-only
"""Agent-facing endpoints: enrollment, heartbeat, command pickup/result.

These routes are called by the Go agent. Human/dashboard routes live in
management.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent
from app.core import audit
from app.core.command_envelope import (
    SUPPORTED_COMMAND_ENVELOPE_VERSIONS,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    generate_token,
    hash_token,
    public_key_pem,
    public_key_bundle_pem,
)
from app.core.keyring import active_signing_key
from app.core.timeutil import ensure_utc
from app.models.models import (
    Agent,
    AgentStatus,
    AgentTrustState,
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
        command_public_keys=public_key_bundle_pem(),
        command_signing_key_id=active_signing_key().key_id,
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

    # Quarantine: the only permitted behavior is a minimal check-in so the
    # operator can see the endpoint is alive and the agent learns its state.
    # No telemetry is recorded, no inventory accepted, no commands delivered,
    # and no signing-key material handed out.
    if agent.trust_state == AgentTrustState.quarantined:
        agent.last_seen_at = now
        return HeartbeatAck(
            ok=True,
            pending_commands=[],
            command_public_keys={},
            trust_state=agent.trust_state,
        )

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

    # The agent persists every completed/refused outcome before upload and
    # advertises that outbox here. This transition is deliberately separate
    # from terminal acknowledgement so operators can see "finished locally,
    # result delivery pending" during partial outages.
    if body.pending_results:
        notices = {notice.command_id: notice for notice in body.pending_results}
        pending_rows = await db.execute(
            select(Command)
            .where(
                Command.agent_id == agent.id,
                Command.id.in_(notices),
                Command.status.in_(
                    [
                        CommandStatus.dispatched,
                        CommandStatus.running,
                        CommandStatus.result_pending,
                    ]
                ),
            )
            .with_for_update()
        )
        for cmd in pending_rows.scalars().all():
            notice = notices[cmd.id]
            first_notice = cmd.status != CommandStatus.result_pending
            cmd.status = CommandStatus.result_pending
            if notice.agent_completed_at is not None:
                cmd.agent_completed_at = ensure_utc(notice.agent_completed_at)
            if first_notice:
                await audit.record(
                    db,
                    action="command.result_pending",
                    actor=f"agent:{agent.id}",
                    agent_id=agent.id,
                    detail={
                        "command_id": cmd.id,
                        "kind": cmd.kind.value,
                        "agent_completed_at": (
                            notice.agent_completed_at.isoformat()
                            if notice.agent_completed_at is not None
                            else None
                        ),
                    },
                )

    # Expire stale commands, then hand out at most one batch of deliverable
    # work. A dispatched command whose lease elapsed is safely re-delivered:
    # the agent's durable reservation prevents duplicate execution and repairs
    # lost heartbeat responses or stop-before-start. Oldest-first (FIFO) so
    # nothing starves, and bounded by
    # max_commands_per_heartbeat so a backlog drains over several beats rather
    # than flooding one — the agent executes them one at a time.
    pending: list[Command] = []
    selected_version = select_command_envelope_version(
        body.supported_command_envelope_versions
    )
    if selected_version is not None:
        batch = max(1, settings.max_commands_per_heartbeat)
        redelivery_before = now - timedelta(
            seconds=max(1, settings.command_redelivery_seconds)
        )
        result = await db.execute(
            select(Command)
            .where(
                Command.agent_id == agent.id,
                or_(
                    Command.status == CommandStatus.queued,
                    and_(
                        Command.status == CommandStatus.dispatched,
                        Command.dispatched_at <= redelivery_before,
                    ),
                ),
                Command.envelope_version == selected_version,
            )
            .order_by(Command.created_at.asc(), Command.id.asc())
        )
        for cmd in result.scalars().all():
            expires = ensure_utc(cmd.expires_at)
            if expires and expires < now:
                cmd.status = CommandStatus.expired
                continue
            cmd.status = CommandStatus.dispatched
            cmd.dispatched_at = now
            pending.append(cmd)
            if len(pending) >= batch:
                break

    return HeartbeatAck(
        ok=True,
        pending_commands=[CommandOut.model_validate(c) for c in pending],
        command_public_keys=public_key_bundle_pem(),
        trust_state=agent.trust_state,
    )


@router.post("/commands/{command_id}/result", status_code=status.HTTP_204_NO_CONTENT)
async def submit_result(
    command_id: str,
    body: CommandResult,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Agent reports the outcome of a command it executed."""
    # A quarantined agent may not submit results. Failing closed here means a
    # command already in flight when the operator quarantined the endpoint has
    # its output rejected rather than trusted after the fact.
    if agent.trust_state != AgentTrustState.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "agent_quarantined"},
        )
    result = await db.execute(
        select(Command)
        .where(Command.id == command_id, Command.agent_id == agent.id)
        .with_for_update()
    )
    cmd = result.scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")

    agent_completed_at = (
        ensure_utc(body.agent_completed_at)
        if body.agent_completed_at is not None
        else None
    )
    terminal = cmd.status in (CommandStatus.succeeded, CommandStatus.failed)
    same_result = (
        cmd.exit_code == body.exit_code
        and cmd.stdout == body.stdout
        and cmd.stderr == body.stderr
        and cmd.stdout_truncated == body.stdout_truncated
        and cmd.stderr_truncated == body.stderr_truncated
        and cmd.stdout_total_bytes == body.stdout_total_bytes
        and cmd.stderr_total_bytes == body.stderr_total_bytes
        and (
            ensure_utc(cmd.agent_completed_at)
            if cmd.agent_completed_at is not None
            else None
        )
        == agent_completed_at
    )
    if terminal:
        if same_result:
            # Lost HTTP acknowledgements are expected under at-least-once
            # delivery. Return success without changing timestamps or emitting
            # a duplicate audit event.
            return None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "command_result_conflict"},
        )

    if cmd.status not in (
        CommandStatus.dispatched,
        CommandStatus.running,
        CommandStatus.result_pending,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "command_not_accepting_results",
                "status": cmd.status.value,
            },
        )

    cmd.exit_code = body.exit_code
    cmd.stdout = body.stdout
    cmd.stderr = body.stderr
    cmd.stdout_truncated = body.stdout_truncated
    cmd.stderr_truncated = body.stderr_truncated
    cmd.stdout_total_bytes = body.stdout_total_bytes
    cmd.stderr_total_bytes = body.stderr_total_bytes
    cmd.agent_completed_at = agent_completed_at
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
            "agent_completed_at": (
                agent_completed_at.isoformat()
                if agent_completed_at is not None
                else None
            ),
            # Truncation is part of the accountability record: "what we stored"
            # vs "what actually happened" must be distinguishable later.
            "stdout_truncated": body.stdout_truncated,
            "stderr_truncated": body.stderr_truncated,
            "stdout_total_bytes": body.stdout_total_bytes,
            "stderr_total_bytes": body.stderr_total_bytes,
        },
    )
