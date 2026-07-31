# SPDX-License-Identifier: AGPL-3.0-only
"""Agent-facing endpoints: enrollment, heartbeat, command pickup/result.

These routes are called by the Go agent. Human/dashboard routes live in
management.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent
from app.core import audit, inventory, metrics
from app.core.clientip import client_ip
from app.core.command_envelope import (
    SUPPORTED_COMMAND_ENVELOPE_VERSIONS,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.enrollment import EnrollmentRejected, redeem_enrollment_token
from app.core.security import (
    generate_token,
    hash_token,
    credential_fingerprint,
    public_key_pem,
    public_key_bundle_pem,
)
from app.core.keyring import active_signing_key
from app.core.ratelimit import enrollment_limiter
from app.core.timeutil import ensure_utc
from app.models.models import (
    Agent,
    AgentStatus,
    AgentTrustState,
    Command,
    CommandStatus,
    Site,
)
from app.schemas.inventory import (
    InventorySubmission,
    canonical_inventory_bytes,
    inventory_content_hash,
)
from app.schemas.schemas import (
    AgentCredentialRenewResponse,
    InventoryAck,
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
@router.post("/agents/enroll", response_model=EnrollResponse)
async def enroll(
    body: EnrollRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Claim an agent identity using a site enrollment token.

    The plaintext agent token is returned exactly once here; the agent must
    persist it. Server keeps only the hash.
    """
    source_ip = client_ip(request)
    retry_after = enrollment_limiter.retry_after(source_ip)
    if retry_after is not None:
        metrics.increment("enrollment_failure_total")
        await audit.record(
            db,
            action="agent.enrollment_failed",
            actor="installer",
            source_ip=source_ip,
            user_agent=request.headers.get("user-agent", "")[:500] or None,
            detail={
                "reason": "rate_limited",
                "hostname": body.hostname,
                "agent_name": body.agent_name or "",
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "enrollment_rate_limited"},
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
    enrollment_limiter.record_failure(source_ip)

    selected_version = select_command_envelope_version(
        body.supported_command_envelope_versions
    )
    if selected_version is None:
        metrics.increment("enrollment_failure_total")
        await audit.record(
            db,
            action="agent.enrollment_failed",
            actor="installer",
            source_ip=source_ip,
            user_agent=request.headers.get("user-agent", "")[:500] or None,
            detail={
                "reason": "no_common_command_envelope_version",
                "hostname": body.hostname,
                "agent_name": body.agent_name or "",
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "no_common_command_envelope_version",
                "server_supported": list(SUPPORTED_COMMAND_ENVELOPE_VERSIONS),
            },
        )

    try:
        enrollment = await redeem_enrollment_token(
            db,
            body=body,
            source_ip=source_ip,
        )
    except EnrollmentRejected as exc:
        metrics.increment("enrollment_failure_total")
        await audit.record(
            db,
            action="agent.enrollment_failed",
            actor="installer",
            source_ip=source_ip,
            user_agent=request.headers.get("user-agent", "")[:500] or None,
            detail={
                "reason": exc.reason,
                "hostname": body.hostname,
                "agent_name": body.agent_name or "",
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "enrollment_rejected", "message": "Enrollment failed"},
        )

    await audit.record(
        db,
        action="agent.enrolled",
        actor=f"installer:{enrollment.enrollment_token.id}",
        agent_id=enrollment.agent.id,
        enrollment_token_id=enrollment.enrollment_token.id,
        organization_id=enrollment.organization_id,
        source_ip=source_ip,
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "hostname": body.hostname,
            "agent_name": enrollment.agent.name,
            "os": enrollment.agent.os,
            "architecture": enrollment.agent.architecture,
            "site_id": enrollment.enrollment_token.site_id,
            "environment": enrollment.agent.environment,
            "command_envelope_version": selected_version,
            "supported_command_envelope_versions": body.supported_command_envelope_versions,
            "public_key_supplied": body.public_key is not None,
        },
    )
    enrollment_limiter.clear(source_ip)
    metrics.increment("enrollment_success_total")

    return EnrollResponse(
        agent_id=enrollment.agent.id,
        agent_token=enrollment.agent_token,
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
        command_public_key=public_key_pem(),
        command_public_keys=public_key_bundle_pem(),
        command_signing_key_id=active_signing_key().key_id,
        command_envelope_version=selected_version,
        credential_expires_at=enrollment.agent.credential_expires_at,
        api_base_url=settings.public_base_url,
        configuration_metadata={
            "organization_id": enrollment.organization_id,
            "site": enrollment.site_name,
            "environment": enrollment.agent.environment,
            "labels": enrollment.agent.labels,
        },
    )


@router.post(
    "/agents/credentials/renew",
    response_model=AgentCredentialRenewResponse,
)
async def renew_agent_credential(
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Rotate the current per-agent bearer credential atomically."""
    plaintext = generate_token()
    agent.token_hash = hash_token(plaintext)
    agent.credential_fingerprint = credential_fingerprint(plaintext)
    agent.credential_issued_at = _now()
    site = await db.get(Site, agent.site_id)
    await audit.record(
        db,
        action="agent.credential_renewed",
        actor=f"agent:{agent.id}",
        agent_id=agent.id,
        organization_id=site.client_id if site else None,
        detail={"credential_fingerprint": agent.credential_fingerprint},
    )
    metrics.increment("agent_credential_renewed_total")
    return AgentCredentialRenewResponse(
        agent_id=agent.id,
        agent_token=plaintext,
        credential_expires_at=agent.credential_expires_at,
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
    # Inventory refresh negotiation. Only hashes travel on the beat; the server
    # decides what is worth resending and the agent POSTs those sections to the
    # bounded inventory endpoint. A steady-state endpoint transfers nothing.
    inventory_requested: list[str] = []
    if body.inventory_hashes:
        inventory_requested = inventory.sections_to_request(
            await inventory.latest_sections(db, agent.id),
            body.inventory_hashes,
            now,
        )

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
        inventory_requested=inventory_requested,
    )


@router.post("/agents/me/inventory", response_model=InventoryAck)
async def submit_inventory(
    body: InventorySubmission,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Accept the inventory sections the heartbeat ack asked for.

    The submission is atomic: every section is validated before any section is
    stored, so a malformed one cannot leave a half-applied snapshot behind.
    Bounds are enforced by rejection rather than truncation, which keeps what is
    persisted exactly what the endpoint reported — the agent is responsible for
    trimming its own lists and saying so with ``partial``.

    Sections are stored independently and deduped on content hash, so an agent
    that resends an unchanged section costs one comparison and no storage.
    """
    # Same fail-closed posture as command results: a quarantined or revoked
    # endpoint has suspended trust, so its self-reported state is not recorded.
    if agent.trust_state != AgentTrustState.active:
        await audit.record(
            db,
            action="inventory.rejected",
            actor=f"agent:{agent.id}",
            agent_id=agent.id,
            detail={"reason": "agent_not_active", "section": None, "byte_size": None},
        )
        # Commit explicitly: the refusal is the only mutation, and the raise
        # below would otherwise roll the evidence back with the request.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "agent_quarantined"},
        )

    # Pass one: validate everything. Nothing is written yet, so the rejection
    # audit can be committed without dragging half a snapshot along with it.
    validated: list[tuple[str, str, dict, str, int, datetime]] = []
    for entry in body.sections:
        byte_size = len(canonical_inventory_bytes(entry.payload))
        try:
            entry.typed_payload()
        except ValueError:
            await audit.record(
                db,
                action="inventory.rejected",
                actor=f"agent:{agent.id}",
                agent_id=agent.id,
                detail={
                    "reason": "section_schema_invalid",
                    "section": entry.section.value,
                    "byte_size": byte_size,
                },
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "inventory_section_invalid",
                    "section": entry.section.value,
                },
            )
        validated.append(
            (
                entry.section.value,
                entry.status.value,
                entry.payload,
                inventory_content_hash(entry.payload),
                byte_size,
                ensure_utc(entry.collected_at),
            )
        )

    # Pass two: store. Every section is known good by this point.
    stored_sections: list[str] = []
    unchanged_sections: list[str] = []
    total_bytes = 0
    for section, section_status, payload, content_hash, byte_size, collected_at in validated:
        total_bytes += byte_size
        snapshot = await inventory.store_section(
            db,
            agent_id=agent.id,
            section=section,
            status=section_status,
            schema_version=body.inventory_schema_version,
            payload=payload,
            content_hash=content_hash,
            byte_size=byte_size,
            collected_at=collected_at,
        )
        if snapshot is None:
            unchanged_sections.append(section)
        else:
            stored_sections.append(section)

    site = await db.get(Site, agent.site_id)
    await audit.record(
        db,
        action="inventory.received",
        actor=f"agent:{agent.id}",
        agent_id=agent.id,
        organization_id=site.client_id if site else None,
        detail={
            # Section names and sizes only. Inventory payloads carry serials,
            # hostnames, and user-adjacent strings, none of which belong in the
            # permanent chain.
            "stored_sections": sorted(stored_sections),
            "unchanged_sections": sorted(unchanged_sections),
            "schema_version": body.inventory_schema_version,
            "total_bytes": total_bytes,
        },
    )
    metrics.increment("inventory_sections_stored_total", len(stored_sections))
    return InventoryAck(
        stored_sections=sorted(stored_sections),
        unchanged_sections=sorted(unchanged_sections),
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
