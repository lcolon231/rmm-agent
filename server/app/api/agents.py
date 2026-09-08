# SPDX-License-Identifier: AGPL-3.0-only
"""Agent-facing endpoints: enrollment, heartbeat, command pickup/result.

These routes are called by the Go agent. Human/dashboard routes live in
management.py.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_agent_for_credential_reattach, get_current_agent
from app.core import audit, inventory, metrics, monitoring
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
    CheckResult,
    CheckResultStatus,
    CheckType,
    Command,
    CommandStatus,
    Site,
)
from app.schemas.inventory import (
    InventorySubmission,
    canonical_inventory_bytes,
    inventory_content_hash,
)
from app.schemas.monitoring import (
    AgentCheckAssignment,
    AgentCheckResultAck,
    AgentCheckResultBatchIn,
)
from app.schemas.schemas import (
    AgentCredentialRenewRequest,
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


def _rotate_agent_credential(
    agent: Agent, *, now: datetime, rotation_nonce: str
) -> tuple[str, datetime]:
    """Issue and install the next bearer while preserving response-loss safety."""
    overlap_until = now + timedelta(seconds=settings.agent_credential_overlap_seconds)
    # A request authenticated by the overlap bearer is retrying after a lost
    # response or failed local persist. Keep that bearer in the overlap slot;
    # otherwise demote the current bearer into it.
    if getattr(agent, "credential_matched", "current") != "overlap":
        agent.previous_token_hash = agent.token_hash
    agent.previous_token_expires_at = overlap_until

    plaintext = generate_token()
    agent.token_hash = hash_token(plaintext)
    agent.credential_fingerprint = credential_fingerprint(plaintext)
    agent.credential_issued_at = now
    agent.credential_expires_at = now + timedelta(
        seconds=settings.agent_credential_lifetime_seconds
    )
    agent.credential_generation += 1
    agent.last_rotation_nonce = rotation_nonce
    agent.last_renewed_at = now
    return plaintext, overlap_until


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
    body: AgentCredentialRenewRequest,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Rotate the per-agent bearer credential with a loss-safe overlap (#125).

    Proof of possession is the presented credential itself (``get_current_agent``
    already fails closed on an unknown, expired, overlapped-out, or revoked
    identity). Rotation is atomic: the just-superseded token moves into the
    bounded overlap slot and stays valid until ``previous_token_expires_at``, so
    a dropped response never strands the agent — it keeps working on the old
    credential and retries with a fresh nonce. A verbatim replay (same nonce) is
    rejected. When the agent authenticated on its overlap credential (i.e. this
    *is* such a retry) the overlap slot is preserved rather than overwritten, so
    even repeated lost responses cannot orphan the credential it still holds.
    """
    now = _now()
    site = await db.get(Site, agent.site_id)
    organization_id = site.client_id if site else None

    # Replay: a verbatim retry of an already-processed rotation reuses the nonce.
    if agent.last_rotation_nonce is not None and secrets.compare_digest(
        agent.last_rotation_nonce, body.rotation_nonce
    ):
        await audit.record(
            db,
            action="agent.credential_renewal_rejected",
            actor=f"agent:{agent.id}",
            agent_id=agent.id,
            organization_id=organization_id,
            detail={"reason": "rotation_nonce_reused"},
        )
        metrics.increment("agent_credential_renewal_rejected_total")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "rotation_nonce_reused"},
        )

    plaintext, overlap_until = _rotate_agent_credential(
        agent, now=now, rotation_nonce=body.rotation_nonce
    )

    await audit.record(
        db,
        action="agent.credential_renewed",
        actor=f"agent:{agent.id}",
        agent_id=agent.id,
        organization_id=organization_id,
        detail={
            "credential_fingerprint": agent.credential_fingerprint,
            "credential_generation": agent.credential_generation,
        },
    )
    metrics.increment("agent_credential_renewed_total")
    return AgentCredentialRenewResponse(
        agent_id=agent.id,
        agent_token=plaintext,
        credential_expires_at=agent.credential_expires_at,
        overlap_expires_at=overlap_until,
        credential_generation=agent.credential_generation,
    )


@router.post(
    "/agents/credentials/reattach",
    response_model=AgentCredentialRenewResponse,
)
async def reattach_agent_credential(
    body: AgentCredentialRenewRequest,
    agent: Agent = Depends(get_agent_for_credential_reattach),
    db: AsyncSession = Depends(get_db),
):
    """Replace a recently expired current bearer for an active agent (#223).

    The dedicated dependency is the trust boundary: ordinary agent APIs still
    reject every expired bearer. Reattachment is bounded from the credential's
    expiry, is never available to quarantined or revoked agents, and returns the
    same opaque 401 for every refused credential state. Rotation then uses the
    ordinary overlap mechanism so persist-before-adopt remains loss-safe.
    """
    if agent.last_rotation_nonce is not None and secrets.compare_digest(
        agent.last_rotation_nonce, body.rotation_nonce
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token"
        )

    now = _now()
    site = await db.get(Site, agent.site_id)
    organization_id = site.client_id if site else None
    plaintext, overlap_until = _rotate_agent_credential(
        agent, now=now, rotation_nonce=body.rotation_nonce
    )

    await audit.record(
        db,
        action="agent.credential_reattached",
        actor=f"agent:{agent.id}",
        agent_id=agent.id,
        organization_id=organization_id,
        detail={
            "credential_fingerprint": agent.credential_fingerprint,
            "credential_generation": agent.credential_generation,
        },
    )
    metrics.increment("agent_credential_reattached_total")
    return AgentCredentialRenewResponse(
        agent_id=agent.id,
        agent_token=plaintext,
        credential_expires_at=agent.credential_expires_at,
        overlap_expires_at=overlap_until,
        credential_generation=agent.credential_generation,
    )


def inventory_field_errors(exc: ValueError, limit: int = 10) -> list[dict]:
    """Field paths and rules from a section validation failure — never values.

    A rejected inventory payload can contain endpoint data, so only the location
    and the rule that failed are echoed back. Bounded so a pathological payload
    cannot turn one refusal into a large response.
    """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return []
    out: list[dict] = []
    for item in errors()[:limit]:
        out.append(
            {
                "field": ".".join(str(part) for part in item.get("loc", ())),
                "rule": item.get("type", "invalid"),
            }
        )
    return out


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
    # Refresh the running agent build (issue #179). An in-place upgrade keeps
    # the same identity and credentials, so without this the dashboard would go
    # on showing the enrollment-time version forever. Only a genuine change is
    # written and audited, so a steady-state fleet produces no extra events. A
    # lower version is recorded exactly like a higher one: a rollback is a real
    # fleet state an operator needs to see, not an anomaly to suppress.
    previous_agent_version = agent.agent_version or ""
    if body.agent_version is not None and body.agent_version != previous_agent_version:
        agent.agent_version = body.agent_version
        await audit.record(
            db,
            action="agent.version_changed",
            actor=f"agent:{agent.id}",
            agent_id=agent.id,
            detail={
                "previous": previous_agent_version,
                "current": body.agent_version,
            },
        )
    previous_versions = list(agent.command_envelope_versions or [])
    agent.command_envelope_versions = body.supported_command_envelope_versions
    # Advertised feature capabilities (issue #61) drive capability-gated features
    # such as interactive shell sessions; refresh them on every beat.
    agent.supported_capabilities = body.supported_capabilities
    # Release channel the endpoint follows (issue #63). Absent leaves the stored
    # value untouched so an older agent is not silently moved between channels;
    # a NULL value is treated as "stable" wherever targeting is decided.
    if body.update_channel is not None:
        agent.update_channel = body.update_channel
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
        monitoring_checks=[
            AgentCheckAssignment(
                definition=item.definition,
                policy_id=item.source_policy_id,
                policy_revision_id=item.source_revision_id,
            )
            for item in await monitoring.resolve_effective_policy(db, agent)
            if item.definition.type != CheckType.offline
        ],
    )


@router.post(
    "/agents/me/monitoring/results",
    response_model=AgentCheckResultAck,
)
async def submit_monitoring_results(
    body: AgentCheckResultBatchIn,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Accept a bounded, revision-pinned batch of durable evaluations."""
    if agent.trust_state != AgentTrustState.active:
        metrics.increment("monitoring_result_rejected_total")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "agent_not_active"},
        )

    effective = {
        item.definition.key: item
        for item in await monitoring.resolve_effective_policy(db, agent)
    }
    now = _now()
    accepted = 0
    duplicates = 0

    for result in body.results:
        assignment = effective.get(result.check_key)
        if (
            assignment is None
            or assignment.source_policy_id != result.policy_id
            or assignment.source_revision_id != result.policy_revision_id
        ):
            metrics.increment("monitoring_result_rejected_total")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "monitoring_policy_superseded"},
            )
        definition = assignment.definition
        if definition.type == CheckType.offline:
            metrics.increment("monitoring_result_rejected_total")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "offline_check_is_server_owned"},
            )

        evaluated_at = ensure_utc(result.evaluated_at)
        max_age_seconds = max(definition.schedule.interval_seconds * 3, 300)
        if evaluated_at > now + timedelta(minutes=5):
            metrics.increment("monitoring_result_rejected_total")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "monitoring_result_from_future"},
            )
        if evaluated_at < now - timedelta(seconds=max_age_seconds):
            metrics.increment("monitoring_result_rejected_total")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "monitoring_result_stale"},
            )

        numeric_types = {
            CheckType.cpu,
            CheckType.memory,
            CheckType.disk,
            CheckType.uptime,
        }
        if (
            definition.type in numeric_types
            and result.status != CheckResultStatus.unknown
            and result.value is None
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "monitoring_result_value_required"},
            )
        if (
            definition.type in {CheckType.cpu, CheckType.memory, CheckType.disk}
            and result.value is not None
            and not 0 <= result.value <= 100
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "monitoring_result_value_out_of_range"},
            )

        existing = await db.get(CheckResult, result.id)
        if existing is not None:
            if (
                existing.agent_id != agent.id
                or existing.check_key != result.check_key
                or existing.policy_id != result.policy_id
                or existing.policy_revision_id != result.policy_revision_id
                or existing.status != result.status
                or existing.value != result.value
                or existing.detail != result.detail
                or ensure_utc(existing.evaluated_at) != evaluated_at
            ):
                metrics.increment("monitoring_result_rejected_total")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"code": "monitoring_result_id_conflict"},
                )
            duplicates += 1
            continue

        try:
            # The savepoint keeps a simultaneous retry's primary-key conflict
            # from invalidating the whole request transaction. After the
            # winning transaction commits, the loser validates the stored
            # payload and acknowledges it as the same idempotent result.
            async with db.begin_nested():
                await monitoring.record_check_result(
                    db,
                    result_id=result.id,
                    agent_id=agent.id,
                    policy_id=result.policy_id,
                    policy_revision_id=result.policy_revision_id,
                    check_key=result.check_key,
                    status=result.status,
                    value=result.value,
                    detail=result.detail,
                    evaluated_at=evaluated_at,
                )
        except IntegrityError:
            concurrent = await db.get(CheckResult, result.id)
            if concurrent is None:
                raise
            if (
                concurrent.agent_id != agent.id
                or concurrent.check_key != result.check_key
                or concurrent.policy_id != result.policy_id
                or concurrent.policy_revision_id != result.policy_revision_id
                or concurrent.status != result.status
                or concurrent.value != result.value
                or concurrent.detail != result.detail
                or ensure_utc(concurrent.evaluated_at) != evaluated_at
            ):
                metrics.increment("monitoring_result_rejected_total")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"code": "monitoring_result_id_conflict"},
                )
            duplicates += 1
        else:
            accepted += 1

    metrics.increment("monitoring_result_accepted_total", accepted)
    metrics.increment("monitoring_result_duplicate_total", duplicates)
    return AgentCheckResultAck(accepted=accepted, duplicates=duplicates)


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
            detail={
                "reason": "agent_not_active",
                "section": None,
                "byte_size": None,
                "fields": [],
            },
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
        except ValueError as exc:
            # Name the offending field, never its value. A bare "section is
            # invalid" forced an operator to read the schema source to work out
            # which of ~20 fields a rejected scan tripped on; the field path plus
            # the rule that failed is non-sensitive and turns that into a glance.
            field_errors = inventory_field_errors(exc)
            await audit.record(
                db,
                action="inventory.rejected",
                actor=f"agent:{agent.id}",
                agent_id=agent.id,
                detail={
                    "reason": "section_schema_invalid",
                    "section": entry.section.value,
                    "byte_size": byte_size,
                    "fields": [item["field"] for item in field_errors],
                },
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "inventory_section_invalid",
                    "section": entry.section.value,
                    "fields": field_errors,
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
