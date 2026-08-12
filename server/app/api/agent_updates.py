# SPDX-License-Identifier: AGPL-3.0-only
"""Signed, staged agent self-update: publish, stage, halt, and roll back (#63).

Two routers live here:

* an administrator-only management router that publishes signed releases,
  advances a staged rollout, pauses/halts it, and exposes per-endpoint evidence;
* an agent-authenticated router carrying the one post-restart report that says
  whether a new build came up healthy.

Every decision fails closed. A release that cannot be signed is not stored, an
endpoint that cannot be positively confirmed eligible is not targeted, an update
dispatched outside a published release is refused, and a release whose resolved
failure rate crosses its threshold halts itself and dispatches nothing further.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_agent, require_role
from app.core import agent_updates as updates
from app.core import audit
from app.core.clientip import client_ip
from app.core.command_envelope import (
    COMMAND_ENVELOPE_V3,
    COMMAND_SCHEMA_VERSION,
    format_command_time,
    select_command_envelope_version,
)
from app.core.database import get_db
from app.core.security import active_signing_key, generate_token, sign_command
from app.models.models import (
    Agent,
    AgentTrustState,
    AgentUpdateAttempt,
    AgentUpdateAttemptStatus,
    AgentUpdateChannel,
    AgentUpdateRelease,
    AgentUpdateReleaseState,
    Command,
    CommandKind,
    CommandStatus,
    Operator,
    OperatorRole,
)
from app.schemas.agent_updates import (
    AgentUpdateAttemptListOut,
    AgentUpdateAttemptOut,
    AgentUpdateDispatchOut,
    AgentUpdateHalt,
    AgentUpdateReleaseCreate,
    AgentUpdateReleaseDetailOut,
    AgentUpdateReleaseListOut,
    AgentUpdateReleaseOut,
    AgentUpdateReleaseStatsOut,
    AgentUpdateRolloutAdvance,
    SelfUpdateReportAck,
    SelfUpdateReportIn,
)

# Publishing a release, staging it, halting it, and rolling an endpoint back all
# replace the code running on every managed endpoint. That is the broadest trust
# boundary in the product, so the whole router is administrator-only; the
# per-request role check is what enforces it, not the route path.
router = APIRouter(
    prefix="/agent-updates",
    tags=["agent-updates"],
    dependencies=[Depends(require_role(OperatorRole.admin))],
)
agent_router = APIRouter(tags=["agent-self-update"])

# States in which no further endpoint may be targeted.
_CLOSED_STATES = (
    AgentUpdateReleaseState.paused,
    AgentUpdateReleaseState.halted,
)
# Command lifetime for a staged update. It is deliberately short relative to the
# 24h envelope maximum: an update command that sat unclaimed for a day is more
# likely to be stale than useful, and the next rollout advance re-dispatches.
_UPDATE_COMMAND_TTL = timedelta(hours=6)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _status_counts(db: AsyncSession, release_id: str) -> dict[str, int]:
    rows = await db.execute(
        select(AgentUpdateAttempt.status, func.count())
        .where(AgentUpdateAttempt.release_id == release_id)
        .group_by(AgentUpdateAttempt.status)
    )
    counts: dict[str, int] = {}
    for value, count in rows.all():
        counts[value.value if hasattr(value, "value") else str(value)] = count
    return counts


def _stats(counts: dict[str, int]) -> AgentUpdateReleaseStatsOut:
    succeeded = counts.get("succeeded", 0)
    failed = counts.get("rolled_back", 0) + counts.get("failed", 0)
    resolved = succeeded + failed
    return AgentUpdateReleaseStatsOut(
        dispatched=counts.get("dispatched", 0),
        staged=counts.get("staged", 0),
        succeeded=succeeded,
        rolled_back=counts.get("rolled_back", 0),
        failed=counts.get("failed", 0),
        resolved=resolved,
        failure_percent=(failed * 100 // resolved) if resolved else 0,
    )


def _release_out(release: AgentUpdateRelease, stats: AgentUpdateReleaseStatsOut) -> dict:
    return {
        "id": release.id,
        "version": release.version,
        "channel": release.channel.value,
        "platform": release.platform,
        "artifact_sha256": release.artifact_sha256,
        "artifact_size_bytes": release.artifact_size_bytes,
        "signer_thumbprint": release.signer_thumbprint,
        "min_supported_version": release.min_supported_version,
        "state": release.state.value,
        "rollout_percent": release.rollout_percent,
        "failure_threshold_percent": release.failure_threshold_percent,
        "min_attempts_before_halt": release.min_attempts_before_halt,
        "health_timeout_seconds": release.health_timeout_seconds,
        "signing_key_id": release.signing_key_id,
        "manifest_sha256": release.manifest_sha256,
        "created_by_email": release.created_by_email,
        "created_at": release.created_at,
        "updated_at": release.updated_at,
        "halted_at": release.halted_at,
        "halted_reason": release.halted_reason,
        "stats": stats,
    }


async def _load_release(db: AsyncSession, release_id: str) -> AgentUpdateRelease:
    release = await db.get(AgentUpdateRelease, release_id)
    if release is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "agent_update_release_not_found"},
        )
    return release


# --------------------------------------------------------------------------- #
# Publication
# --------------------------------------------------------------------------- #
@router.post(
    "/releases",
    response_model=AgentUpdateReleaseDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def publish_release(
    body: AgentUpdateReleaseCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Publish signed release metadata. Publishing targets no endpoint.

    A release starts at 0% with no rollout: reaching endpoints is a separate,
    separately audited decision, so publishing can never be an accidental
    fleet-wide deployment.
    """
    # The anti-rollback floor must not exceed the release itself, or the release
    # would refuse itself at every endpoint.
    if updates.compare_versions(body.version, body.min_supported_version) < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "min_supported_version_above_release"},
        )

    existing = await db.scalar(
        select(AgentUpdateRelease).where(
            AgentUpdateRelease.version == body.version,
            AgentUpdateRelease.channel == AgentUpdateChannel(body.channel),
            AgentUpdateRelease.platform == body.platform,
        )
    )
    if existing is not None:
        # A published release is immutable: the signature is over its metadata,
        # so "republishing" would silently change what an endpoint verified.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_release_exists", "release_id": existing.id},
        )

    now = _now()
    release_id = str(uuid.uuid4())
    manifest = updates.build_manifest(
        release_id=release_id,
        version=body.version,
        channel=body.channel,
        platform=body.platform,
        artifact_url=body.artifact_url,
        artifact_sha256=body.artifact_sha256,
        artifact_size_bytes=body.artifact_size_bytes,
        min_supported_version=body.min_supported_version,
        signer_thumbprint=body.signer_thumbprint,
        health_timeout_seconds=body.health_timeout_seconds,
        published_at=now,
    )
    try:
        signed = updates.sign_manifest(manifest)
    except (FileNotFoundError, ValueError) as exc:
        # No signing key means no publication. Storing unsigned metadata and
        # signing later would create a window in which a release exists without
        # a verifiable publication record.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "agent_update_signing_unavailable"},
        ) from exc

    release = AgentUpdateRelease(
        id=release_id,
        version=body.version,
        channel=AgentUpdateChannel(body.channel),
        platform=body.platform,
        artifact_url=body.artifact_url,
        artifact_sha256=body.artifact_sha256,
        artifact_size_bytes=body.artifact_size_bytes,
        signer_thumbprint=body.signer_thumbprint,
        min_supported_version=body.min_supported_version,
        manifest=signed.manifest,
        manifest_sha256=signed.manifest_sha256,
        signature=signed.signature,
        signing_key_id=signed.signing_key_id,
        state=AgentUpdateReleaseState.published,
        rollout_percent=0,
        failure_threshold_percent=body.failure_threshold_percent,
        min_attempts_before_halt=body.min_attempts_before_halt,
        health_timeout_seconds=body.health_timeout_seconds,
        created_by_email=operator.email,
        created_at=now,
        updated_at=now,
    )
    db.add(release)
    await db.flush()

    await audit.record(
        db,
        action="agent_update.release_published",
        actor=operator.email,
        source_ip=client_ip(request),
        detail={
            "release_id": release.id,
            "version": release.version,
            "channel": release.channel.value,
            "platform": release.platform,
            "artifact_sha256": release.artifact_sha256,
            "artifact_size_bytes": release.artifact_size_bytes,
            # The source URL is prose; only its digest rides the audit trail.
            "artifact_url_sha256": hashlib.sha256(
                release.artifact_url.encode("utf-8")
            ).hexdigest(),
            "min_supported_version": release.min_supported_version,
            "signer_pinned": bool(release.signer_thumbprint),
            "manifest_sha256": release.manifest_sha256,
            "signing_key_id": release.signing_key_id,
            "failure_threshold_percent": release.failure_threshold_percent,
            "min_attempts_before_halt": release.min_attempts_before_halt,
        },
    )
    await db.commit()
    await db.refresh(release)
    return _detail_out(release, _stats({}))


def _detail_out(release: AgentUpdateRelease, stats: AgentUpdateReleaseStatsOut) -> dict:
    payload = _release_out(release, stats)
    payload.update(
        {
            "artifact_url": release.artifact_url,
            "manifest": release.manifest,
            "signature": release.signature,
            "signature_valid": updates.verify_manifest(
                release.manifest, release.signature, release.signing_key_id
            ),
        }
    )
    return payload


@router.get("/releases", response_model=AgentUpdateReleaseListOut)
async def list_releases(
    channel: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(AgentUpdateRelease).order_by(AgentUpdateRelease.created_at.desc())
    if channel is not None:
        if channel not in updates.CHANNELS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "agent_update_channel_invalid"},
            )
        query = query.where(AgentUpdateRelease.channel == AgentUpdateChannel(channel))
    releases = (await db.execute(query.limit(limit))).scalars().all()
    out = []
    for release in releases:
        out.append(
            AgentUpdateReleaseOut(
                **_release_out(release, _stats(await _status_counts(db, release.id)))
            )
        )
    return AgentUpdateReleaseListOut(releases=out)


@router.get("/releases/{release_id}", response_model=AgentUpdateReleaseDetailOut)
async def get_release(release_id: str, db: AsyncSession = Depends(get_db)):
    release = await _load_release(db, release_id)
    return _detail_out(release, _stats(await _status_counts(db, release.id)))


@router.get("/releases/{release_id}/attempts", response_model=AgentUpdateAttemptListOut)
async def list_attempts(
    release_id: str,
    limit: int = Query(default=200, ge=1, le=1_000),
    db: AsyncSession = Depends(get_db),
):
    await _load_release(db, release_id)
    rows = (
        await db.execute(
            select(AgentUpdateAttempt)
            .where(AgentUpdateAttempt.release_id == release_id)
            .order_by(AgentUpdateAttempt.dispatched_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return AgentUpdateAttemptListOut(
        attempts=[
            AgentUpdateAttemptOut(
                id=row.id,
                agent_id=row.agent_id,
                command_id=row.command_id,
                status=row.status.value,
                from_version=row.from_version,
                to_version=row.to_version,
                observed_version=row.observed_version,
                reason=row.reason,
                health_attempts=row.health_attempts,
                rollout_bucket=row.rollout_bucket,
                dispatched_at=row.dispatched_at,
                reported_at=row.reported_at,
            )
            for row in rows
        ]
    )


# --------------------------------------------------------------------------- #
# Staged rollout
# --------------------------------------------------------------------------- #
@router.post("/releases/{release_id}/rollout", response_model=AgentUpdateDispatchOut)
async def advance_rollout(
    release_id: str,
    body: AgentUpdateRolloutAdvance,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Raise the staged rollout and dispatch to the endpoints it newly admits."""
    release = await _load_release(db, release_id)
    if release.state in _CLOSED_STATES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "agent_update_release_not_active",
                "state": release.state.value,
            },
        )
    if release.state == AgentUpdateReleaseState.completed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_release_completed"},
        )
    if body.rollout_percent < release.rollout_percent:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_rollout_cannot_shrink"},
        )

    # Re-evaluate the halt rule before widening. Evidence may have arrived since
    # the last advance, and widening a failing release is exactly what the canary
    # halt exists to prevent.
    counts = await _status_counts(db, release.id)
    decision = updates.evaluate_halt(
        status_counts=counts,
        failure_threshold_percent=release.failure_threshold_percent,
        min_attempts_before_halt=release.min_attempts_before_halt,
    )
    if decision.halt:
        await _halt_release(db, release, decision.reason, actor="system")
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "agent_update_release_halted",
                "reason": decision.reason,
                "resolved": decision.resolved,
                "failed": decision.failed,
            },
        )

    now = _now()
    release.rollout_percent = body.rollout_percent
    release.state = AgentUpdateReleaseState.rolling
    release.updated_at = now

    already = set(
        (
            await db.execute(
                select(AgentUpdateAttempt.agent_id).where(
                    AgentUpdateAttempt.release_id == release.id
                )
            )
        )
        .scalars()
        .all()
    )
    candidates = (
        (await db.execute(select(Agent).where(Agent.revoked_at.is_(None))))
        .scalars()
        .all()
    )

    skipped: dict[str, int] = {}
    dispatched = 0
    truncated = False
    for agent in candidates:
        if agent.id in already:
            skipped["already_attempted"] = skipped.get("already_attempted", 0) + 1
            continue
        eligibility = updates.evaluate_eligibility(
            agent,
            release_version=release.version,
            release_channel=release.channel.value,
            release_platform=release.platform,
            min_supported_version=release.min_supported_version,
            rollout_percent=release.rollout_percent,
            release_id=release.id,
            trust_active=agent.trust_state == AgentTrustState.active,
        )
        if not eligibility.eligible:
            skipped[eligibility.reason] = skipped.get(eligibility.reason, 0) + 1
            continue
        envelope_version = select_command_envelope_version(
            agent.command_envelope_versions or []
        )
        if envelope_version != COMMAND_ENVELOPE_V3:
            # Self-update metadata must ride a key-identified signature, so an
            # agent that cannot negotiate v3 is not targeted.
            skipped["envelope_unsupported"] = skipped.get("envelope_unsupported", 0) + 1
            continue
        if dispatched >= body.max_dispatch:
            truncated = True
            break

        command = await _dispatch_update_command(db, release, agent, now)
        db.add(
            AgentUpdateAttempt(
                id=str(uuid.uuid4()),
                release_id=release.id,
                agent_id=agent.id,
                command_id=command.id,
                status=AgentUpdateAttemptStatus.dispatched,
                from_version=agent.agent_version,
                to_version=release.version,
                rollout_bucket=updates.rollout_bucket(release.id, agent.id),
                dispatched_at=now,
            )
        )
        dispatched += 1

    await audit.record(
        db,
        action="agent_update.rollout_advanced",
        actor=operator.email,
        source_ip=client_ip(request),
        detail={
            "release_id": release.id,
            "version": release.version,
            "channel": release.channel.value,
            "rollout_percent": release.rollout_percent,
            "dispatched": dispatched,
            "truncated": truncated,
        },
    )
    await db.commit()
    return AgentUpdateDispatchOut(
        release_id=release.id,
        state=release.state.value,
        rollout_percent=release.rollout_percent,
        dispatched=dispatched,
        skipped=skipped,
        truncated=truncated,
    )


async def _dispatch_update_command(
    db: AsyncSession,
    release: AgentUpdateRelease,
    agent: Agent,
    now: datetime,
) -> Command:
    """Queue one signed agent_self_update command derived from the manifest."""
    payload = updates.command_payload(release.manifest)
    command = Command(
        id=str(uuid.uuid4()),
        agent_id=agent.id,
        kind=CommandKind.agent_self_update,
        payload=payload,
        envelope_version=COMMAND_ENVELOPE_V3,
        schema_version=COMMAND_SCHEMA_VERSION,
        issued_at=now,
        nonce=generate_token(24),
        signing_key_id=active_signing_key().key_id,
        status=CommandStatus.queued,
        created_at=now,
        expires_at=now + _UPDATE_COMMAND_TTL,
        actor_email=release.created_by_email,
    )
    db.add(command)
    await db.flush()
    command.signature = sign_command(
        envelope_version=command.envelope_version,
        schema_version=command.schema_version,
        command_id=command.id,
        agent_id=agent.id,
        kind=CommandKind.agent_self_update.value,
        payload=payload,
        issued_at=format_command_time(command.issued_at),
        expires_at=format_command_time(command.expires_at),
        nonce=command.nonce,
        signing_key_id=command.signing_key_id,
    )
    await audit.record(
        db,
        action="agent_update.dispatched",
        actor="system",
        agent_id=agent.id,
        detail={
            "release_id": release.id,
            "command_id": command.id,
            "version": release.version,
            "channel": release.channel.value,
            "from_version": agent.agent_version or "",
            "artifact_sha256": release.artifact_sha256,
            "rollout_bucket": updates.rollout_bucket(release.id, agent.id),
        },
    )
    return command


# --------------------------------------------------------------------------- #
# Pause, resume, halt
# --------------------------------------------------------------------------- #
async def _halt_release(
    db: AsyncSession,
    release: AgentUpdateRelease,
    reason: str,
    *,
    actor: str,
) -> None:
    release.state = AgentUpdateReleaseState.halted
    release.halted_at = _now()
    release.halted_reason = reason
    release.updated_at = release.halted_at
    await audit.record(
        db,
        action="agent_update.rollout_halted",
        actor=actor,
        detail={
            "release_id": release.id,
            "version": release.version,
            "channel": release.channel.value,
            "reason": reason,
            "rollout_percent": release.rollout_percent,
        },
    )


@router.post("/releases/{release_id}/halt", response_model=AgentUpdateReleaseOut)
async def halt_release(
    release_id: str,
    body: AgentUpdateHalt,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Stop a release permanently. Halting is terminal and cannot be resumed."""
    release = await _load_release(db, release_id)
    if release.state == AgentUpdateReleaseState.halted:
        return AgentUpdateReleaseOut(
            **_release_out(release, _stats(await _status_counts(db, release.id)))
        )
    await _halt_release(db, release, "operator_halted", actor=operator.email)
    await audit.record(
        db,
        action="agent_update.halt_reason_recorded",
        actor=operator.email,
        source_ip=client_ip(request),
        detail={"release_id": release.id, "reason": body.reason},
    )
    await db.commit()
    await db.refresh(release)
    return AgentUpdateReleaseOut(
        **_release_out(release, _stats(await _status_counts(db, release.id)))
    )


@router.post("/releases/{release_id}/pause", response_model=AgentUpdateReleaseOut)
async def pause_release(
    release_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Stop targeting new endpoints. In-flight attempts still report their outcome."""
    release = await _load_release(db, release_id)
    if release.state == AgentUpdateReleaseState.halted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_release_halted"},
        )
    release.state = AgentUpdateReleaseState.paused
    release.updated_at = _now()
    await audit.record(
        db,
        action="agent_update.rollout_paused",
        actor=operator.email,
        source_ip=client_ip(request),
        detail={"release_id": release.id, "rollout_percent": release.rollout_percent},
    )
    await db.commit()
    await db.refresh(release)
    return AgentUpdateReleaseOut(
        **_release_out(release, _stats(await _status_counts(db, release.id)))
    )


@router.post("/releases/{release_id}/resume", response_model=AgentUpdateReleaseOut)
async def resume_release(
    release_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Resume a paused release, unless the halt rule already condemns it."""
    release = await _load_release(db, release_id)
    if release.state == AgentUpdateReleaseState.halted:
        # A halt is terminal on purpose: resuming a release that failed its
        # canary would re-dispatch the build that caused the failures.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_release_halted"},
        )
    if release.state != AgentUpdateReleaseState.paused:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "agent_update_release_not_paused"},
        )
    counts = await _status_counts(db, release.id)
    decision = updates.evaluate_halt(
        status_counts=counts,
        failure_threshold_percent=release.failure_threshold_percent,
        min_attempts_before_halt=release.min_attempts_before_halt,
    )
    if decision.halt:
        await _halt_release(db, release, decision.reason, actor="system")
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "agent_update_release_halted",
                "reason": decision.reason,
            },
        )
    release.state = (
        AgentUpdateReleaseState.rolling
        if release.rollout_percent > 0
        else AgentUpdateReleaseState.published
    )
    release.updated_at = _now()
    await audit.record(
        db,
        action="agent_update.rollout_resumed",
        actor=operator.email,
        source_ip=client_ip(request),
        detail={"release_id": release.id, "rollout_percent": release.rollout_percent},
    )
    await db.commit()
    await db.refresh(release)
    return AgentUpdateReleaseOut(
        **_release_out(release, _stats(await _status_counts(db, release.id)))
    )


# --------------------------------------------------------------------------- #
# Agent-facing outcome report
# --------------------------------------------------------------------------- #
@agent_router.post(
    "/agents/me/self-update/report",
    response_model=SelfUpdateReportAck,
)
async def report_self_update(
    body: SelfUpdateReportIn,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Record one endpoint's post-restart outcome and re-evaluate the halt rule.

    An endpoint may report an outcome for a release it was never targeted with
    (for example an operator-triggered rollback). That is recorded as audit
    evidence but never creates an attempt row, so the halt rule keeps counting
    only the endpoints the rollout actually chose.
    """
    now = _now()
    if body.observed_version:
        # The report is also the earliest reliable statement of what is now
        # running, so it refreshes the stored build alongside the heartbeat.
        agent.agent_version = body.observed_version

    attempt: AgentUpdateAttempt | None = None
    if body.release_id:
        attempt = await db.scalar(
            select(AgentUpdateAttempt).where(
                AgentUpdateAttempt.release_id == body.release_id,
                AgentUpdateAttempt.agent_id == agent.id,
            )
        )

    status_map = {
        "succeeded": AgentUpdateAttemptStatus.succeeded,
        "rolled_back": AgentUpdateAttemptStatus.rolled_back,
        "failed": AgentUpdateAttemptStatus.failed,
    }
    release_state: str | None = None
    if attempt is not None:
        attempt.status = status_map[body.status]
        attempt.from_version = body.from_version or attempt.from_version
        attempt.to_version = body.to_version or attempt.to_version
        attempt.observed_version = body.observed_version
        attempt.reason = body.reason
        attempt.health_attempts = body.attempts
        attempt.reported_at = now

    await audit.record(
        db,
        action="agent_update.outcome_reported",
        actor="agent",
        agent_id=agent.id,
        detail={
            "release_id": body.release_id or "",
            "command_id": body.command_id or "",
            "status": body.status,
            "reason": body.reason or "",
            "from_version": body.from_version or "",
            "to_version": body.to_version or "",
            "observed_version": body.observed_version or "",
            "health_attempts": body.attempts,
            "recorded": attempt is not None,
        },
    )

    if attempt is not None:
        release = await db.get(AgentUpdateRelease, attempt.release_id)
        if release is not None:
            await db.flush()
            decision = updates.evaluate_halt(
                status_counts=await _status_counts(db, release.id),
                failure_threshold_percent=release.failure_threshold_percent,
                min_attempts_before_halt=release.min_attempts_before_halt,
            )
            if decision.halt and release.state != AgentUpdateReleaseState.halted:
                await _halt_release(db, release, decision.reason, actor="system")
            release_state = release.state.value

    await db.commit()
    return SelfUpdateReportAck(
        ok=True, recorded=attempt is not None, release_state=release_state
    )
