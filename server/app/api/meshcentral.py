# SPDX-License-Identifier: AGPL-3.0-only
"""Authorized, audited MeshCentral remote-desktop launch endpoints (issue #62).

NodeLink authorizes, identity-maps, and audits a *launch* and mints a
short-lived, single-device access URL through MeshCentral's own API. It never
proxies the desktop stream, never stores the minted login material, and treats
MeshCentral as a separate trust boundary. Every gate fails closed.
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
from app.core.meshcentral import (
    MeshCentralClient,
    MeshCentralError,
    get_client,
    provider_enabled,
)
from app.core.meshcentral_mapping import get_mapping_for_agent, mapping_availability
from app.core.script_authorization import authorize_command
from app.models.models import (
    Agent,
    AgentTrustState,
    CommandKind,
    MeshLaunchRecord,
    MeshLaunchStatus,
    Operator,
    OperatorRole,
)
from app.schemas.meshcentral import (
    MeshAvailabilityOut,
    MeshLaunchOut,
    MeshLaunchRequest,
)

router = APIRouter(
    tags=["remote-desktop"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)

# Mapping reason code -> (http status, response code). All fail closed.
_MAPPING_HTTP = {
    "no_mapping": (409, "remote_desktop_unmapped"),
    "mapping_unmapped": (409, "remote_desktop_unmapped"),
    "mapping_stale": (409, "remote_desktop_mapping_stale"),
    "mapping_conflict": (409, "remote_desktop_mapping_conflict"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_evidence(request: Request, operator: Operator) -> dict[str, Any]:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def get_meshcentral_client() -> MeshCentralClient | None:
    """Injectable client factory. Tests override this with a Fake client."""
    return get_client(settings)


async def _record_denied(
    db: AsyncSession,
    agent: Agent,
    *,
    reason: str,
    policy: str,
    evidence: dict[str, Any],
    launch_id: str | None = None,
) -> None:
    await audit.record(
        db,
        action="meshcentral.launch_denied",
        agent_id=agent.id,
        detail={
            "launch_id": launch_id,
            "agent_id": agent.id,
            "reason": reason,
            "policy": policy,
            "trust_state": agent.trust_state.value,
        },
        **evidence,
    )
    await db.commit()


async def _get_launch(
    db: AsyncSession, agent_id: str, launch_id: str
) -> MeshLaunchRecord:
    row = (
        await db.execute(
            select(MeshLaunchRecord).where(
                MeshLaunchRecord.id == launch_id,
                MeshLaunchRecord.agent_id == agent_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Remote desktop launch not found")
    return row


def _require_owner(row: MeshLaunchRecord, operator: Operator) -> None:
    # 404 (not 403) so a second operator cannot use this endpoint as a
    # launch-ID oracle. Admins see lifecycle evidence through the audit log.
    if row.operator_id != operator.id:
        raise HTTPException(404, detail="Remote desktop launch not found")


@router.get(
    "/agents/{agent_id}/remote-desktop/availability",
    response_model=MeshAvailabilityOut,
)
async def remote_desktop_availability(
    agent_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Fail-closed availability so the dashboard can render without a launch."""
    enabled = provider_enabled(settings)
    if not enabled:
        return MeshAvailabilityOut(
            available=False, reason="provider_disabled", provider_enabled=False
        )
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, detail="Agent not found")
    if agent.trust_state != AgentTrustState.active:
        return MeshAvailabilityOut(
            available=False, reason="agent_not_trusted", provider_enabled=True
        )
    authorization = authorize_command(operator, agent, CommandKind.powershell)
    if not authorization.allowed:
        return MeshAvailabilityOut(
            available=False, reason="not_authorized", provider_enabled=True
        )
    mapping = await get_mapping_for_agent(db, agent_id)
    available, reason = mapping_availability(mapping, settings)
    return MeshAvailabilityOut(
        available=available, reason=reason, provider_enabled=True
    )


@router.post(
    "/agents/{agent_id}/remote-desktop/launches",
    response_model=MeshLaunchOut,
    status_code=status.HTTP_201_CREATED,
)
async def launch_remote_desktop(
    agent_id: str,
    body: MeshLaunchRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
    client: MeshCentralClient | None = Depends(get_meshcentral_client),
):
    evidence = _request_evidence(request, operator)

    # 1. Provider disabled -> fail closed before touching the agent.
    if not provider_enabled(settings) or client is None:
        agent = await db.get(Agent, agent_id)
        if agent is not None:
            await _record_denied(
                db,
                agent,
                reason="provider_disabled",
                policy="provider",
                evidence=evidence,
            )
        raise HTTPException(409, detail={"code": "remote_desktop_disabled"})

    # 2. Agent must exist.
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, detail="Agent not found")

    # 3. Authorization: operator role + explicit arbitrary-script scope, exactly
    # like an interactive shell. Admin is not a bypass.
    authorization = authorize_command(operator, agent, CommandKind.powershell)
    if not authorization.allowed:
        await _record_denied(
            db,
            agent,
            reason="not_authorized",
            policy=authorization.policy,
            evidence=evidence,
        )
        raise HTTPException(403, detail={"code": "remote_desktop_not_authorized"})

    # 4. Agent trust state.
    if agent.trust_state != AgentTrustState.active:
        await _record_denied(
            db, agent, reason="agent_not_trusted", policy="trust_state", evidence=evidence
        )
        raise HTTPException(409, detail={"code": "agent_not_trusted"})

    # 5. Identity mapping must exist and be fresh (fail closed on stale/conflict).
    mapping = await get_mapping_for_agent(db, agent_id)
    available, reason = mapping_availability(mapping, settings)
    if not available:
        await _record_denied(
            db, agent, reason=reason, policy="mapping", evidence=evidence
        )
        http_status, code = _MAPPING_HTTP.get(reason, (409, "remote_desktop_unmapped"))
        raise HTTPException(http_status, detail={"code": code})

    # 6. Per-operator launch rate limit (durable, idempotent count).
    window_start = _now() - timedelta(seconds=60)
    recent = (
        await db.execute(
            select(func.count(MeshLaunchRecord.id)).where(
                MeshLaunchRecord.operator_id == operator.id,
                MeshLaunchRecord.created_at >= window_start,
            )
        )
    ).scalar_one()
    if recent >= settings.meshcentral_max_launches_per_operator_per_minute:
        await _record_denied(
            db, agent, reason="rate_limited", policy="rate_limit", evidence=evidence
        )
        raise HTTPException(
            429,
            detail={"code": "remote_desktop_rate_limited"},
            headers={"Retry-After": "60"},
        )

    # 7. Insert the launch record and audit the request, then mint.
    row = MeshLaunchRecord(
        agent_id=agent_id,
        mapping_id=mapping.id,
        operator_id=operator.id,
        actor_email=operator.email,
        meshcentral_node_id=mapping.meshcentral_node_id,
        status=MeshLaunchStatus.requested,
        created_at=_now(),
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        action="meshcentral.launch_requested",
        agent_id=agent.id,
        detail={
            "launch_id": row.id,
            "agent_id": agent.id,
            "meshcentral_node_id": mapping.meshcentral_node_id,
            "mapping_id": mapping.id,
        },
        **evidence,
    )

    try:
        minted = await client.mint_device_login(
            node_id=mapping.meshcentral_node_id,
            ttl_seconds=settings.meshcentral_login_ttl_seconds,
            operator_ref=operator.id,
        )
    except MeshCentralError as exc:
        row.status = MeshLaunchStatus.failed
        row.denied_reason = exc.code[:64]
        row.closed_at = _now()
        await audit.record(
            db,
            action="meshcentral.launch_failed",
            agent_id=agent.id,
            detail={
                "launch_id": row.id,
                "agent_id": agent.id,
                "meshcentral_node_id": mapping.meshcentral_node_id,
                "reason": exc.code,
            },
            **evidence,
        )
        await db.commit()
        raise HTTPException(503, detail={"code": "remote_desktop_unavailable"})

    row.status = MeshLaunchStatus.authorized
    row.expires_at = minted.expires_at
    row.meshcentral_session_ref = minted.session_ref
    await audit.record(
        db,
        action="meshcentral.session_launched",
        agent_id=agent.id,
        detail={
            "launch_id": row.id,
            "agent_id": agent.id,
            "meshcentral_node_id": mapping.meshcentral_node_id,
            "mapping_id": mapping.id,
            "expires_at": minted.expires_at.isoformat(),
            "meshcentral_session_ref": minted.session_ref,
            "reason": body.reason or "operator_launch",
        },
        **evidence,
    )
    await db.commit()

    out = MeshLaunchOut.model_validate(row)
    out.login_url = minted.login_url
    out.login_expires_at = minted.expires_at
    return out


@router.get(
    "/agents/{agent_id}/remote-desktop/launches/{launch_id}",
    response_model=MeshLaunchOut,
)
async def get_remote_desktop_launch(
    agent_id: str,
    launch_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_launch(db, agent_id, launch_id)
    _require_owner(row, operator)
    # login_url is deliberately never populated on GET.
    return MeshLaunchOut.model_validate(row)


@router.post(
    "/agents/{agent_id}/remote-desktop/launches/{launch_id}/close",
    response_model=MeshLaunchOut,
)
async def close_remote_desktop_launch(
    agent_id: str,
    launch_id: str,
    body: MeshLaunchRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
    client: MeshCentralClient | None = Depends(get_meshcentral_client),
):
    row = await _get_launch(db, agent_id, launch_id)
    _require_owner(row, operator)
    if row.status in (MeshLaunchStatus.closed, MeshLaunchStatus.failed, MeshLaunchStatus.denied):
        return MeshLaunchOut.model_validate(row)
    row.status = MeshLaunchStatus.closed
    row.closed_at = _now()
    # Best-effort revoke; MeshCentral remains authoritative for its own session.
    if client is not None and row.meshcentral_session_ref:
        await client.revoke(row.meshcentral_session_ref)
    await audit.record(
        db,
        action="meshcentral.session_closed",
        agent_id=agent_id,
        detail={
            "launch_id": row.id,
            "agent_id": agent_id,
            "meshcentral_node_id": row.meshcentral_node_id,
            "status": row.status.value,
            "reason": body.reason or "operator_closed",
        },
        **_request_evidence(request, operator),
    )
    await db.commit()
    return MeshLaunchOut.model_validate(row)
