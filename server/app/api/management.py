# SPDX-License-Identifier: AGPL-3.0-only
"""Operator-facing endpoints: manage clients, sites, enrollment tokens, view
agents, and dispatch commands.

Authorization model:
  - The whole router requires a valid operator token (readonly or higher). This
    is set as a router-level dependency, so no route is reachable anonymously.
  - Mutating provisioning routes require `operator` or higher.
  - Command dispatch applies an explicit policy in the handler so both role
    denials and the separate arbitrary-script permission are auditable.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_role
from app.core import (
    anchor,
    anchor_publish,
    audit,
    inventory,
    inventory_diff,
    metrics,
    retention,
)
from app.core.clientip import client_ip
from app.core.command_envelope import (
    ACTIVE_COMMAND_ENVELOPE_VERSION,
    COMMAND_ENVELOPE_V3,
    COMMAND_SCHEMA_VERSION,
    canonical_command_bytes,
    format_command_time,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import generate_token, hash_token, sign_command
from app.core.keyring import active_signing_key, load_keyring
from app.core.redaction import AUDIT_DETAIL_SCHEMAS
from app.schemas.inventory import (
    InventoryDiffOut,
    InventoryHistoryOut,
    InventoryOut,
    InventorySection,
    InventorySectionOut,
)
from app.core.script_authorization import (
    authorize_command,
    decision_audit_detail,
)
from app.models.models import (
    Agent,
    AgentStatus,
    AgentTrustState,
    AgentInventorySnapshot,
    AnchorPublication,
    AuditEvent,
    AuditAnchor,
    Client,
    Command,
    CommandKind,
    CommandStatus,
    EnrollmentToken,
    EnrollmentTokenStatus,
    Heartbeat,
    Operator,
    OperatorRole,
    Site,
)
from app.schemas.schemas import (
    AgentOut,
    AuditEventListOut,
    AuditEventOut,
    AnchorOut,
    AnchorVerifyOut,
    ClientCreate,
    ClientOut,
    CommandCreate,
    CommandDetailOut,
    CommandHistoryItemOut,
    CommandHistoryOut,
    CommandOut,
    EnrollmentTokenCreate,
    EnrollmentTokenListOut,
    EnrollmentTokenMetadataOut,
    EnrollmentTokenOut,
    EnrollmentDashboardOut,
    EndpointDetailOut,
    EndpointListItemOut,
    EndpointListOut,
    EndpointTelemetrySampleOut,
    NavigationClientListOut,
    NavigationClientOut,
    NavigationSiteOut,
    SiteCreate,
    SiteOut,
    TrustStateChange,
)

# Router-level dependency: every route here needs at least a readonly operator.
router = APIRouter(
    tags=["management"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


MAX_NAVIGATION_CLIENTS = 200


async def _navigation_client(
    db: AsyncSession, client: Client, site_counts: dict[str, int] | None = None
) -> NavigationClientOut:
    if site_counts is None:
        site_counts = dict(
            (
                await db.execute(
                    select(Agent.site_id, func.count(Agent.id))
                    .where(Agent.site_id.in_([site.id for site in client.sites]))
                    .group_by(Agent.site_id)
                )
            ).all()
        ) if client.sites else {}
    return NavigationClientOut(
        id=client.id,
        name=client.name,
        sites=[
            NavigationSiteOut(
                id=site.id,
                client_id=site.client_id,
                name=site.name,
                endpoint_count=site_counts.get(site.id, 0),
            )
            for site in client.sites
        ],
    )


# --------------------------------------------------------------------------- #
# Clients & sites
# --------------------------------------------------------------------------- #
@router.post("/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
async def create_client(
    body: ClientCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    duplicate = await db.scalar(
        select(Client.id).where(
            func.lower(func.trim(Client.name)) == body.name.casefold()
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "client_name_exists"},
        )
    client = Client(name=body.name)
    db.add(client)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "client_name_exists"},
        ) from exc
    await audit.record(
        db,
        action="client.created",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=client.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={"client_id": client.id, "name": client.name},
    )
    return client


@router.get("/clients", response_model=list[ClientOut])
async def list_clients(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Client).order_by(Client.created_at))
    return list(result.scalars().all())


@router.get("/clients/navigation", response_model=NavigationClientListOut)
async def list_client_navigation(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client)
        .options(selectinload(Client.sites))
        .order_by(Client.created_at, Client.id)
        .limit(MAX_NAVIGATION_CLIENTS + 1)
    )
    clients = list(result.scalars().unique().all())
    truncated = len(clients) > MAX_NAVIGATION_CLIENTS
    visible_clients = clients[:MAX_NAVIGATION_CLIENTS]
    site_ids = [site.id for client in visible_clients for site in client.sites]
    site_counts = dict(
        (
            await db.execute(
                select(Agent.site_id, func.count(Agent.id))
                .where(Agent.site_id.in_(site_ids))
                .group_by(Agent.site_id)
            )
        ).all()
    ) if site_ids else {}
    items = [
        await _navigation_client(db, client, site_counts) for client in visible_clients
    ]
    await audit.record(
        db,
        action="client_navigation.list_viewed",
        actor=operator.email,
        detail={"client_count": len(items), "truncated": truncated},
    )
    return NavigationClientListOut(items=items, truncated=truncated)


@router.get("/clients/{client_id}", response_model=NavigationClientOut)
async def get_client_navigation(
    client_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client).options(selectinload(Client.sites)).where(Client.id == client_id)
    )
    client = result.scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")
    await audit.record(
        db,
        action="client_navigation.client_viewed",
        actor=operator.email,
        detail={"client_id": client.id},
    )
    return await _navigation_client(db, client)


@router.post("/sites", response_model=SiteOut, status_code=status.HTTP_201_CREATED)
async def create_site(
    body: SiteCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    if not await db.get(Client, body.client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    duplicate = await db.scalar(
        select(Site.id).where(
            Site.client_id == body.client_id,
            func.lower(func.trim(Site.name)) == body.name.casefold(),
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "site_name_exists"},
        )
    site = Site(client_id=body.client_id, name=body.name)
    db.add(site)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "site_name_exists"},
        ) from exc
    await audit.record(
        db,
        action="site.created",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=body.client_id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "site_id": site.id,
            "client_id": site.client_id,
            "name": site.name,
        },
    )
    return site


@router.get("/sites/{site_id}", response_model=NavigationSiteOut)
async def get_site_navigation(
    site_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Site, func.count(Agent.id))
        .outerjoin(Agent, Agent.site_id == Site.id)
        .where(Site.id == site_id)
        .group_by(Site.id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")
    site, endpoint_count = row
    await audit.record(
        db,
        action="client_navigation.site_viewed",
        actor=operator.email,
        detail={"site_id": site.id, "client_id": site.client_id},
    )
    return NavigationSiteOut(
        id=site.id,
        client_id=site.client_id,
        name=site.name,
        endpoint_count=endpoint_count,
    )


# --------------------------------------------------------------------------- #
# Enrollment tokens
# --------------------------------------------------------------------------- #
async def _enrollment_token_metadata(
    db: AsyncSession, token: EnrollmentToken
) -> EnrollmentTokenMetadataOut:
    site = await db.get(Site, token.site_id)
    if site is None:
        raise HTTPException(status_code=500, detail="Enrollment token assignment is invalid")
    organization = await db.get(Client, site.client_id)
    if organization is None:
        raise HTTPException(status_code=500, detail="Enrollment token assignment is invalid")
    assigned = await db.get(Operator, token.assigned_user_id) if token.assigned_user_id else None
    created_by = await db.get(Operator, token.created_by_id) if token.created_by_id else None
    revoked_by = await db.get(Operator, token.revoked_by_id) if token.revoked_by_id else None
    return EnrollmentTokenMetadataOut(
        id=token.id,
        site_id=site.id,
        organization_id=organization.id,
        organization_name=organization.name,
        site_name=site.name,
        masked_token=f"{token.token_prefix or 'nlenr'}••••••••",
        name=token.name,
        description=token.description,
        label=token.label,
        assigned_user_id=token.assigned_user_id,
        assigned_user_email=assigned.email if assigned else None,
        environment=token.environment,
        hostname_restriction=token.hostname_restriction,
        agent_name_restriction=token.agent_name_restriction,
        labels=list(token.labels or []),
        max_uses=token.max_uses,
        use_count=token.uses,
        expires_at=token.expires_at,
        created_at=token.created_at,
        created_by_id=token.created_by_id,
        created_by_email=created_by.email if created_by else None,
        last_used_at=token.last_used_at,
        revoked_at=token.revoked_at,
        revoked_by_id=token.revoked_by_id,
        revoked_by_email=revoked_by.email if revoked_by else None,
        status=token.status,
        notes=token.notes,
    )


def _sortable_time(value: datetime | None) -> float:
    if value is None:
        return float("-inf")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


@router.post("/enrollment-tokens", response_model=EnrollmentTokenOut)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    site = await db.get(Site, body.site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    if body.assigned_user_id and not await db.get(Operator, body.assigned_user_id):
        raise HTTPException(status_code=404, detail="Assigned user not found")

    now = _now()
    expires_at = body.expires_at or (
        now + timedelta(hours=settings.enrollment_token_default_expiry_hours)
    )
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=422, detail="Token expiration must be in the future")
    if expires_at > now + timedelta(days=settings.enrollment_token_max_expiry_days):
        raise HTTPException(
            status_code=422,
            detail=f"Token expiration cannot exceed {settings.enrollment_token_max_expiry_days} days",
        )
    if body.max_uses > settings.enrollment_token_max_uses:
        raise HTTPException(status_code=422, detail="Maximum uses exceeds deployment policy")

    plaintext = f"nlenr_{generate_token()}"
    etoken = EnrollmentToken(
        site_id=body.site_id,
        token_hash=hash_token(plaintext),
        token_prefix=plaintext[:12],
        name=body.name if body.name != "Enrollment token" or not body.label else body.label,
        description=body.description,
        label=body.label,
        assigned_user_id=body.assigned_user_id,
        environment=body.environment,
        hostname_restriction=body.hostname_restriction,
        agent_name_restriction=body.agent_name_restriction,
        labels=body.labels,
        max_uses=body.max_uses,
        expires_at=expires_at,
        created_by_id=operator.id,
        notes=body.notes,
    )
    db.add(etoken)
    await db.flush()

    await audit.record(
        db,
        action="enrollment_token.created",
        actor=operator.email,
        actor_user_id=operator.id,
        enrollment_token_id=etoken.id,
        organization_id=site.client_id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "site_id": site.id,
            "name": etoken.name,
            "expires_at": expires_at.isoformat(),
            "max_uses": etoken.max_uses,
            "has_hostname_restriction": bool(etoken.hostname_restriction),
            "has_agent_name_restriction": bool(etoken.agent_name_restriction),
            "labels": etoken.labels,
        },
    )
    metrics.increment("enrollment_token_created_total")
    metadata = await _enrollment_token_metadata(db, etoken)
    return EnrollmentTokenOut(**metadata.model_dump(), token=plaintext)


@router.get("/enrollment-tokens", response_model=EnrollmentTokenListOut)
async def list_enrollment_tokens(
    search: str | None = Query(default=None, max_length=100),
    token_status: EnrollmentTokenStatus | None = Query(default=None, alias="status"),
    organization_id: str | None = Query(default=None, max_length=36),
    site_id: str | None = Query(default=None, max_length=36),
    sort: str = Query(default="created_at", pattern="^(created_at|expires_at|name|status|use_count)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(EnrollmentToken).join(Site).join(Client)
    if organization_id:
        stmt = stmt.where(Client.id == organization_id)
    if site_id:
        stmt = stmt.where(Site.id == site_id)
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                EnrollmentToken.name.ilike(term),
                EnrollmentToken.description.ilike(term),
                EnrollmentToken.label.ilike(term),
            )
        )
    tokens = list((await db.execute(stmt)).scalars().all())
    if token_status:
        tokens = [token for token in tokens if token.status == token_status]
    key = {
        "created_at": lambda token: _sortable_time(token.created_at),
        "expires_at": lambda token: _sortable_time(token.expires_at),
        "name": lambda token: token.name.casefold(),
        "status": lambda token: token.status.value,
        "use_count": lambda token: token.uses,
    }[sort]
    tokens.sort(key=key, reverse=direction == "desc")
    total = len(tokens)
    page_tokens = tokens[(page - 1) * page_size : page * page_size]
    return EnrollmentTokenListOut(
        items=[await _enrollment_token_metadata(db, token) for token in page_tokens],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/enrollment-tokens/{token_id}", response_model=EnrollmentTokenMetadataOut)
async def get_enrollment_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
):
    token = await db.get(EnrollmentToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Enrollment token not found")
    return await _enrollment_token_metadata(db, token)


@router.post("/enrollment-tokens/{token_id}/revoke", response_model=EnrollmentTokenMetadataOut)
async def revoke_enrollment_token(
    token_id: str,
    body: TrustStateChange,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    token = await db.get(EnrollmentToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Enrollment token not found")
    if not token.revoked:
        now = _now()
        token.revoked = True
        token.revoked_at = now
        token.revoked_by_id = operator.id
        site = await db.get(Site, token.site_id)
        await audit.record(
            db,
            action="enrollment_token.revoked",
            actor=operator.email,
            actor_user_id=operator.id,
            enrollment_token_id=token.id,
            organization_id=site.client_id if site else None,
            source_ip=client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:500] or None,
            detail={"site_id": token.site_id, "reason": body.reason},
        )
        metrics.increment("enrollment_token_revoked_total")
    return await _enrollment_token_metadata(db, token)


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #
@router.get("/agents", response_model=list[AgentOut])
async def list_agents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).order_by(Agent.enrolled_at))
    return list(result.scalars().all())


@router.get("/endpoints", response_model=EndpointListOut)
async def list_endpoints(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    client_id: str | None = Query(default=None, min_length=1, max_length=36),
    site_id: str | None = Query(default=None, min_length=1, max_length=36),
    status: AgentStatus | None = None,
    search: str | None = Query(default=None, min_length=1, max_length=100),
    sort: str = Query(default="last_seen", pattern="^(last_seen|hostname|status)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    latest_heartbeat_id = (
        select(Heartbeat.id)
        .where(Heartbeat.agent_id == Agent.id)
        .correlate(Agent)
        .order_by(Heartbeat.ts.desc(), Heartbeat.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    filters = []
    if client_id:
        filters.append(Client.id == client_id)
    if site_id:
        filters.append(Site.id == site_id)
    if status:
        filters.append(Agent.status == status)
    if search:
        filters.append(Agent.hostname.ilike(f"%{search.strip()}%"))
    base = select(Agent).join(Site).join(Client).where(*filters)
    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    sort_column = {
        "hostname": Agent.hostname,
        "status": Agent.status,
        "last_seen": Agent.last_seen_at,
    }[sort]
    ordering = sort_column.asc() if direction == "asc" else sort_column.desc()
    result = await db.execute(
        select(Agent, Client, Site, Heartbeat)
        .join(Site, Agent.site_id == Site.id)
        .join(Client, Site.client_id == Client.id)
        .outerjoin(Heartbeat, Heartbeat.id == latest_heartbeat_id)
        .where(*filters)
        .order_by(ordering, Agent.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = [
        EndpointListItemOut(
            id=agent.id,
            hostname=agent.hostname,
            os=agent.os,
            os_version=agent.os_version,
            agent_version=agent.agent_version,
            status=agent.status,
            last_seen_at=agent.last_seen_at,
            client_id=client.id,
            client_name=client.name,
            site_id=site.id,
            site_name=site.name,
            cpu_percent=heartbeat.cpu_percent if heartbeat else None,
            mem_percent=heartbeat.mem_percent if heartbeat else None,
            disk_percent=heartbeat.disk_percent if heartbeat else None,
            logged_in_user=heartbeat.logged_in_user if heartbeat else None,
        )
        for agent, client, site, heartbeat in result.all()
    ]
    await audit.record(
        db,
        action="endpoint_list.viewed",
        actor=operator.email,
        detail={
            "client_id": client_id,
            "site_id": site_id,
            "status": status.value if status else None,
            "search": bool(search),
            "sort": sort,
            "direction": direction,
            "page": page,
            "page_size": page_size,
            "result_count": len(items),
        },
    )
    return EndpointListOut(items=items, page=page, page_size=page_size, total=total)


@router.get("/endpoints/{endpoint_id}", response_model=EndpointDetailOut)
async def get_endpoint_detail(
    endpoint_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    history_hours: int = Query(default=24, ge=1, le=168),
    history_limit: int = Query(default=144, ge=10, le=500),
    db: AsyncSession = Depends(get_db),
):
    endpoint_result = await db.execute(
        select(Agent, Client, Site)
        .join(Site, Agent.site_id == Site.id)
        .join(Client, Site.client_id == Client.id)
        .where(Agent.id == endpoint_id)
    )
    endpoint_row = endpoint_result.one_or_none()
    if endpoint_row is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    agent, client, site = endpoint_row
    latest_heartbeat = await db.scalar(
        select(Heartbeat)
        .where(Heartbeat.agent_id == agent.id)
        .order_by(Heartbeat.ts.desc(), Heartbeat.id.desc())
        .limit(1)
    )
    cutoff = _now() - timedelta(hours=history_hours)
    heartbeat_result = await db.execute(
        select(Heartbeat)
        .where(Heartbeat.agent_id == agent.id, Heartbeat.ts >= cutoff)
        .order_by(Heartbeat.ts.desc(), Heartbeat.id.desc())
        .limit(history_limit + 1)
    )
    descending_heartbeats = list(heartbeat_result.scalars().all())
    history_truncated = len(descending_heartbeats) > history_limit
    history = list(reversed(descending_heartbeats[:history_limit]))
    script_execution_allowed = authorize_command(
        operator, agent, CommandKind.powershell
    ).allowed

    def telemetry_sample(heartbeat: Heartbeat) -> EndpointTelemetrySampleOut:
        return EndpointTelemetrySampleOut(
            ts=heartbeat.ts,
            cpu_percent=heartbeat.cpu_percent,
            mem_percent=heartbeat.mem_percent,
            disk_percent=heartbeat.disk_percent,
            uptime_seconds=heartbeat.uptime_seconds,
            logged_in_user=heartbeat.logged_in_user,
        )

    stale_after_seconds = max(settings.heartbeat_interval_seconds * 3, 300)
    if latest_heartbeat is None:
        telemetry_freshness = "unavailable"
    else:
        latest_ts = latest_heartbeat.ts
        if latest_ts.tzinfo is None:
            latest_ts = latest_ts.replace(tzinfo=timezone.utc)
        telemetry_freshness = (
            "stale"
            if _now() - latest_ts > timedelta(seconds=stale_after_seconds)
            else "current"
        )

    await audit.record(
        db,
        action="endpoint_detail.viewed",
        actor=operator.email,
        agent_id=agent.id,
        detail={
            "history_hours": history_hours,
            "history_limit": history_limit,
            "history_count": len(history),
            "history_truncated": history_truncated,
            "script_execution_allowed": script_execution_allowed,
        },
    )
    return EndpointDetailOut(
        id=agent.id,
        hostname=agent.hostname,
        os=agent.os,
        os_version=agent.os_version,
        agent_version=agent.agent_version,
        command_envelope_versions=agent.command_envelope_versions,
        status=agent.status,
        trust_state=agent.trust_state,
        last_seen_at=agent.last_seen_at,
        enrolled_at=agent.enrolled_at,
        client_id=client.id,
        client_name=client.name,
        site_id=site.id,
        site_name=site.name,
        script_execution_allowed=script_execution_allowed,
        current_telemetry=telemetry_sample(latest_heartbeat) if latest_heartbeat else None,
        telemetry=[telemetry_sample(heartbeat) for heartbeat in history],
        telemetry_freshness=telemetry_freshness,
        stale_after_seconds=stale_after_seconds,
        history_hours=history_hours,
        history_limit=history_limit,
        history_truncated=history_truncated,
    )


@router.get("/agents/{agent_id}", response_model=AgentOut)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


# --------------------------------------------------------------------------- #
# Agent trust state
# --------------------------------------------------------------------------- #
def _trust_conflict(agent: Agent, wanted: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "agent_trust_state_conflict",
            "current": agent.trust_state.value,
            "requested": wanted,
        },
    )


async def _apply_trust_change(
    db: AsyncSession,
    agent: Agent,
    new_state: AgentTrustState,
    reason: str,
    operator: Operator,
    action: str,
) -> Agent:
    previous = agent.trust_state
    agent.trust_state = new_state
    agent.trust_state_reason = reason
    agent.trust_state_changed_at = _now()
    agent.trust_state_changed_by = operator.email
    site = await db.get(Site, agent.site_id)
    await audit.record(
        db,
        action=action,
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=agent.id,
        organization_id=site.client_id if site else None,
        detail={
            "previous_trust_state": previous.value,
            "trust_state": new_state.value,
            "reason": reason,
        },
    )
    return agent


@router.post("/agents/{agent_id}/quarantine", response_model=AgentOut)
async def quarantine_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Suspend trust in an agent without destroying its identity.

    A quarantined agent still authenticates and checks in (so the operator can
    see it is alive), but receives no commands, may not submit results, and has
    no telemetry or inventory recorded. Reversible via restore.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state != AgentTrustState.active:
        raise _trust_conflict(agent, AgentTrustState.quarantined.value)
    return await _apply_trust_change(
        db, agent, AgentTrustState.quarantined, body.reason, operator, "agent.quarantined"
    )


@router.post("/agents/{agent_id}/restore", response_model=AgentOut)
async def restore_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Return a quarantined agent to active. Revoked agents cannot be restored —
    revocation is terminal and the endpoint must re-enroll as a new identity."""
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state != AgentTrustState.quarantined:
        raise _trust_conflict(agent, AgentTrustState.active.value)
    return await _apply_trust_change(
        db, agent, AgentTrustState.active, body.reason, operator, "agent.restored"
    )


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
async def revoke_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Permanently revoke an agent's credentials (admin only — irreversible).

    The agent's bearer token stops authenticating entirely, and any still-queued
    or dispatched-but-unreported commands are expired so nothing issued under
    the old trust can be delivered or complete later.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state == AgentTrustState.revoked:
        raise _trust_conflict(agent, AgentTrustState.revoked.value)

    result = await db.execute(
        select(Command).where(
            Command.agent_id == agent.id,
            Command.status.in_(
                [
                    CommandStatus.queued,
                    CommandStatus.dispatched,
                    CommandStatus.running,
                    CommandStatus.result_pending,
                ]
            ),
        )
    )
    expired_ids = []
    for cmd in result.scalars().all():
        cmd.status = CommandStatus.expired
        expired_ids.append(cmd.id)

    agent = await _apply_trust_change(
        db, agent, AgentTrustState.revoked, body.reason, operator, "agent.revoked"
    )
    agent.revoked_at = _now()
    metrics.increment("agent_revoked_total")
    if expired_ids:
        await audit.record(
            db,
            action="agent.commands_expired_on_revoke",
            actor=operator.email,
            agent_id=agent.id,
            detail={"command_ids": sorted(expired_ids)},
        )
    return agent


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@router.get("/signing-keys")
async def list_signing_keys(db: AsyncSession = Depends(get_db)):
    """Expose redacted key lifecycle state for operator verification."""
    active_id, keys = load_keyring()
    return {
        "active_key_id": active_id,
        "keys": [
            {"key_id": key_id, "status": key.status, "active": key_id == active_id}
            for key_id, key in sorted(keys.items())
        ],
    }


@router.post("/agents/{agent_id}/commands", response_model=CommandOut)
async def dispatch_command(
    agent_id: str,
    body: CommandCreate,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Queue a command for an agent, signed so the agent can verify authenticity.

    The acting operator is recorded in the audit event, so the tamper-evident
    log answers not just *what* ran but *who* ordered it.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    decision = authorize_command(operator, agent, body.kind)
    decision_detail = decision_audit_detail(
        decision,
        operator=operator,
        agent=agent,
        kind=body.kind,
    )
    if not decision.allowed:
        # HTTPException would normally roll the request transaction back. This
        # denial audit is the only mutation so commit it explicitly before the
        # fail-closed response; no command has been signed or queued.
        await audit.record(
            db,
            action="command.authorization_denied",
            actor=operator.email,
            agent_id=agent.id,
            detail=decision_detail,
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "code": (
                    "script_execution_not_authorized"
                    if body.kind in (CommandKind.powershell, CommandKind.shell)
                    else "command_role_not_authorized"
                )
            },
        )
    # Trust gate before capability negotiation: no new work may even be queued
    # for an agent the server no longer fully trusts.
    if agent.trust_state != AgentTrustState.active:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_not_trusted",
                "trust_state": agent.trust_state.value,
            },
        )
    # Admission control: cap the outstanding (non-terminal) work per agent so a
    # runaway operator or client cannot pile unbounded commands on one
    # endpoint. Terminal commands (succeeded/failed/expired) do not count.
    outstanding = (
        await db.execute(
            select(func.count())
            .select_from(Command)
            .where(
                Command.agent_id == agent_id,
                Command.status.in_(
                    [
                        CommandStatus.queued,
                        CommandStatus.dispatched,
                        CommandStatus.running,
                        CommandStatus.result_pending,
                    ]
                ),
            )
        )
    ).scalar_one()
    if outstanding >= settings.max_outstanding_commands_per_agent:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "agent_command_queue_full",
                "outstanding": outstanding,
                "limit": settings.max_outstanding_commands_per_agent,
            },
        )
    envelope_version = select_command_envelope_version(
        agent.command_envelope_versions or []
    )
    if envelope_version is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_command_envelope_version_unsupported",
                "required": ACTIVE_COMMAND_ENVELOPE_VERSION,
                "agent_supported": agent.command_envelope_versions or [],
            },
        )

    await audit.record(
        db,
        action="command.authorization_allowed",
        actor=operator.email,
        agent_id=agent.id,
        detail=decision_detail,
    )
    now = _now()
    key_id = active_signing_key().key_id if envelope_version == COMMAND_ENVELOPE_V3 else None
    cmd = Command(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        kind=body.kind,
        payload=body.payload,
        envelope_version=envelope_version,
        schema_version=COMMAND_SCHEMA_VERSION,
        issued_at=now,
        nonce=generate_token(24),
        signing_key_id=key_id,
        status=CommandStatus.queued,
        created_at=now,
        expires_at=now + timedelta(seconds=body.ttl_seconds),
    )
    db.add(cmd)
    await db.flush()  # persist before signing

    cmd.signature = sign_command(
        envelope_version=cmd.envelope_version,
        schema_version=cmd.schema_version,
        command_id=cmd.id,
        agent_id=agent_id,
        kind=body.kind.value,
        payload=body.payload,
        issued_at=format_command_time(cmd.issued_at),
        expires_at=format_command_time(cmd.expires_at),
        nonce=cmd.nonce,
        signing_key_id=cmd.signing_key_id,
    )
    envelope_sha256 = hashlib.sha256(
        canonical_command_bytes(
            cmd.envelope_version,
            cmd.schema_version,
            cmd.id,
            agent_id,
            body.kind.value,
            body.payload,
            format_command_time(cmd.issued_at),
            format_command_time(cmd.expires_at),
            cmd.nonce,
            cmd.signing_key_id,
        )
    ).hexdigest()

    await audit.record(
        db,
        action="command.dispatched",
        actor=operator.email,
        agent_id=agent_id,
        detail={
            "command_id": cmd.id,
            "kind": body.kind.value,
            "payload_keys": sorted(body.payload),
            "envelope_version": cmd.envelope_version,
            "schema_version": cmd.schema_version,
            "issued_at": format_command_time(cmd.issued_at),
            "expires_at": format_command_time(cmd.expires_at),
            "nonce": cmd.nonce,
            "signing_key_id": cmd.signing_key_id,
            "envelope_sha256": envelope_sha256,
        },
    )
    return cmd


def _effective_command_status(cmd: Command, now: datetime) -> CommandStatus:
    """Report queued/dispatched work past expires_at as expired.

    The stored row flips to expired at the next agent heartbeat sweep; until
    then the operator view must not present dead work as pending. The rare
    race where a dispatched command's result lands just after expiry keeps the
    agent-reported terminal status, which is the truthful record of what ran.
    """
    if cmd.status in (CommandStatus.queued, CommandStatus.dispatched):
        expires = cmd.expires_at
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < now:
                return CommandStatus.expired
    return cmd.status


@router.get("/agents/{agent_id}/commands", response_model=CommandHistoryOut)
async def list_commands(
    agent_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Paginated command history for one endpoint, newest first."""
    if await db.get(Agent, agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    total = (
        await db.execute(
            select(func.count()).select_from(Command).where(Command.agent_id == agent_id)
        )
    ).scalar_one()
    outstanding = (
        await db.execute(
            select(func.count())
            .select_from(Command)
            .where(
                Command.agent_id == agent_id,
                Command.status.in_(
                    [
                        CommandStatus.queued,
                        CommandStatus.dispatched,
                        CommandStatus.running,
                        CommandStatus.result_pending,
                    ]
                ),
            )
        )
    ).scalar_one()
    result = await db.execute(
        select(Command)
        .where(Command.agent_id == agent_id)
        .order_by(Command.created_at.desc(), Command.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    now = _now()
    items = []
    for cmd in result.scalars().all():
        item = CommandHistoryItemOut.model_validate(cmd)
        item.status = _effective_command_status(cmd, now)
        items.append(item)
    return CommandHistoryOut(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        outstanding=outstanding,
        outstanding_limit=settings.max_outstanding_commands_per_agent,
    )


@router.get(
    "/agents/{agent_id}/commands/{command_id}", response_model=CommandDetailOut
)
async def get_command(
    agent_id: str,
    command_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """One command's signed-envelope evidence and bounded result streams.

    Viewing is audited: the detail response includes captured stdout/stderr,
    which can contain sensitive endpoint data, so the record must show who
    read it.
    """
    cmd = (
        await db.execute(
            select(Command).where(
                Command.id == command_id, Command.agent_id == agent_id
            )
        )
    ).scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")
    detail = CommandDetailOut.model_validate(cmd)
    detail.status = _effective_command_status(cmd, _now())
    await audit.record(
        db,
        action="command_detail.viewed",
        actor=operator.email,
        agent_id=agent_id,
        detail={"command_id": cmd.id, "status": detail.status.value},
    )
    return detail


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
@router.get("/enrollment-dashboard", response_model=EnrollmentDashboardOut)
async def enrollment_dashboard(db: AsyncSession = Depends(get_db)):
    agents = list((await db.execute(select(Agent))).scalars().all())
    tokens = list((await db.execute(select(EnrollmentToken))).scalars().all())
    recent_agents = list(
        (
            await db.execute(
                select(Agent)
                .order_by(Agent.enrolled_at.desc(), Agent.id.desc())
                .limit(8)
            )
        ).scalars().all()
    )
    failure_cutoff = _now() - timedelta(hours=24)
    recent_failures = (
        await db.execute(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.action == "agent.enrollment_failed",
                AuditEvent.ts >= failure_cutoff,
            )
        )
    ).scalar_one()
    return EnrollmentDashboardOut(
        total_agents=len(agents),
        active_agents=sum(
            agent.trust_state == AgentTrustState.active
            and agent.status != AgentStatus.offline
            for agent in agents
        ),
        offline_agents=sum(agent.status == AgentStatus.offline for agent in agents),
        revoked_agents=sum(
            agent.trust_state == AgentTrustState.revoked for agent in agents
        ),
        active_enrollment_tokens=sum(
            token.status == EnrollmentTokenStatus.active for token in tokens
        ),
        expired_tokens=sum(
            token.status == EnrollmentTokenStatus.expired for token in tokens
        ),
        recently_enrolled_agents=recent_agents,
        recent_enrollment_failures=recent_failures,
    )


# --------------------------------------------------------------------------- #
# Inventory views (issue #40)
# --------------------------------------------------------------------------- #
@router.get("/endpoints/{endpoint_id}/inventory", response_model=InventoryOut)
async def get_endpoint_inventory(
    endpoint_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """The endpoint's current inventory: the newest snapshot per section.

    Sections this build knows about but the endpoint has never reported are
    listed separately rather than omitted, so "we have no data for this" is
    visible instead of looking like the section does not exist.
    """
    agent = await db.get(Agent, endpoint_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    latest = await inventory.latest_sections(db, endpoint_id)
    items = [
        InventorySectionOut.model_validate(latest[name])
        for name in sorted(latest)
    ]
    missing = [
        section for section in InventorySection if section.value not in latest
    ]
    await audit.record(
        db,
        action="inventory.viewed",
        actor=operator.email,
        agent_id=endpoint_id,
        detail={
            "sections": sorted(latest),
            "missing_sections": [section.value for section in missing],
        },
    )
    return InventoryOut(
        agent_id=endpoint_id, sections=items, missing_sections=missing
    )


@router.get(
    "/endpoints/{endpoint_id}/inventory/{section}/history",
    response_model=InventoryHistoryOut,
)
async def get_inventory_history(
    endpoint_id: str,
    section: InventorySection,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Snapshots for one section, newest first.

    Rows exist only where content actually changed, so the history is a list of
    *changes* rather than a sample of every collection. Retention bounds how far
    back it reaches; the newest row is never pruned.
    """
    agent = await db.get(Agent, endpoint_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    filters = [
        AgentInventorySnapshot.agent_id == endpoint_id,
        AgentInventorySnapshot.section == section.value,
    ]
    total = (
        await db.execute(
            select(func.count()).select_from(AgentInventorySnapshot).where(*filters)
        )
    ).scalar_one()
    rows = list(
        (
            await db.execute(
                select(AgentInventorySnapshot)
                .where(*filters)
                .order_by(
                    AgentInventorySnapshot.received_at.desc(),
                    AgentInventorySnapshot.id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()
    )
    return InventoryHistoryOut(
        agent_id=endpoint_id,
        section=section,
        items=[InventorySectionOut.model_validate(row) for row in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/endpoints/{endpoint_id}/inventory/{section}/diff",
    response_model=InventoryDiffOut,
)
async def get_inventory_diff(
    endpoint_id: str,
    section: InventorySection,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    from_snapshot: str | None = Query(default=None, max_length=36),
    to_snapshot: str | None = Query(default=None, max_length=36),
    db: AsyncSession = Depends(get_db),
):
    """What changed between two snapshots of one section.

    With no explicit snapshots this compares the two most recent, which is the
    common question: "what changed on this endpoint most recently?". Both
    snapshots must belong to this endpoint and this section — a diff across
    endpoints would silently compare unrelated machines.
    """
    agent = await db.get(Agent, endpoint_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    async def _load(snapshot_id: str) -> AgentInventorySnapshot:
        row = await db.get(AgentInventorySnapshot, snapshot_id)
        if (
            row is None
            or row.agent_id != endpoint_id
            or row.section != section.value
        ):
            # Same response whether it belongs to another endpoint or does not
            # exist: no cross-endpoint probing through this parameter.
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return row

    if from_snapshot and to_snapshot:
        before = await _load(from_snapshot)
        after = await _load(to_snapshot)
    else:
        recent = list(
            (
                await db.execute(
                    select(AgentInventorySnapshot)
                    .where(
                        AgentInventorySnapshot.agent_id == endpoint_id,
                        AgentInventorySnapshot.section == section.value,
                    )
                    .order_by(
                        AgentInventorySnapshot.received_at.desc(),
                        AgentInventorySnapshot.id.desc(),
                    )
                    .limit(2)
                )
            ).scalars().all()
        )
        if len(recent) < 2:
            # One snapshot (or none) is not an error: the endpoint simply has
            # not changed this section since it was first reported.
            return InventoryDiffOut(
                agent_id=endpoint_id,
                section=section,
                comparable=False,
                before=(
                    InventorySectionOut.model_validate(recent[0]) if recent else None
                ),
                after=None,
                diff={"field_changes": [], "list_changes": {}},
                summary=inventory_diff.summarize_diff({}),
            )
        after, before = recent[0], recent[1]

    computed = inventory_diff.diff_payloads(
        section.value, before.payload, after.payload
    )
    await audit.record(
        db,
        action="inventory.diff_viewed",
        actor=operator.email,
        agent_id=endpoint_id,
        detail={
            "section": section.value,
            "from_snapshot": before.id,
            "to_snapshot": after.id,
        },
    )
    return InventoryDiffOut(
        agent_id=endpoint_id,
        section=section,
        comparable=True,
        before=InventorySectionOut.model_validate(before),
        after=InventorySectionOut.model_validate(after),
        diff=computed,
        summary=inventory_diff.summarize_diff(computed),
    )


@router.get("/audit/event-types")
async def list_audit_event_types():
    """Every audit action a production producer may emit.

    Sourced from the redaction policy registry, which ``audit.record`` enforces
    fail-closed, so a filter list built from this endpoint cannot drift from the
    actions that can actually appear in the chain."""
    return {"items": sorted(AUDIT_DETAIL_SCHEMAS)}


@router.get("/audit/events", response_model=AuditEventListOut)
async def list_audit_events(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    event_type: str | None = Query(default=None, max_length=100),
    actor: str | None = Query(default=None, max_length=255),
    agent_id: str | None = Query(default=None, max_length=36),
    organization_id: str | None = Query(default=None, max_length=36),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    before_seq: int | None = Query(default=None, ge=1),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Audit events newest first by sequence number.

    Ordering is by ``seq`` rather than timestamp: the sequence is the value the
    chain hashes and verification walks, so a page boundary here matches the
    boundary verification uses. Legacy pre-sequence events sort last.

    Pagination is pinned to a sequence ceiling. The chain only ever appends, and
    newest-first offset pagination over a growing list shifts rows onto later
    pages — a caller turning the page would see a row twice and could conclude
    the register was inconsistent. The first request's ceiling is returned as
    ``before_seq``; passing it back makes every later page a view of that same
    snapshot. This view is also self-referential (reading it records an
    ``audit_timeline.viewed`` event), so without the ceiling paging would
    duplicate a row on every single page turn rather than only under concurrent
    activity.
    """
    if before_seq is None:
        before_seq = (
            await db.execute(select(func.max(AuditEvent.seq)))
        ).scalar_one_or_none()
    filters = []
    if before_seq is not None:
        # Legacy pre-sequence rows have no ceiling to compare against and sort
        # last; excluding them here would drop them from every snapshot.
        filters.append(
            or_(AuditEvent.seq <= before_seq, AuditEvent.seq.is_(None))
        )
    if event_type:
        filters.append(AuditEvent.action == event_type)
    if actor:
        filters.append(AuditEvent.actor.ilike(f"%{actor.strip()}%"))
    if agent_id:
        filters.append(AuditEvent.agent_id == agent_id)
    if organization_id:
        filters.append(AuditEvent.organization_id == organization_id)
    if date_from:
        filters.append(AuditEvent.ts >= date_from)
    if date_to:
        filters.append(AuditEvent.ts <= date_to)
    total = (
        await db.execute(
            select(func.count()).select_from(AuditEvent).where(*filters)
        )
    ).scalar_one()
    events = list(
        (
            await db.execute(
                select(AuditEvent)
                .where(*filters)
                # nullslast() is explicit because the backends disagree by
                # default: PostgreSQL sorts NULLs first under DESC, SQLite sorts
                # them last. Legacy pre-sequence events must land in the same
                # place on both, and the ts/id tiebreakers keep the total order
                # stable so a row cannot repeat or be skipped across pages.
                .order_by(
                    AuditEvent.seq.desc().nullslast(),
                    AuditEvent.ts.desc(),
                    AuditEvent.id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()
    )
    await audit.record(
        db,
        action="audit_timeline.viewed",
        actor=operator.email,
        detail={
            # Only a registered action name is recorded verbatim; anything else
            # is collapsed so a query string cannot inject prose into the chain.
            "event_type": (
                event_type
                if event_type in AUDIT_DETAIL_SCHEMAS
                else "unregistered" if event_type else None
            ),
            "actor_filter": bool(actor),
            "agent_id": agent_id,
            "organization_id": organization_id,
            "date_from": bool(date_from),
            "date_to": bool(date_to),
            "before_seq": before_seq,
            "page": page,
            "page_size": page_size,
            "result_count": len(events),
            "total": total,
        },
    )
    return AuditEventListOut(
        items=[AuditEventOut.model_validate(event) for event in events],
        before_seq=before_seq,
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/audit/events/{event_id}", response_model=AuditEventOut)
async def get_audit_event(
    event_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """One audit event with its full recorded detail.

    The detail was already sanitized by the redaction policy before it was
    hashed, so this route exposes the same safe representation that chain and
    anchor verification cover — there is no unredacted form to leak."""
    event = await db.get(AuditEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Audit event not found")
    out = AuditEventOut.model_validate(event)
    await audit.record(
        db,
        action="audit_event.viewed",
        actor=operator.email,
        detail={"event_id": event.id, "action": event.action, "seq": event.seq},
    )
    return out


@router.get("/audit/verify")
async def verify_audit_chain(db: AsyncSession = Depends(get_db)):
    ok, broken_at = await audit.verify_chain(db)
    return {"intact": ok, "first_broken_event_id": broken_at}


@router.post("/audit/anchors", response_model=AnchorOut)
async def create_audit_anchor(
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Commit to the audit chain as it stands: compute the Merkle root over all
    event hashes and store it as an anchor.

    The returned `merkle_root` is the value to publish OUTSIDE this system
    (transparency log, on-chain, the monthly compliance report). The anchor row
    alone proves nothing against an attacker with database access — the
    external copies are what make history un-rewritable.
    """
    result = await anchor.create_anchor(db)
    if result is None:
        raise HTTPException(status_code=400, detail="No audit events to anchor")

    await audit.record(
        db,
        action="audit.anchored",
        actor=operator.email,
        detail={
            "anchor_id": result.id,
            "merkle_root": result.merkle_root,
            "event_count": result.event_count,
        },
    )
    return result


@router.get("/audit/anchors", response_model=list[AnchorOut])
async def list_audit_anchors(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditAnchor).order_by(AuditAnchor.created_at))
    return list(result.scalars().all())


@router.get("/audit/anchors/{anchor_id}/verify", response_model=AnchorVerifyOut)
async def verify_audit_anchor(anchor_id: str, db: AsyncSession = Depends(get_db)):
    """Recompute the Merkle root over the anchor's covered prefix and compare.
    A mismatch means events covered by the anchor were altered, removed, or
    reordered after it was made."""
    a = await db.get(AuditAnchor, anchor_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Anchor not found")
    ok, reason = await anchor.verify_anchor(db, a)
    return AnchorVerifyOut(anchor_id=a.id, intact=ok, reason=reason)


@router.get("/audit/publication-status")
async def audit_publication_status(db: AsyncSession = Depends(get_db)):
    """Operator-visible lag/health of external anchor publication.

    `lag_alert` is true when the oldest unpublished anchor is older than the
    configured threshold — the window in which a database-owning attacker could
    rewrite history before any external copy exists. A null backend means
    publication is disabled, in which case every anchor is unpublished."""
    status = await anchor_publish.publication_status(db)
    return {
        "backend": status.backend,
        "total_anchors": status.total_anchors,
        "published": status.published,
        "pending": status.pending,
        "oldest_unpublished_age_seconds": status.oldest_unpublished_age_seconds,
        "lag_alert": status.lag_alert,
        "last_error": status.last_error,
    }


@router.get("/storage/status")
async def storage_status(db: AsyncSession = Depends(get_db)):
    """Observable storage growth for every persistent data class (issue #114).

    Reports per-class counts, oldest-age, backlog, host disk headroom, and
    unpublished-anchor lag, each with a threshold-breach flag; `alert` is true
    when any class has breached. Audit data and anchors are reported for capacity
    planning but are never pruned, so this endpoint has no effect on chain or
    external-anchor verification."""
    return await retention.storage_status(db, settings)


@router.get("/audit/anchors/{anchor_id}/receipt")
async def audit_anchor_receipt(anchor_id: str, db: AsyncSession = Depends(get_db)):
    """The external-publication receipt(s) for an anchor, with a tamper check.

    Each receipt is the destination's proof of publication (e.g. an S3 object
    version-id + ETag). `receipt_intact` recomputes the stored receipt digest —
    false means the receipt row itself was altered. Receipts never contain
    credentials."""
    a = await db.get(AuditAnchor, anchor_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Anchor not found")
    rows = (
        await db.execute(
            select(AnchorPublication).where(AnchorPublication.anchor_id == anchor_id)
        )
    ).scalars().all()
    out = []
    for r in rows:
        intact, reason = anchor_publish.verify_receipt(r)
        out.append({
            "backend": r.backend,
            "status": r.status,
            "uri": r.uri,
            "receipt": r.receipt,
            "receipt_sha256": r.receipt_sha256,
            "receipt_intact": intact,
            "receipt_reason": reason,
            "attempts": r.attempts,
            "last_error": r.last_error,
            "published_at": r.published_at,
        })
    return {"anchor_id": anchor_id, "merkle_root": a.merkle_root, "publications": out}
