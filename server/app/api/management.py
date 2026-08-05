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
    email_notifications,
    inventory,
    inventory_diff,
    metrics,
    monitoring as monitoring_core,
    retention,
    webhook_notifications,
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
from app.core.redaction import AUDIT_DETAIL_SCHEMAS, scrub_text
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
    Alert,
    AlertEmailAttempt,
    AlertEmailDelivery,
    AlertWebhookAttempt,
    AlertWebhookDelivery,
    AlertEvent,
    AlertEventType,
    AlertObservation,
    AlertState,
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
    CheckResult,
    CheckResultStatus,
    EnrollmentToken,
    EnrollmentTokenStatus,
    EmailDeliveryStatus,
    Heartbeat,
    MaintenanceWindow,
    MonitoringPolicy,
    MonitoringPolicyRevision,
    MonitoringScope,
    Operator,
    OperatorRole,
    Site,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookSecretVersion,
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
from app.schemas.monitoring import (
    AlertDetailOut,
    AlertAcknowledge,
    AlertAssign,
    AlertAssigneeOut,
    AlertComment,
    AlertEmailAttemptOut,
    AlertEmailDeliveryListOut,
    AlertEmailDeliveryOut,
    AlertEmailRetry,
    AlertEmailStatusOut,
    AlertWebhookAttemptOut,
    AlertWebhookDeliveryListOut,
    AlertWebhookDeliveryOut,
    AlertWebhookRetry,
    AlertEventOut,
    AlertListOut,
    AlertOut,
    AlertResolve,
    CheckResultListOut,
    EffectiveCheckOut,
    EffectivePolicyOut,
    MaintenanceWindowCreate,
    MaintenanceWindowOut,
    MonitoringPolicyCreate,
    MonitoringPolicyDetailOut,
    MonitoringPolicyOut,
    MonitoringPolicyRevisionOut,
    MonitoringPolicyUpdate,
    WebhookDestinationValidationOut,
    WebhookEndpointCreate,
    WebhookEndpointOut,
    WebhookEndpointSecretOut,
    WebhookEndpointUpdate,
    WebhookSecretRotate,
    WebhookStatusOut,
)

# Router-level dependency: every route here needs at least a readonly operator.
router = APIRouter(
    tags=["management"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


MAX_NAVIGATION_CLIENTS = 200


async def _require_monitoring_scope_target(
    db: AsyncSession, scope: MonitoringScope, scope_id: str | None
) -> None:
    """Verify the polymorphic monitoring scope target before persisting it."""
    if scope == MonitoringScope.global_:
        return
    model = {
        MonitoringScope.client: Client,
        MonitoringScope.site: Site,
        MonitoringScope.agent: Agent,
    }[scope]
    if scope_id is None or await db.get(model, scope_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "monitoring_scope_target_not_found"},
        )


def _require_monitoring_check_bounds(checks) -> None:
    if len(checks) > settings.monitoring_max_checks_per_policy:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "monitoring_policy_check_limit_exceeded"},
        )
    if any(
        check.schedule.interval_seconds
        < settings.monitoring_check_interval_min_seconds
        or check.schedule.interval_seconds
        > settings.monitoring_check_interval_max_seconds
        for check in checks
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "monitoring_check_interval_out_of_bounds"},
        )


async def _policy_revisions(
    db: AsyncSession, policy_id: str
) -> list[MonitoringPolicyRevision]:
    result = await db.execute(
        select(MonitoringPolicyRevision)
        .where(MonitoringPolicyRevision.policy_id == policy_id)
        .order_by(
            MonitoringPolicyRevision.version.desc(),
            MonitoringPolicyRevision.created_at.desc(),
        )
    )
    return list(result.scalars().all())


async def _policy_out(
    db: AsyncSession, policy: MonitoringPolicy
) -> MonitoringPolicyOut:
    revision = await monitoring_core.current_revision(db, policy.id)
    checks = revision.checks if revision is not None else []
    return MonitoringPolicyOut(
        id=policy.id,
        name=policy.name,
        scope=policy.scope,
        scope_id=policy.scope_id,
        enabled=policy.enabled,
        created_at=policy.created_at,
        current_version=revision.version if revision is not None else 0,
        check_count=len(checks or []),
    )


async def _policy_detail(
    db: AsyncSession, policy: MonitoringPolicy
) -> MonitoringPolicyDetailOut:
    revisions = await _policy_revisions(db, policy.id)
    current = revisions[0] if revisions else None
    summary = await _policy_out(db, policy)
    return MonitoringPolicyDetailOut(
        **summary.model_dump(),
        checks=current.checks if current is not None else [],
        revisions=[
            MonitoringPolicyRevisionOut.model_validate(revision)
            for revision in revisions
        ],
    )


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
# Monitoring policies, windows, and result views (issue #41)
# --------------------------------------------------------------------------- #
@router.post(
    "/monitoring/policies",
    response_model=MonitoringPolicyDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_monitoring_policy(
    body: MonitoringPolicyCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    await _require_monitoring_scope_target(db, body.scope, body.scope_id)
    policy_count = (
        await db.execute(select(func.count()).select_from(MonitoringPolicy))
    ).scalar_one()
    if policy_count >= settings.monitoring_max_policies:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "monitoring_policy_limit_reached"},
        )
    _require_monitoring_check_bounds(body.checks)
    duplicate = await db.scalar(
        select(MonitoringPolicy.id).where(
            MonitoringPolicy.scope == body.scope,
            MonitoringPolicy.scope_id == body.scope_id,
            func.lower(func.trim(MonitoringPolicy.name)) == body.name.casefold(),
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "monitoring_policy_name_exists"},
        )

    policy = MonitoringPolicy(
        name=body.name,
        scope=body.scope,
        scope_id=body.scope_id,
        enabled=body.enabled,
    )
    db.add(policy)
    await db.flush()
    revision = MonitoringPolicyRevision(
        policy_id=policy.id,
        version=1,
        checks=[check.model_dump(mode="json") for check in body.checks],
        change_note=body.change_note,
        created_by=operator.email,
    )
    db.add(revision)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "monitoring_policy_name_exists"},
        ) from exc
    await audit.record(
        db,
        action="monitoring_policy.created",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "policy_id": policy.id,
            "scope": policy.scope.value,
            "scope_id": policy.scope_id,
            "enabled": policy.enabled,
            "check_count": len(body.checks),
            "name": policy.name,
            "change_note": body.change_note or "",
        },
    )
    return await _policy_detail(db, policy)


@router.get("/monitoring/policies", response_model=list[MonitoringPolicyOut])
async def list_monitoring_policies(db: AsyncSession = Depends(get_db)):
    policies = list(
        (
            await db.execute(
                select(MonitoringPolicy).order_by(
                    MonitoringPolicy.scope,
                    MonitoringPolicy.name,
                    MonitoringPolicy.id,
                )
            )
        ).scalars().all()
    )
    return [await _policy_out(db, policy) for policy in policies]


@router.get(
    "/monitoring/policies/{policy_id}", response_model=MonitoringPolicyDetailOut
)
async def get_monitoring_policy(
    policy_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(MonitoringPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Monitoring policy not found")
    detail = await _policy_detail(db, policy)
    await audit.record(
        db,
        action="monitoring_policy.viewed",
        actor=operator.email,
        detail={
            "policy_id": policy.id,
            "version": detail.current_version,
            "check_count": detail.check_count,
            "revision_count": len(detail.revisions),
        },
    )
    return detail


@router.put(
    "/monitoring/policies/{policy_id}", response_model=MonitoringPolicyDetailOut
)
async def revise_monitoring_policy(
    policy_id: str,
    body: MonitoringPolicyUpdate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(MonitoringPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Monitoring policy not found")
    _require_monitoring_check_bounds(body.checks)
    latest_version = await db.scalar(
        select(func.max(MonitoringPolicyRevision.version)).where(
            MonitoringPolicyRevision.policy_id == policy.id
        )
    )
    revision = MonitoringPolicyRevision(
        policy_id=policy.id,
        version=(latest_version or 0) + 1,
        checks=[check.model_dump(mode="json") for check in body.checks],
        change_note=body.change_note,
        created_by=operator.email,
    )
    if body.enabled is not None:
        policy.enabled = body.enabled
    db.add(revision)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "monitoring_policy_revision_conflict"},
        ) from exc
    active_check_keys = (
        {check.key for check in body.checks if check.enabled}
        if policy.enabled
        else set()
    )
    await monitoring_core.resolve_policy_alerts(
        db,
        policy.id,
        active_check_keys=active_check_keys,
        reason="policy_revised",
    )
    await audit.record(
        db,
        action="monitoring_policy.revised",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "policy_id": policy.id,
            "version": revision.version,
            "enabled": policy.enabled,
            "check_count": len(body.checks),
            "change_note": body.change_note or "",
        },
    )
    return await _policy_detail(db, policy)


@router.delete("/monitoring/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitoring_policy(
    policy_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(MonitoringPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Monitoring policy not found")
    await monitoring_core.resolve_policy_alerts(
        db, policy.id, reason="policy_deleted"
    )
    await audit.record(
        db,
        action="monitoring_policy.deleted",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "policy_id": policy.id,
            "scope": policy.scope.value,
            "scope_id": policy.scope_id,
            "name": policy.name,
        },
    )
    await db.delete(policy)
    return None


@router.get(
    "/monitoring/policies/{policy_id}/revisions",
    response_model=list[MonitoringPolicyRevisionOut],
)
async def list_monitoring_policy_revisions(
    policy_id: str, db: AsyncSession = Depends(get_db)
):
    if await db.get(MonitoringPolicy, policy_id) is None:
        raise HTTPException(status_code=404, detail="Monitoring policy not found")
    return [
        MonitoringPolicyRevisionOut.model_validate(revision)
        for revision in await _policy_revisions(db, policy_id)
    ]


@router.get(
    "/agents/{agent_id}/monitoring/effective-policy",
    response_model=EffectivePolicyOut,
)
async def get_agent_effective_monitoring_policy(
    agent_id: str, db: AsyncSession = Depends(get_db)
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    checks = await monitoring_core.resolve_effective_policy(db, agent)
    return EffectivePolicyOut(
        agent_id=agent.id,
        checks=[
            EffectiveCheckOut(
                definition=item.definition,
                source_scope=item.source_scope,
                source_policy_id=item.source_policy_id,
                source_revision_id=item.source_revision_id,
                source_policy_name=item.source_policy_name,
            )
            for item in checks
        ],
    )


@router.post(
    "/monitoring/maintenance-windows",
    response_model=MaintenanceWindowOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_maintenance_window(
    body: MaintenanceWindowCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    await _require_monitoring_scope_target(db, body.scope, body.scope_id)
    window_count = (
        await db.execute(select(func.count()).select_from(MaintenanceWindow))
    ).scalar_one()
    if window_count >= settings.monitoring_max_maintenance_windows:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "maintenance_window_limit_reached"},
        )
    window = MaintenanceWindow(
        name=body.name,
        scope=body.scope,
        scope_id=body.scope_id,
        starts_at=body.starts_at,
        ends_at=body.ends_at,
        created_by=operator.email,
    )
    db.add(window)
    await db.flush()
    await audit.record(
        db,
        action="maintenance_window.created",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "maintenance_window_id": window.id,
            "scope": window.scope.value,
            "scope_id": window.scope_id,
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
            "name": window.name,
        },
    )
    return window


@router.get(
    "/monitoring/maintenance-windows", response_model=list[MaintenanceWindowOut]
)
async def list_maintenance_windows(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(MaintenanceWindow).order_by(
            MaintenanceWindow.starts_at, MaintenanceWindow.id
        )
    )
    return list(result.scalars().all())


@router.delete(
    "/monitoring/maintenance-windows/{window_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_maintenance_window(
    window_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    window = await db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    await audit.record(
        db,
        action="maintenance_window.deleted",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "maintenance_window_id": window.id,
            "scope": window.scope.value,
            "scope_id": window.scope_id,
            "name": window.name,
        },
    )
    await db.delete(window)
    return None


@router.get(
    "/agents/{agent_id}/monitoring/results", response_model=CheckResultListOut
)
async def list_agent_monitoring_results(
    agent_id: str,
    check_key: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Agent, agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    conditions = [CheckResult.agent_id == agent_id]
    if check_key is not None:
        conditions.append(CheckResult.check_key == check_key)
    rows = list(
        (
            await db.execute(
                select(CheckResult)
                .where(*conditions)
                .order_by(CheckResult.received_at.desc(), CheckResult.id.desc())
                .limit(limit)
            )
        ).scalars().all()
    )
    return CheckResultListOut(agent_id=agent_id, items=rows)


@router.get("/monitoring/alerts", response_model=AlertListOut)
async def list_monitoring_alerts(
    agent_id: str | None = Query(default=None, max_length=36),
    policy_id: str | None = Query(default=None, max_length=36),
    check_key: str | None = Query(default=None, max_length=64),
    state: AlertState | None = Query(default=None),
    result_status: CheckResultStatus | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if agent_id is not None:
        conditions.append(Alert.agent_id == agent_id)
    if policy_id is not None:
        conditions.append(Alert.policy_id == policy_id)
    if check_key is not None:
        conditions.append(Alert.check_key == check_key)
    if state is not None:
        conditions.append(Alert.state == state)
    if result_status is not None:
        conditions.append(Alert.last_result_status == result_status)
    rows = list(
        (
            await db.execute(
                select(Alert)
                .where(*conditions)
                .order_by(Alert.last_observed_at.desc(), Alert.id.desc())
                .limit(limit)
            )
        ).scalars().all()
    )
    return AlertListOut(items=rows)


async def _alert_detail(db: AsyncSession, alert: Alert) -> AlertDetailOut:
    observations = list(
        (
            await db.execute(
                select(AlertObservation)
                .where(AlertObservation.alert_id == alert.id)
                .order_by(
                    AlertObservation.evaluated_at.desc(),
                    AlertObservation.check_result_id.desc(),
                )
                .limit(100)
            )
        ).scalars().all()
    )
    events = list(
        (
            await db.execute(
                select(AlertEvent)
                .where(AlertEvent.alert_id == alert.id)
                .order_by(AlertEvent.created_at.desc(), AlertEvent.id.desc())
                .limit(200)
            )
        ).scalars().all()
    )
    return AlertDetailOut.model_validate(
        {
            **AlertOut.model_validate(alert).model_dump(),
            "observations": observations,
            "events": events,
        }
    )


@router.get("/monitoring/alerts/{alert_id}", response_model=AlertDetailOut)
async def get_monitoring_alert(
    alert_id: str, db: AsyncSession = Depends(get_db)
):
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found")
    return await _alert_detail(db, alert)


@router.get("/monitoring/alert-assignees", response_model=list[AlertAssigneeOut])
async def list_monitoring_alert_assignees(
    _operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    return list(
        (
            await db.execute(
                select(Operator)
                .where(Operator.disabled.is_(False))
                .order_by(Operator.email, Operator.id)
            )
        ).scalars().all()
    )


async def _lock_alert_action(
    db: AsyncSession,
    alert_id: str,
    *,
    request_id: str,
    expected_version: int,
) -> tuple[Alert, bool]:
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id).with_for_update()
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found")
    prior = await db.scalar(
        select(AlertEvent).where(
            AlertEvent.alert_id == alert_id,
            AlertEvent.request_id == request_id,
        )
    )
    if prior is not None:
        return alert, True
    if alert.version != expected_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "alert_version_conflict",
                "current_version": alert.version,
            },
        )
    return alert, False


def _safe_alert_comment(comment: str | None) -> tuple[str | None, bool]:
    if comment is None:
        return None, False
    safe = scrub_text(comment)
    return safe, safe != comment


async def _operator_alert_event(
    db: AsyncSession,
    alert: Alert,
    event_type: AlertEventType,
    operator: Operator,
    *,
    request_id: str,
    from_state: AlertState | None,
    to_state: AlertState | None,
    comment: str | None,
    assigned_to: Operator | None = None,
) -> tuple[str | None, bool]:
    safe_comment, comment_redacted = _safe_alert_comment(comment)
    event = AlertEvent(
        id=str(uuid.uuid4()),
        alert_id=alert.id,
        generation=alert.generation,
        event_type=event_type,
        from_state=from_state,
        to_state=to_state,
        actor=operator.email,
        actor_user_id=operator.id,
        comment=safe_comment,
        comment_redacted=comment_redacted,
        assigned_to_operator_id=assigned_to.id if assigned_to else None,
        assigned_to_email=assigned_to.email if assigned_to else None,
        request_id=request_id,
    )
    db.add(event)
    email_notifications.enqueue_alert_event(db, alert, event)
    await webhook_notifications.enqueue_alert_event(db, alert, event)
    return safe_comment, comment_redacted


def _alert_audit_context(request: Request, operator: Operator) -> dict:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


@router.post(
    "/monitoring/alerts/{alert_id}/acknowledge", response_model=AlertDetailOut
)
async def acknowledge_monitoring_alert(
    alert_id: str,
    body: AlertAcknowledge,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    alert, replay = await _lock_alert_action(
        db, alert_id, request_id=body.request_id,
        expected_version=body.expected_version,
    )
    if replay:
        return await _alert_detail(db, alert)
    if alert.state != AlertState.open:
        raise HTTPException(
            status_code=409,
            detail={"code": "alert_acknowledge_invalid_state", "state": alert.state.value},
        )
    previous = alert.state
    alert.state = AlertState.acknowledged
    alert.acknowledged_at = _now()
    alert.acknowledged_by = operator.email
    alert.version += 1
    alert.updated_at = _now()
    safe_comment, redacted = await _operator_alert_event(
        db, alert, AlertEventType.acknowledged, operator,
        request_id=body.request_id, from_state=previous,
        to_state=alert.state, comment=body.comment,
    )
    await audit.record(
        db, action="monitoring_alert.acknowledged",
        agent_id=alert.agent_id, **_alert_audit_context(request, operator),
        detail={
            "alert_id": alert.id, "generation": alert.generation,
            "request_id": body.request_id, "from_state": previous.value,
            "to_state": alert.state.value, "comment": safe_comment or "",
            "comment_redacted": redacted,
        },
    )
    metrics.increment("monitoring_alert_acknowledged_total")
    await db.flush()
    return await _alert_detail(db, alert)


@router.post("/monitoring/alerts/{alert_id}/assign", response_model=AlertDetailOut)
async def assign_monitoring_alert(
    alert_id: str,
    body: AlertAssign,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    alert, replay = await _lock_alert_action(
        db, alert_id, request_id=body.request_id,
        expected_version=body.expected_version,
    )
    if replay:
        return await _alert_detail(db, alert)
    assignee = None
    if body.assigned_to_operator_id is not None:
        assignee = await db.get(Operator, body.assigned_to_operator_id)
        if assignee is None or assignee.disabled:
            raise HTTPException(
                status_code=422, detail={"code": "alert_assignee_unavailable"}
            )
    alert.assigned_to_operator_id = assignee.id if assignee else None
    alert.assigned_to_email = assignee.email if assignee else None
    alert.version += 1
    alert.updated_at = _now()
    safe_comment, redacted = await _operator_alert_event(
        db, alert, AlertEventType.assigned, operator,
        request_id=body.request_id, from_state=alert.state,
        to_state=alert.state, comment=body.comment, assigned_to=assignee,
    )
    await audit.record(
        db, action="monitoring_alert.assigned",
        agent_id=alert.agent_id, **_alert_audit_context(request, operator),
        detail={
            "alert_id": alert.id, "generation": alert.generation,
            "request_id": body.request_id,
            "assigned_to_operator_id": assignee.id if assignee else "",
            "assigned_to_email": assignee.email if assignee else "",
            "comment": safe_comment or "", "comment_redacted": redacted,
        },
    )
    metrics.increment("monitoring_alert_assigned_total")
    await db.flush()
    return await _alert_detail(db, alert)


@router.post("/monitoring/alerts/{alert_id}/comments", response_model=AlertDetailOut)
async def comment_on_monitoring_alert(
    alert_id: str,
    body: AlertComment,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    alert, replay = await _lock_alert_action(
        db, alert_id, request_id=body.request_id,
        expected_version=body.expected_version,
    )
    if replay:
        return await _alert_detail(db, alert)
    alert.version += 1
    alert.updated_at = _now()
    safe_comment, redacted = await _operator_alert_event(
        db, alert, AlertEventType.commented, operator,
        request_id=body.request_id, from_state=alert.state,
        to_state=alert.state, comment=body.comment,
    )
    await audit.record(
        db, action="monitoring_alert.commented",
        agent_id=alert.agent_id, **_alert_audit_context(request, operator),
        detail={
            "alert_id": alert.id, "generation": alert.generation,
            "request_id": body.request_id, "state": alert.state.value,
            "comment": safe_comment or "", "comment_redacted": redacted,
        },
    )
    metrics.increment("monitoring_alert_commented_total")
    await db.flush()
    return await _alert_detail(db, alert)


@router.post("/monitoring/alerts/{alert_id}/resolve", response_model=AlertDetailOut)
async def resolve_monitoring_alert(
    alert_id: str,
    body: AlertResolve,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    alert, replay = await _lock_alert_action(
        db, alert_id, request_id=body.request_id,
        expected_version=body.expected_version,
    )
    if replay:
        return await _alert_detail(db, alert)
    if alert.state == AlertState.resolved:
        raise HTTPException(
            status_code=409,
            detail={"code": "alert_resolve_invalid_state", "state": alert.state.value},
        )
    previous = alert.state
    alert.state = AlertState.resolved
    alert.resolved_at = _now()
    alert.resolution_reason = "manual_resolution"
    alert.suppression_window_id = None
    alert.suppressed_until = None
    alert.version += 1
    alert.updated_at = _now()
    safe_comment, redacted = await _operator_alert_event(
        db, alert, AlertEventType.manual_resolution, operator,
        request_id=body.request_id, from_state=previous,
        to_state=alert.state, comment=body.comment,
    )
    await audit.record(
        db, action="monitoring_alert.resolved",
        agent_id=alert.agent_id, **_alert_audit_context(request, operator),
        detail={
            "alert_id": alert.id, "generation": alert.generation,
            "request_id": body.request_id, "from_state": previous.value,
            "to_state": alert.state.value, "comment": safe_comment or "",
            "comment_redacted": redacted,
        },
    )
    metrics.increment("monitoring_alert_manually_resolved_total")
    await db.flush()
    return await _alert_detail(db, alert)


def _email_delivery_out(
    delivery: AlertEmailDelivery,
    attempts: list[AlertEmailAttempt],
) -> AlertEmailDeliveryOut:
    return AlertEmailDeliveryOut(
        id=delivery.id,
        alert_id=delivery.alert_id,
        alert_event_id=delivery.alert_event_id,
        generation=delivery.generation,
        event_type=delivery.event_type,
        recipient=email_notifications.mask_recipient(delivery.recipient),
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        max_attempts=delivery.max_attempts,
        next_attempt_at=delivery.next_attempt_at,
        provider_message_id=delivery.provider_message_id,
        last_error_code=delivery.last_error_code,
        sent_at=delivery.sent_at,
        created_at=delivery.created_at,
        updated_at=delivery.updated_at,
        attempts=[AlertEmailAttemptOut.model_validate(item) for item in attempts],
    )


@router.get(
    "/monitoring/email-alerts/status", response_model=AlertEmailStatusOut
)
async def monitoring_email_alert_status(
    db: AsyncSession = Depends(get_db),
):
    status_body = email_notifications.configuration_status(settings)
    status_body["counts"] = await email_notifications.delivery_counts(db)
    return status_body


@router.get(
    "/monitoring/alerts/{alert_id}/email-deliveries",
    response_model=AlertEmailDeliveryListOut,
)
async def list_monitoring_alert_email_deliveries(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Alert, alert_id) is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found")
    deliveries = list(
        (
            await db.execute(
                select(AlertEmailDelivery)
                .where(AlertEmailDelivery.alert_id == alert_id)
                .order_by(
                    AlertEmailDelivery.created_at.desc(),
                    AlertEmailDelivery.id.desc(),
                )
                .limit(250)
            )
        ).scalars().all()
    )
    attempts_by_delivery: dict[str, list[AlertEmailAttempt]] = {
        item.id: [] for item in deliveries
    }
    if deliveries:
        attempts = list(
            (
                await db.execute(
                    select(AlertEmailAttempt)
                    .where(
                        AlertEmailAttempt.delivery_id.in_(
                            [item.id for item in deliveries]
                        )
                    )
                    .order_by(
                        AlertEmailAttempt.created_at,
                        AlertEmailAttempt.id,
                    )
                )
            ).scalars().all()
        )
        for attempt in attempts:
            attempts_by_delivery[attempt.delivery_id].append(attempt)
    return AlertEmailDeliveryListOut(
        items=[
            _email_delivery_out(item, attempts_by_delivery[item.id])
            for item in deliveries
        ]
    )


@router.post(
    "/monitoring/email-deliveries/{delivery_id}/retry",
    response_model=AlertEmailDeliveryOut,
)
async def retry_monitoring_alert_email_delivery(
    delivery_id: str,
    body: AlertEmailRetry,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    delivery = await db.scalar(
        select(AlertEmailDelivery)
        .where(AlertEmailDelivery.id == delivery_id)
        .with_for_update()
    )
    if delivery is None:
        raise HTTPException(status_code=404, detail="Email delivery not found")
    if delivery.last_retry_request_id == body.request_id:
        attempts = list(
            (
                await db.execute(
                    select(AlertEmailAttempt)
                    .where(AlertEmailAttempt.delivery_id == delivery.id)
                    .order_by(AlertEmailAttempt.created_at, AlertEmailAttempt.id)
                )
            ).scalars().all()
        )
        return _email_delivery_out(delivery, attempts)
    if delivery.status != EmailDeliveryStatus.failed:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "email_delivery_retry_invalid_state",
                "status": delivery.status.value,
            },
        )
    if delivery.attempt_count >= 20:
        raise HTTPException(
            status_code=409,
            detail={"code": "email_delivery_retry_limit_reached"},
        )
    previous_status = delivery.status
    delivery.status = EmailDeliveryStatus.retrying
    delivery.next_attempt_at = _now()
    delivery.claimed_at = None
    delivery.max_attempts = max(delivery.max_attempts, delivery.attempt_count + 1)
    delivery.last_retry_request_id = body.request_id
    delivery.updated_at = _now()
    await audit.record(
        db,
        action="monitoring_alert_email.retried",
        agent_id=(await db.get(Alert, delivery.alert_id)).agent_id,
        **_alert_audit_context(request, operator),
        detail={
            "delivery_id": delivery.id,
            "alert_id": delivery.alert_id,
            "request_id": body.request_id,
            "previous_status": previous_status.value,
            "recipient": delivery.recipient,
        },
    )
    metrics.increment("email_alert_manual_retry_total")
    attempts = list(
        (
            await db.execute(
                select(AlertEmailAttempt)
                .where(AlertEmailAttempt.delivery_id == delivery.id)
                .order_by(AlertEmailAttempt.created_at, AlertEmailAttempt.id)
            )
        ).scalars().all()
    )
    return _email_delivery_out(delivery, attempts)


# --------------------------------------------------------------------------- #
# Signed webhook endpoints and delivery history (issue #46)
# --------------------------------------------------------------------------- #
def _webhook_destination_error(exc: webhook_notifications.WebhookError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"code": exc.code, "state": exc.state},
    )


async def _webhook_endpoint_out(
    db: AsyncSession, endpoint: WebhookEndpoint
) -> WebhookEndpointOut:
    secret = await db.scalar(
        select(WebhookSecretVersion).where(
            WebhookSecretVersion.endpoint_id == endpoint.id,
            WebhookSecretVersion.version == endpoint.current_secret_version,
        )
    )
    if secret is None:
        raise HTTPException(
            status_code=500,
            detail={"code": "webhook_secret_version_unavailable"},
        )
    return WebhookEndpointOut(
        id=endpoint.id,
        name=endpoint.name,
        url=webhook_notifications.mask_destination(endpoint.url),
        event_types=endpoint.event_types,
        enabled=endpoint.enabled,
        current_secret_version=endpoint.current_secret_version,
        current_secret_key_id=secret.id,
        version=endpoint.version,
        deleted_at=endpoint.deleted_at,
        created_at=endpoint.created_at,
        updated_at=endpoint.updated_at,
    )


@router.get("/monitoring/webhooks/status", response_model=WebhookStatusOut)
async def monitoring_webhook_status(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(
        select(func.count()).select_from(WebhookEndpoint).where(
            WebhookEndpoint.deleted_at.is_(None)
        )
    )
    enabled = await db.scalar(
        select(func.count()).select_from(WebhookEndpoint).where(
            WebhookEndpoint.deleted_at.is_(None),
            WebhookEndpoint.enabled.is_(True),
        )
    )
    return WebhookStatusOut(
        encryption_key_configured=webhook_notifications.encryption_key_configured(
            settings
        ),
        endpoint_count=total or 0,
        enabled_endpoint_count=enabled or 0,
        endpoint_limit=settings.webhook_max_endpoints,
        counts=await webhook_notifications.delivery_counts(db),
    )


@router.get(
    "/monitoring/webhook-endpoints", response_model=list[WebhookEndpointOut]
)
async def list_webhook_endpoints(db: AsyncSession = Depends(get_db)):
    endpoints = list(
        (
            await db.execute(
                select(WebhookEndpoint)
                .where(WebhookEndpoint.deleted_at.is_(None))
                .order_by(WebhookEndpoint.name, WebhookEndpoint.id)
            )
        ).scalars().all()
    )
    return [await _webhook_endpoint_out(db, endpoint) for endpoint in endpoints]


@router.post(
    "/monitoring/webhook-endpoints",
    response_model=WebhookEndpointSecretOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook_endpoint(
    body: WebhookEndpointCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    try:
        destination = await webhook_notifications.validate_destination(
            body.url, settings
        )
    except webhook_notifications.WebhookError as exc:
        raise _webhook_destination_error(exc) from exc
    endpoint_count = await db.scalar(
        select(func.count()).select_from(WebhookEndpoint).where(
            WebhookEndpoint.deleted_at.is_(None)
        )
    )
    if (endpoint_count or 0) >= settings.webhook_max_endpoints:
        raise HTTPException(
            status_code=409, detail={"code": "webhook_endpoint_limit_reached"}
        )
    now = _now()
    endpoint_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())
    plaintext_secret = webhook_notifications.generate_endpoint_secret()
    try:
        encrypted_secret = webhook_notifications.encrypt_secret(
            plaintext_secret,
            endpoint_id=endpoint_id,
            secret_id=secret_id,
            version=1,
            config=settings,
        )
    except webhook_notifications.WebhookError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "state": exc.state},
        ) from exc
    endpoint = WebhookEndpoint(
        id=endpoint_id,
        name=body.name,
        url=destination.url,
        event_types=[item.value for item in body.event_types],
        enabled=body.enabled,
        current_secret_version=1,
        version=1,
        created_by=operator.email,
        updated_by=operator.email,
        created_at=now,
        updated_at=now,
    )
    secret_version = WebhookSecretVersion(
        id=secret_id,
        endpoint_id=endpoint.id,
        version=1,
        encrypted_secret=encrypted_secret,
        created_by=operator.email,
        created_at=now,
    )
    db.add_all([endpoint, secret_version])
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "webhook_endpoint_name_exists"}
        ) from exc
    await audit.record(
        db,
        action="webhook_endpoint.created",
        **_alert_audit_context(request, operator),
        detail={
            "endpoint_id": endpoint.id,
            "name": endpoint.name,
            "url": endpoint.url,
            "enabled": endpoint.enabled,
            "event_types": endpoint.event_types,
            "secret_version": 1,
        },
    )
    public = await _webhook_endpoint_out(db, endpoint)
    return WebhookEndpointSecretOut(
        **public.model_dump(), secret=plaintext_secret
    )


@router.put(
    "/monitoring/webhook-endpoints/{endpoint_id}",
    response_model=WebhookEndpointOut,
)
async def update_webhook_endpoint(
    endpoint_id: str,
    body: WebhookEndpointUpdate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    endpoint = await db.scalar(
        select(WebhookEndpoint)
        .where(
            WebhookEndpoint.id == endpoint_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    if endpoint.version != body.expected_version:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_endpoint_version_conflict",
                "current_version": endpoint.version,
            },
        )
    if body.url is not None:
        try:
            endpoint.url = (
                await webhook_notifications.validate_destination(body.url, settings)
            ).url
        except webhook_notifications.WebhookError as exc:
            raise _webhook_destination_error(exc) from exc
    if body.name is not None:
        endpoint.name = body.name
    if body.event_types is not None:
        endpoint.event_types = [item.value for item in body.event_types]
    if body.enabled is not None:
        endpoint.enabled = body.enabled
    previous_version = endpoint.version
    endpoint.version += 1
    endpoint.updated_by = operator.email
    endpoint.updated_at = _now()
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "webhook_endpoint_name_exists"}
        ) from exc
    await audit.record(
        db,
        action="webhook_endpoint.updated",
        **_alert_audit_context(request, operator),
        detail={
            "endpoint_id": endpoint.id,
            "request_id": body.request_id,
            "previous_version": previous_version,
            "version": endpoint.version,
            "name": endpoint.name,
            "url": endpoint.url,
            "enabled": endpoint.enabled,
            "event_types": endpoint.event_types,
        },
    )
    return await _webhook_endpoint_out(db, endpoint)


@router.post(
    "/monitoring/webhook-endpoints/{endpoint_id}/validate",
    response_model=WebhookDestinationValidationOut,
)
async def validate_webhook_endpoint(
    endpoint_id: str,
    _operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    endpoint = await db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or endpoint.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    try:
        destination = await webhook_notifications.validate_destination(
            endpoint.url, settings
        )
    except webhook_notifications.WebhookError as exc:
        return WebhookDestinationValidationOut(
            endpoint_id=endpoint.id,
            state=exc.state,
            code=exc.code,
            resolved_address_count=0,
        )
    return WebhookDestinationValidationOut(
        endpoint_id=endpoint.id,
        state="valid",
        resolved_address_count=len(destination.addresses),
    )


@router.post(
    "/monitoring/webhook-endpoints/{endpoint_id}/rotate-secret",
    response_model=WebhookEndpointSecretOut,
)
async def rotate_webhook_endpoint_secret(
    endpoint_id: str,
    body: WebhookSecretRotate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    endpoint = await db.scalar(
        select(WebhookEndpoint)
        .where(
            WebhookEndpoint.id == endpoint_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    if endpoint.version != body.expected_version:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_endpoint_version_conflict",
                "current_version": endpoint.version,
            },
        )
    old_secret = await db.scalar(
        select(WebhookSecretVersion).where(
            WebhookSecretVersion.endpoint_id == endpoint.id,
            WebhookSecretVersion.version == endpoint.current_secret_version,
        )
    )
    if old_secret is None:
        raise HTTPException(
            status_code=409, detail={"code": "webhook_secret_version_unavailable"}
        )
    new_version_number = endpoint.current_secret_version + 1
    new_secret_id = str(uuid.uuid4())
    plaintext_secret = webhook_notifications.generate_endpoint_secret()
    try:
        encrypted_secret = webhook_notifications.encrypt_secret(
            plaintext_secret,
            endpoint_id=endpoint.id,
            secret_id=new_secret_id,
            version=new_version_number,
            config=settings,
        )
    except webhook_notifications.WebhookError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "state": exc.state},
        ) from exc
    now = _now()
    old_secret.retired_at = now
    db.add(
        WebhookSecretVersion(
            id=new_secret_id,
            endpoint_id=endpoint.id,
            version=new_version_number,
            encrypted_secret=encrypted_secret,
            created_by=operator.email,
            created_at=now,
        )
    )
    previous_version = endpoint.version
    previous_secret_version = endpoint.current_secret_version
    endpoint.current_secret_version = new_version_number
    endpoint.version += 1
    endpoint.updated_by = operator.email
    endpoint.updated_at = now
    await db.flush()
    await audit.record(
        db,
        action="webhook_endpoint.secret_rotated",
        **_alert_audit_context(request, operator),
        detail={
            "endpoint_id": endpoint.id,
            "request_id": body.request_id,
            "previous_version": previous_version,
            "version": endpoint.version,
            "previous_secret_version": previous_secret_version,
            "secret_version": new_version_number,
        },
    )
    public = await _webhook_endpoint_out(db, endpoint)
    return WebhookEndpointSecretOut(
        **public.model_dump(), secret=plaintext_secret
    )


@router.delete(
    "/monitoring/webhook-endpoints/{endpoint_id}", status_code=204
)
async def delete_webhook_endpoint(
    endpoint_id: str,
    request: Request,
    request_id: str = Query(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    expected_version: int = Query(ge=1),
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    endpoint = await db.scalar(
        select(WebhookEndpoint)
        .where(
            WebhookEndpoint.id == endpoint_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    if endpoint.version != expected_version:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_endpoint_version_conflict",
                "current_version": endpoint.version,
            },
        )
    previous_version = endpoint.version
    endpoint.enabled = False
    endpoint.deleted_at = _now()
    endpoint.version += 1
    endpoint.updated_by = operator.email
    endpoint.updated_at = endpoint.deleted_at
    await audit.record(
        db,
        action="webhook_endpoint.deleted",
        **_alert_audit_context(request, operator),
        detail={
            "endpoint_id": endpoint.id,
            "request_id": request_id,
            "previous_version": previous_version,
            "version": endpoint.version,
            "name": endpoint.name,
            "url": endpoint.url,
        },
    )
    return None


def _webhook_delivery_out(
    delivery: AlertWebhookDelivery,
    endpoint_name: str,
    attempts: list[AlertWebhookAttempt],
) -> AlertWebhookDeliveryOut:
    return AlertWebhookDeliveryOut(
        id=delivery.id,
        endpoint_id=delivery.endpoint_id,
        endpoint_name=endpoint_name,
        alert_id=delivery.alert_id,
        alert_event_id=delivery.alert_event_id,
        generation=delivery.generation,
        event_type=delivery.event_type,
        destination=webhook_notifications.mask_destination(
            delivery.destination_url
        ),
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        max_attempts=delivery.max_attempts,
        next_attempt_at=delivery.next_attempt_at,
        last_http_status=delivery.last_http_status,
        last_error_code=delivery.last_error_code,
        delivered_at=delivery.delivered_at,
        created_at=delivery.created_at,
        updated_at=delivery.updated_at,
        attempts=[
            AlertWebhookAttemptOut.model_validate(item) for item in attempts
        ],
    )


@router.get(
    "/monitoring/alerts/{alert_id}/webhook-deliveries",
    response_model=AlertWebhookDeliveryListOut,
)
async def list_monitoring_alert_webhook_deliveries(
    alert_id: str, db: AsyncSession = Depends(get_db)
):
    if await db.get(Alert, alert_id) is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found")
    deliveries = list(
        (
            await db.execute(
                select(AlertWebhookDelivery)
                .where(AlertWebhookDelivery.alert_id == alert_id)
                .order_by(
                    AlertWebhookDelivery.created_at.desc(),
                    AlertWebhookDelivery.id.desc(),
                )
                .limit(250)
            )
        ).scalars().all()
    )
    attempts_by_delivery: dict[str, list[AlertWebhookAttempt]] = {
        item.id: [] for item in deliveries
    }
    endpoint_names: dict[str, str] = {}
    if deliveries:
        attempts = list(
            (
                await db.execute(
                    select(AlertWebhookAttempt)
                    .where(
                        AlertWebhookAttempt.delivery_id.in_(
                            [item.id for item in deliveries]
                        )
                    )
                    .order_by(
                        AlertWebhookAttempt.created_at,
                        AlertWebhookAttempt.id,
                    )
                )
            ).scalars().all()
        )
        for attempt in attempts:
            attempts_by_delivery[attempt.delivery_id].append(attempt)
        endpoints = list(
            (
                await db.execute(
                    select(WebhookEndpoint).where(
                        WebhookEndpoint.id.in_(
                            [item.endpoint_id for item in deliveries]
                        )
                    )
                )
            ).scalars().all()
        )
        endpoint_names = {item.id: item.name for item in endpoints}
    return AlertWebhookDeliveryListOut(
        items=[
            _webhook_delivery_out(
                item,
                endpoint_names.get(item.endpoint_id, "Deleted endpoint"),
                attempts_by_delivery[item.id],
            )
            for item in deliveries
        ]
    )


@router.post(
    "/monitoring/webhook-deliveries/{delivery_id}/retry",
    response_model=AlertWebhookDeliveryOut,
)
async def retry_monitoring_alert_webhook_delivery(
    delivery_id: str,
    body: AlertWebhookRetry,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    delivery = await db.scalar(
        select(AlertWebhookDelivery)
        .where(AlertWebhookDelivery.id == delivery_id)
        .with_for_update()
    )
    if delivery is None:
        raise HTTPException(status_code=404, detail="Webhook delivery not found")
    endpoint = await db.get(WebhookEndpoint, delivery.endpoint_id)
    endpoint_name = endpoint.name if endpoint else "Deleted endpoint"
    if delivery.last_retry_request_id == body.request_id:
        attempts = list(
            (
                await db.execute(
                    select(AlertWebhookAttempt)
                    .where(AlertWebhookAttempt.delivery_id == delivery.id)
                    .order_by(
                        AlertWebhookAttempt.created_at, AlertWebhookAttempt.id
                    )
                )
            ).scalars().all()
        )
        return _webhook_delivery_out(delivery, endpoint_name, attempts)
    if delivery.status != WebhookDeliveryStatus.failed:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_delivery_retry_invalid_state",
                "status": delivery.status.value,
            },
        )
    if delivery.attempt_count >= 20:
        raise HTTPException(
            status_code=409,
            detail={"code": "webhook_delivery_retry_limit_reached"},
        )
    previous_status = delivery.status
    delivery.status = WebhookDeliveryStatus.retrying
    delivery.next_attempt_at = _now()
    delivery.claimed_at = None
    delivery.max_attempts = max(delivery.max_attempts, delivery.attempt_count + 1)
    delivery.last_retry_request_id = body.request_id
    delivery.updated_at = _now()
    alert = await db.get(Alert, delivery.alert_id)
    await audit.record(
        db,
        action="monitoring_alert_webhook.retried",
        agent_id=alert.agent_id if alert else None,
        **_alert_audit_context(request, operator),
        detail={
            "delivery_id": delivery.id,
            "alert_id": delivery.alert_id,
            "endpoint_id": delivery.endpoint_id,
            "request_id": body.request_id,
            "previous_status": previous_status.value,
            "destination": delivery.destination_url,
        },
    )
    metrics.increment("webhook_manual_retry_total")
    attempts = list(
        (
            await db.execute(
                select(AlertWebhookAttempt)
                .where(AlertWebhookAttempt.delivery_id == delivery.id)
                .order_by(
                    AlertWebhookAttempt.created_at, AlertWebhookAttempt.id
                )
            )
        ).scalars().all()
    )
    return _webhook_delivery_out(delivery, endpoint_name, attempts)


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
