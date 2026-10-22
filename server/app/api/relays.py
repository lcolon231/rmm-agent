# SPDX-License-Identifier: AGPL-3.0-only
"""Relay region, relay, relay-key, and tenant residency administration (#87).

Regions, relays, and relay keys are deployment infrastructure shared by every
tenant, so they are managed only by a platform administrator. Key registration
and every revocation additionally require a fresh step-up, because a relay key
is a credential that can carry agent traffic. A tenant's residency policy is
set by a platform administrator and readable by anyone who can see the tenant.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_operator,
    require_platform_admin,
    require_role,
    require_step_up,
)
from app.core import audit, relays
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.tenant_scope import assert_client_visible
from app.models.models import (
    Agent,
    Client,
    Operator,
    OperatorRole,
    Relay,
    RelayKey,
    RelayRegion,
    Site,
    TenantRegionPolicy,
)

router = APIRouter(tags=["relays"], dependencies=[Depends(require_platform_admin)])
tenant_router = APIRouter(
    tags=["relays"], dependencies=[Depends(require_role(OperatorRole.readonly))]
)

# Relay status transitions an operator may request. ``revoked`` is terminal.
_RELAY_TRANSITIONS = {
    "pending": {"active", "revoked"},
    "active": {"draining", "revoked"},
    "draining": {"active", "revoked"},
    "revoked": set(),
}
_REGION_TRANSITIONS = {
    "active": {"draining", "disabled"},
    "draining": {"active", "disabled"},
    "disabled": {"active"},
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _conflict(code: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": code})


def _invalid(code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"code": code}
    )


def _not_found(code: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": code})


def _validate_base_url(value: str) -> str:
    """A relay origin: https, a host, nothing an agent could be confused by."""
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise _invalid("relay_base_url_invalid")
    return f"https://{parts.netloc}"


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class RegionCreate(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    name: str = Field(min_length=1, max_length=200)


class StatusChange(BaseModel):
    status: str = Field(min_length=1, max_length=16)
    reason: str | None = Field(default=None, max_length=1000)


class RegionOut(BaseModel):
    id: str
    code: str
    name: str
    status: str
    created_at: datetime


class RelayCreate(BaseModel):
    region_id: str = Field(min_length=36, max_length=36)
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=9, max_length=512)
    tls_spki_pins: list[str] = Field(default_factory=list, max_length=4)


class RelayKeyOut(BaseModel):
    key_id: str
    public_key_sha256: str
    status: str
    not_after: datetime
    created_at: datetime
    retired_at: datetime | None
    revoked_at: datetime | None


class RelayOut(BaseModel):
    id: str
    region_id: str
    name: str
    base_url: str
    tls_spki_pins: list[str]
    status: str
    created_at: datetime
    revoked_at: datetime | None
    last_forward_at: datetime | None
    keys: list[RelayKeyOut] = Field(default_factory=list)


class RelayKeyCreate(BaseModel):
    key_id: str = Field(min_length=1, max_length=64)
    public_key_pem: str = Field(min_length=1, max_length=1024)
    not_after: datetime


class KeyRevoke(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class RegionPolicyIn(BaseModel):
    region_id: str = Field(min_length=36, max_length=36)
    mode: str = Field(min_length=1, max_length=16)


class RegionPolicyOut(BaseModel):
    client_id: str
    region_id: str | None
    region_code: str | None
    mode: str
    home_region_active_relays: int
    # Agents of this tenant that cannot route through relays and therefore
    # keep using the origin even under a strict policy.
    legacy_direct_agents: int
    updated_at: datetime | None
    set_by: str | None


def _region_out(region: RelayRegion) -> RegionOut:
    return RegionOut(
        id=region.id,
        code=region.code,
        name=region.name,
        status=region.status,
        created_at=region.created_at,
    )


async def _relay_out(db: AsyncSession, relay: Relay) -> RelayOut:
    keys = (
        await db.execute(
            select(RelayKey)
            .where(RelayKey.relay_id == relay.id)
            .order_by(RelayKey.created_at.asc(), RelayKey.key_id.asc())
        )
    ).scalars()
    return RelayOut(
        id=relay.id,
        region_id=relay.region_id,
        name=relay.name,
        base_url=relay.base_url,
        tls_spki_pins=list(relay.tls_spki_pins or []),
        status=relay.status,
        created_at=relay.created_at,
        revoked_at=relay.revoked_at,
        last_forward_at=relay.last_forward_at,
        keys=[
            RelayKeyOut(
                key_id=k.key_id,
                public_key_sha256=k.public_key_sha256,
                status=k.status,
                not_after=k.not_after,
                created_at=k.created_at,
                retired_at=k.retired_at,
                revoked_at=k.revoked_at,
            )
            for k in keys
        ],
    )


def _request_context(request: Request) -> dict:
    return {
        "source_ip": client_ip(request),
        "user_agent": (request.headers.get("user-agent") or "")[:500] or None,
    }


# --------------------------------------------------------------------------- #
# Regions
# --------------------------------------------------------------------------- #
@router.get("/relay-regions", response_model=list[RegionOut])
async def list_regions(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(RelayRegion).order_by(RelayRegion.code))).scalars()
    return [_region_out(r) for r in rows]


@router.post("/relay-regions", response_model=RegionOut, status_code=201)
async def create_region(
    body: RegionCreate,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    if not relays.REGION_CODE_RE.fullmatch(body.code):
        raise _invalid("region_code_invalid")
    if await db.scalar(select(RelayRegion).where(RelayRegion.code == body.code)):
        raise _conflict("region_code_exists")
    region = RelayRegion(code=body.code, name=body.name, status="active", created_at=_now())
    db.add(region)
    await db.flush()
    await audit.record(
        db,
        action="relay_region.created",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={"region_id": region.id, "code": region.code, "name": region.name},
        **_request_context(request),
    )
    await db.commit()
    return _region_out(region)


@router.patch("/relay-regions/{region_id}", response_model=RegionOut)
async def change_region_status(
    region_id: str,
    body: StatusChange,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    region = await db.get(RelayRegion, region_id)
    if region is None:
        raise _not_found("region_not_found")
    if body.status not in relays.REGION_STATUSES:
        raise _invalid("region_status_invalid")
    if body.status == region.status:
        return _region_out(region)
    if body.status not in _REGION_TRANSITIONS[region.status]:
        raise _conflict("region_transition_invalid")
    previous = region.status
    region.status = body.status
    await audit.record(
        db,
        action="relay_region.status_changed",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={"region_id": region.id, "previous": previous, "current": region.status},
        **_request_context(request),
    )
    await db.commit()
    return _region_out(region)


# --------------------------------------------------------------------------- #
# Relays
# --------------------------------------------------------------------------- #
@router.get("/relays", response_model=list[RelayOut])
async def list_relays(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Relay).order_by(Relay.name, Relay.id))).scalars().all()
    return [await _relay_out(db, r) for r in rows]


@router.get("/relays/{relay_id}", response_model=RelayOut)
async def get_relay(relay_id: str, db: AsyncSession = Depends(get_db)):
    relay = await db.get(Relay, relay_id)
    if relay is None:
        raise _not_found("relay_not_found")
    return await _relay_out(db, relay)


@router.post("/relays", response_model=RelayOut, status_code=201)
async def register_relay(
    body: RelayCreate,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    region = await db.get(RelayRegion, body.region_id)
    if region is None:
        raise _not_found("region_not_found")
    base_url = _validate_base_url(body.base_url)
    pins = list(dict.fromkeys(body.tls_spki_pins))
    if any(not relays.SPKI_PIN_RE.fullmatch(pin) for pin in pins):
        raise _invalid("relay_pin_invalid")
    if await db.scalar(select(Relay).where(Relay.base_url == base_url)):
        raise _conflict("relay_base_url_exists")
    relay = Relay(
        region_id=region.id,
        name=body.name,
        base_url=base_url,
        tls_spki_pins=pins,
        status="pending",
        created_at=_now(),
    )
    db.add(relay)
    await db.flush()
    await audit.record(
        db,
        action="relay.registered",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={
            "relay_id": relay.id,
            "region_id": region.id,
            "name": relay.name,
            "base_url": relay.base_url,
            "pin_count": len(pins),
        },
        **_request_context(request),
    )
    await db.commit()
    return await _relay_out(db, relay)


async def _live_keys(db: AsyncSession, relay_id: str) -> list[RelayKey]:
    return list(
        (
            await db.execute(
                select(RelayKey).where(
                    RelayKey.relay_id == relay_id, RelayKey.status == "active"
                )
            )
        ).scalars()
    )


@router.patch("/relays/{relay_id}", response_model=RelayOut)
async def change_relay_status(
    relay_id: str,
    body: StatusChange,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    relay = await db.get(Relay, relay_id)
    if relay is None:
        raise _not_found("relay_not_found")
    if body.status not in relays.RELAY_STATUSES:
        raise _invalid("relay_status_invalid")
    if body.status == relay.status:
        return await _relay_out(db, relay)
    if body.status not in _RELAY_TRANSITIONS[relay.status]:
        raise _conflict("relay_transition_invalid")
    if body.status == "revoked":
        # Revocation is a security action: it must always be possible, and it
        # must carry a fresh step-up like every other credential revocation.
        await require_step_up(operator, db)
    now = _now()
    if body.status == "active":
        live = [k for k in await _live_keys(db, relay.id) if _as_utc(k.not_after) > now]
        if not live:
            raise _conflict("relay_has_no_key")
    previous = relay.status
    relay.status = body.status
    if body.status == "revoked":
        relay.revoked_at = now
        for key in await _live_keys(db, relay.id):
            key.status = "revoked"
            key.revoked_at = now
    await audit.record(
        db,
        action="relay.status_changed",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={"relay_id": relay.id, "previous": previous, "current": relay.status},
        **_request_context(request),
    )
    await db.commit()
    return await _relay_out(db, relay)


@router.post("/relays/{relay_id}/keys", response_model=RelayOut, status_code=201)
async def register_relay_key(
    relay_id: str,
    body: RelayKeyCreate,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    relay = await db.get(Relay, relay_id)
    if relay is None:
        raise _not_found("relay_not_found")
    if relay.status == "revoked":
        raise _conflict("relay_revoked")
    if not relays.KEY_ID_RE.fullmatch(body.key_id):
        raise _invalid("relay_key_id_invalid")
    try:
        fingerprint = relays.public_key_fingerprint(body.public_key_pem)
    except (ValueError, TypeError):
        raise _invalid("relay_key_invalid") from None
    now = _now()
    not_after = _as_utc(body.not_after)
    if not_after <= now or not_after > now + timedelta(days=relays.MAX_KEY_LIFETIME_DAYS):
        raise _invalid("relay_key_lifetime_invalid")
    if await db.scalar(select(RelayKey).where(RelayKey.key_id == body.key_id)):
        raise _conflict("relay_key_id_exists")
    if await db.scalar(select(RelayKey).where(RelayKey.public_key_sha256 == fingerprint)):
        # A key is never reused, not even after retirement: reuse would make a
        # retired key's old forwards indistinguishable from new ones.
        raise _conflict("relay_key_reused")
    if len(await _live_keys(db, relay.id)) >= relays.MAX_LIVE_KEYS_PER_RELAY:
        raise _conflict("relay_key_limit")
    key = RelayKey(
        relay_id=relay.id,
        key_id=body.key_id,
        public_key_pem=body.public_key_pem.strip() + "\n",
        public_key_sha256=fingerprint,
        status="active",
        not_after=not_after,
        created_at=now,
    )
    db.add(key)
    await audit.record(
        db,
        action="relay.key_registered",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={
            "relay_id": relay.id,
            "key_id": key.key_id,
            "public_key_sha256": fingerprint,
            "not_after": not_after.isoformat(),
        },
        **_request_context(request),
    )
    await db.commit()
    return await _relay_out(db, relay)


async def _relay_key(db: AsyncSession, relay_id: str, key_id: str) -> RelayKey:
    key = await db.scalar(
        select(RelayKey).where(RelayKey.relay_id == relay_id, RelayKey.key_id == key_id)
    )
    if key is None:
        raise _not_found("relay_key_not_found")
    return key


@router.post("/relays/{relay_id}/keys/{key_id}/retire", response_model=RelayOut)
async def retire_relay_key(
    relay_id: str,
    key_id: str,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    key = await _relay_key(db, relay_id, key_id)
    if key.status != "active":
        raise _conflict("relay_key_not_active")
    key.status = "retired"
    key.retired_at = _now()
    await audit.record(
        db,
        action="relay.key_retired",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={"relay_id": relay_id, "key_id": key_id},
        **_request_context(request),
    )
    await db.commit()
    return await _relay_out(db, await db.get(Relay, relay_id))


@router.post("/relays/{relay_id}/keys/{key_id}/revoke", response_model=RelayOut)
async def revoke_relay_key(
    relay_id: str,
    key_id: str,
    body: KeyRevoke,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    key = await _relay_key(db, relay_id, key_id)
    if key.status == "revoked":
        raise _conflict("relay_key_already_revoked")
    key.status = "revoked"
    key.revoked_at = _now()
    await audit.record(
        db,
        action="relay.key_revoked",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={"relay_id": relay_id, "key_id": key_id, "reason": body.reason},
        **_request_context(request),
    )
    await db.commit()
    return await _relay_out(db, await db.get(Relay, relay_id))


# --------------------------------------------------------------------------- #
# Tenant residency policy
# --------------------------------------------------------------------------- #
async def _policy_out(db: AsyncSession, client_id: str) -> RegionPolicyOut:
    policy = await db.get(TenantRegionPolicy, client_id)
    region = await db.get(RelayRegion, policy.region_id) if policy is not None else None
    active_relays = 0
    if region is not None:
        active_relays = await db.scalar(
            select(func.count())
            .select_from(Relay)
            .where(Relay.region_id == region.id, Relay.status == "active")
        )
    tenant_agents = (
        await db.execute(
            select(Agent.supported_capabilities)
            .join(Site, Site.id == Agent.site_id)
            .where(Site.client_id == client_id)
        )
    ).scalars()
    legacy = sum(
        1 for caps in tenant_agents if relays.RELAY_ROUTING_CAPABILITY not in (caps or [])
    )
    return RegionPolicyOut(
        client_id=client_id,
        region_id=region.id if region is not None else None,
        region_code=region.code if region is not None else None,
        mode=policy.mode if policy is not None else "none",
        home_region_active_relays=active_relays or 0,
        legacy_direct_agents=legacy,
        updated_at=policy.updated_at if policy is not None else None,
        set_by=policy.set_by if policy is not None else None,
    )


@tenant_router.get("/clients/{client_id}/region-policy", response_model=RegionPolicyOut)
async def get_region_policy(
    client_id: str,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    await assert_client_visible(operator, client_id, db, detail="Client not found")
    return await _policy_out(db, client_id)


@router.put("/clients/{client_id}/region-policy", response_model=RegionPolicyOut)
async def set_region_policy(
    client_id: str,
    body: RegionPolicyIn,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Client, client_id) is None:
        raise _not_found("client_not_found")
    if body.mode not in relays.RESIDENCY_MODES:
        raise _invalid("residency_mode_invalid")
    region = await db.get(RelayRegion, body.region_id)
    if region is None:
        raise _not_found("region_not_found")
    if body.mode == "strict":
        # A strict policy with nowhere to route would strand every capable
        # agent of the tenant the moment it took effect.
        active = await db.scalar(
            select(func.count())
            .select_from(Relay)
            .where(Relay.region_id == region.id, Relay.status == "active")
        )
        if region.status != "active" or not active:
            raise _conflict("region_has_no_active_relay")
    policy = await db.get(TenantRegionPolicy, client_id)
    previous_mode = policy.mode if policy is not None else "none"
    previous_region = policy.region_id if policy is not None else ""
    if policy is None:
        policy = TenantRegionPolicy(client_id=client_id)
        db.add(policy)
    policy.region_id = region.id
    policy.mode = body.mode
    policy.set_by = operator.email
    policy.updated_at = _now()
    await audit.record(
        db,
        action="tenant.region_policy_set",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={
            "client_id": client_id,
            "region_id": region.id,
            "mode": body.mode,
            "previous_region_id": previous_region,
            "previous_mode": previous_mode,
        },
        **_request_context(request),
    )
    await db.commit()
    return await _policy_out(db, client_id)


@router.delete("/clients/{client_id}/region-policy", response_model=RegionPolicyOut)
async def clear_region_policy(
    client_id: str,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(TenantRegionPolicy, client_id)
    if policy is None:
        raise _not_found("region_policy_not_found")
    previous_mode, previous_region = policy.mode, policy.region_id
    await db.delete(policy)
    await audit.record(
        db,
        action="tenant.region_policy_set",
        actor=operator.email,
        actor_user_id=operator.id,
        detail={
            "client_id": client_id,
            "region_id": "",
            "mode": "none",
            "previous_region_id": previous_region,
            "previous_mode": previous_mode,
        },
        **_request_context(request),
    )
    await db.commit()
    return await _policy_out(db, client_id)
