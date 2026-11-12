# SPDX-License-Identifier: AGPL-3.0-only
"""Public API version discovery and API token lifecycle (issue #72).

Token *management* is deliberately not part of the public surface: minting
requires an interactive, step-up-fresh operator session, and no API token can
list, create, or revoke tokens (``require_interactive_operator`` /
``require_step_up`` refuse token principals). A leaked token therefore cannot
entrench itself by minting successors.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_operator,
    require_interactive_operator,
    require_step_up,
)
from app.core import api_tokens, audit, public_api
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.models.models import ApiToken, Client, Operator, OperatorClientMembership
from app.schemas.public_api import (
    ApiTokenCreate,
    ApiTokenCreatedOut,
    ApiTokenListOut,
    ApiTokenOut,
    ApiVersionOut,
)

router = APIRouter(tags=["public-api"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _evidence(request: Request, actor: Operator) -> dict:
    return {
        "actor": actor.email,
        "actor_user_id": actor.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def _out(token: ApiToken, now: datetime) -> dict:
    return {
        "id": token.id,
        "name": token.name,
        "prefix": token.prefix,
        "operator_id": token.operator_id,
        "client_id": token.client_id,
        "role_ceiling": token.role_ceiling,
        "client_role_ceiling": token.client_role_ceiling,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "last_used_at": token.last_used_at,
        "revoked_at": token.revoked_at,
        "active": api_tokens.is_active(token, now),
    }


@router.get("/api-version", response_model=ApiVersionOut)
async def api_version(_operator: Operator = Depends(get_current_operator)):
    """The public API version, revision, webhook versions, and deprecations."""
    return public_api.version_document()


@router.post(
    "/api-tokens",
    response_model=ApiTokenCreatedOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_token(
    body: ApiTokenCreate,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Mint a tenant-scoped API token for the caller. Shown once.

    The token is bound to one client the caller can see, and its ceilings may
    not exceed the caller's own global role or that client's membership role.
    Step-up gated: a credential that outlives the session is exactly what a
    stolen session would mint to persist.
    """
    now = _now()
    client = await db.get(Client, body.client_id)
    membership = (
        await db.execute(
            select(OperatorClientMembership).where(
                OperatorClientMembership.operator_id == operator.id,
                OperatorClientMembership.client_id == body.client_id,
            )
        )
    ).scalar_one_or_none()
    if client is None or (membership is None and not operator.is_platform_admin):
        raise HTTPException(status_code=404, detail="Client not found")
    if api_tokens.role_exceeds(body.role_ceiling, operator.role):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "api_token_role_ceiling_exceeds_role",
                "message": "role_ceiling may not exceed your own role.",
            },
        )
    if membership is not None and api_tokens.client_role_exceeds(
        body.client_role_ceiling, membership.role
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "api_token_client_role_ceiling_exceeds_membership",
                "message": "client_role_ceiling may not exceed your role on this client.",
            },
        )
    days = body.expires_in_days or settings.api_token_default_ttl_days
    if days > settings.api_token_max_ttl_days:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "api_token_ttl_exceeds_maximum",
                "message": f"expires_in_days may not exceed {settings.api_token_max_ttl_days}.",
            },
        )
    active = (
        await db.execute(
            select(func.count())
            .select_from(ApiToken)
            .where(
                ApiToken.operator_id == operator.id,
                ApiToken.revoked_at.is_(None),
                ApiToken.expires_at > now,
            )
        )
    ).scalar_one()
    if active >= settings.api_token_max_active_per_operator:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "api_token_limit_reached",
                "message": "Revoke an existing API token before creating another.",
            },
        )

    minted = api_tokens.mint(
        operator=operator,
        client_id=body.client_id,
        name=body.name,
        role_ceiling=body.role_ceiling,
        client_role_ceiling=body.client_role_ceiling,
        expires_at=now + timedelta(days=days),
        now=now,
    )
    db.add(minted.token)
    await db.flush()
    await audit.record(
        db,
        action="api_token.created",
        organization_id=body.client_id,
        detail={
            "token_id": minted.token.id,
            "prefix": minted.token.prefix,
            "operator_id": operator.id,
            "client_id": body.client_id,
            "role_ceiling": minted.token.role_ceiling,
            "client_role_ceiling": minted.token.client_role_ceiling,
            "expires_at": minted.token.expires_at.isoformat(),
            "name": body.name,
        },
        **_evidence(request, operator),
    )
    return {**_out(minted.token, now), "token": minted.plaintext}


@router.get("/api-tokens", response_model=ApiTokenListOut)
async def list_api_tokens(
    operator_id: str | None = Query(default=None, max_length=36),
    operator: Operator = Depends(require_interactive_operator),
    db: AsyncSession = Depends(get_db),
):
    """The caller's tokens; a platform admin may list any operator's."""
    target = operator_id or operator.id
    if target != operator.id and not operator.is_platform_admin:
        raise HTTPException(status_code=403, detail="Requires platform administrator")
    tokens = (
        await db.execute(
            select(ApiToken)
            .where(ApiToken.operator_id == target)
            .order_by(ApiToken.created_at.desc(), ApiToken.id)
        )
    ).scalars().all()
    now = _now()
    return {"items": [_out(token, now) for token in tokens]}


@router.delete("/api-tokens/{token_id}", response_model=ApiTokenOut)
async def revoke_api_token(
    token_id: str,
    request: Request,
    operator: Operator = Depends(require_interactive_operator),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a token. Owner or platform admin; idempotent.

    Not step-up gated: revoking only ever removes access, and it must stay
    one click away for someone who just noticed a leak.
    """
    token = (
        await db.execute(select(ApiToken).where(ApiToken.id == token_id).with_for_update())
    ).scalar_one_or_none()
    if token is None or (
        token.operator_id != operator.id and not operator.is_platform_admin
    ):
        raise HTTPException(status_code=404, detail="API token not found")
    now = _now()
    if token.revoked_at is None:
        token.revoked_at = now
        token.revoked_by = operator.email
        await db.flush()
        await audit.record(
            db,
            action="api_token.revoked",
            organization_id=token.client_id,
            detail={
                "token_id": token.id,
                "prefix": token.prefix,
                "operator_id": token.operator_id,
                "client_id": token.client_id,
                "revoked_by_operator_id": operator.id,
            },
            **_evidence(request, operator),
        )
    return _out(token, now)
