# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant retention policy API (issue #88).

Reading a tenant's effective policy needs the global ``readonly`` role and
visibility of the tenant. Changing it needs the global ``admin`` role,
``client_admin`` on that tenant (a platform admin passes both), and a fresh
step-up, because shortening retention destroys evidence. A tenant the caller
cannot see answers 404, exactly like one that does not exist.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_operator, require_role, require_step_up
from app.core import evidence_vault, retention_policy
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.tenant_scope import assert_client_action, assert_client_visible
from app.models.models import Client, ClientRole, Operator, OperatorRole

router = APIRouter(tags=["retention"])

_NOT_FOUND = {"code": "client_not_found"}


class RetentionPolicyIn(BaseModel):
    """Full replacement of a tenant's overrides; an omitted or null category
    inherits the platform default."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    telemetry_days: int | None = None
    command_output_days: int | None = None
    command_record_days: int | None = None
    inventory_history_per_section: int | None = None
    alert_days: int | None = None
    notification_days: int | None = None
    evidence_default_days: int | None = None


class RetentionPolicyClear(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


async def _view(db: AsyncSession, client_id: str) -> dict:
    policy = await retention_policy.effective_policy(db, client_id)
    return {
        "client_id": client_id,
        "version": policy.version,
        "set_by": policy.set_by,
        "updated_at": _iso(policy.updated_at),
        # A tenant-wide legal hold suspends every purge for the tenant.
        "pruning_suspended": await evidence_vault.tenant_hold_active(db, client_id),
        "categories": {
            category.name: {
                "unit": category.unit,
                "effective": value.value,
                "source": value.source,
                "override": value.override,
                "platform_default": value.platform_default,
                "minimum": value.minimum,
                "maximum": value.maximum,
            }
            for category in retention_policy.CATEGORIES
            for value in (policy.values[category.name],)
        },
    }


async def _require_client(db: AsyncSession, client_id: str) -> None:
    # A platform admin passes the tenant asserts for any id; an id that names
    # no client must still be a 404, not an empty default policy.
    if await db.get(Client, client_id) is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)


def _raise(exc: retention_policy.RetentionPolicyError) -> None:
    detail: dict = {"code": exc.code}
    if exc.category:
        detail["category"] = exc.category
    raise HTTPException(status_code=exc.status_code, detail=detail) from exc


def _meta(request: Request) -> dict:
    return {
        "source_ip": client_ip(request),
        "user_agent": (request.headers.get("user-agent") or "")[:500] or None,
    }


@router.get(
    "/clients/{client_id}/retention-policy",
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)
async def get_retention_policy(
    client_id: str,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    await assert_client_visible(operator, client_id, db, detail=_NOT_FOUND)
    await _require_client(db, client_id)
    return await _view(db, client_id)


@router.put(
    "/clients/{client_id}/retention-policy",
    dependencies=[Depends(require_role(OperatorRole.admin))],
)
async def set_retention_policy(
    client_id: str,
    body: RetentionPolicyIn,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    await assert_client_action(
        operator, client_id, db, minimum=ClientRole.client_admin, detail=_NOT_FOUND
    )
    await _require_client(db, client_id)
    values = body.model_dump(exclude={"expected_version"})
    try:
        await retention_policy.set_policy(
            db,
            client_id=client_id,
            values=values,
            expected_version=body.expected_version,
            actor_email=operator.email,
            actor_user_id=operator.id,
            request_meta=_meta(request),
        )
    except retention_policy.RetentionPolicyError as exc:
        _raise(exc)
    await db.commit()
    return await _view(db, client_id)


@router.delete(
    "/clients/{client_id}/retention-policy",
    dependencies=[Depends(require_role(OperatorRole.admin))],
)
async def clear_retention_policy(
    client_id: str,
    body: RetentionPolicyClear,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    await assert_client_action(
        operator, client_id, db, minimum=ClientRole.client_admin, detail=_NOT_FOUND
    )
    try:
        await retention_policy.clear_policy(
            db,
            client_id=client_id,
            expected_version=body.expected_version,
            actor_email=operator.email,
            actor_user_id=operator.id,
            request_meta=_meta(request),
        )
    except retention_policy.RetentionPolicyError as exc:
        _raise(exc)
    await db.commit()
    return await _view(db, client_id)
