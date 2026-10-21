# SPDX-License-Identifier: AGPL-3.0-only
"""Justified emergency override endpoints (issue #65).

One resource, ``/emergency-overrides``: the exception records themselves. The
decision rules live in :mod:`app.core.emergency_overrides`; this module
resolves identities and tenancy, sends the mandatory notification, records
evidence, and maps refusal codes to status codes. Every refusal commits its
audit event before raising, mirroring the approval and dispatch handlers: a
denial is evidence and must survive the rolled-back request transaction.

Activation is behind step-up authentication. The gate is vacuous for an
operator with no second factor (the compatibility contract documented on
``require_step_up``), and real the moment they enrol one: minting an override
is exactly the kind of action a stolen session must not be able to take alone.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role, require_step_up
from app.core import approvals as approvals_core
from app.core import audit, tenant_scope
from app.core import emergency_overrides as overrides_core
from app.core.clientip import client_ip
from app.core.command_envelope import validate_command_payload
from app.core.config import Settings, settings
from app.core.database import get_db
from app.core.email_notifications import (
    OutboundEmail,
    ProviderError,
    build_transactional_provider,
    configured_recipients,
)
from app.models.models import (
    Agent,
    ClientRole,
    Command,
    EmergencyOverride,
    EmergencyOverrideStatus,
    Operator,
    OperatorRole,
)
from app.schemas.emergency_overrides import (
    EmergencyOverrideActivate,
    EmergencyOverrideDetail,
    EmergencyOverrideOut,
    EmergencyOverrideReview,
    EmergencyOverrideRevoke,
)
from app.schemas.schemas import MAX_COMMAND_PAYLOAD_BYTES

router = APIRouter(
    tags=["emergency-overrides"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)

MAX_PAGE_SIZE = 200


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent", "")[:500] or None


# --------------------------------------------------------------------------- #
# Notification
# --------------------------------------------------------------------------- #
def render_notification(
    override: EmergencyOverride, agent: Agent, config: Settings = settings
) -> tuple[str, str, str]:
    """Subject, text body, and HTML body for the activation notice.

    The recipients are the configured alert recipients: the people who already
    get told when an endpoint is unhealthy, and who should therefore also be
    told when someone bypassed the second reviewer. The message must let a
    reader decide *without logging in* whether to escalate: who did it, to
    which endpoint, what kind of command, when it expires, and that it still
    needs a review.
    """
    hostname = agent.hostname or agent.id
    expires = override.expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subject = (
        f"[NodeLink] Emergency override by {override.activated_by_email} "
        f"on {hostname} ({override.kind.value})"
    )
    lines = [
        f"{override.activated_by_email} activated an emergency override and may run a "
        f"'{override.kind.value}' command on {hostname} without a second approver.",
        "",
        f"Endpoint: {hostname} ({agent.id})",
        f"Command kind: {override.kind.value}",
        f"Expires: {expires}",
        f"Override id: {override.id}",
        "",
        "Justification given:",
        override.justification,
        "",
        "This override is single-use and still needs a post-hoc review by a tenant or "
        "platform administrator who is not the activator. If you did not expect this, "
        "revoke it from the Emergency overrides page and investigate.",
    ]
    text_body = "\n".join(lines) + "\n"
    html_body = (
        f"<p><strong>{html.escape(override.activated_by_email)}</strong> activated an "
        f"emergency override and may run a <code>{html.escape(override.kind.value)}</code> "
        f"command on <strong>{html.escape(hostname)}</strong> without a second approver.</p>"
        "<ul>"
        f"<li>Endpoint: {html.escape(hostname)} ({html.escape(agent.id)})</li>"
        f"<li>Command kind: {html.escape(override.kind.value)}</li>"
        f"<li>Expires: {html.escape(expires)}</li>"
        f"<li>Override id: {html.escape(override.id)}</li>"
        "</ul>"
        f"<p>Justification given:</p><blockquote>{html.escape(override.justification)}</blockquote>"
        "<p>This override is single-use and still needs a post-hoc review by a tenant or "
        "platform administrator who is not the activator. If you did not expect this, "
        "revoke it from the Emergency overrides page and investigate.</p>"
    )
    return subject, text_body, html_body


async def _notify(
    db: AsyncSession,
    override: EmergencyOverride,
    agent: Agent,
    *,
    actor: Operator,
    config: Settings = settings,
    provider=None,
) -> None:
    """Send the activation notice now and record the outcome on the row.

    A failure never blocks the override -- the override exists precisely for
    when things are already going wrong -- but it is never silent either: the
    row carries a coded reason, the audit chain carries the same, and the
    review queue flags the override as unnotified.
    """
    recipients = configured_recipients(config)
    if not recipients:
        override.notification_error = overrides_core.NOTIFICATION_NO_RECIPIENTS
        await _audit_notification(db, override, actor=actor, error=override.notification_error)
        return
    selected = provider if provider is not None else build_transactional_provider(config)
    if selected is None:
        override.notification_error = overrides_core.NOTIFICATION_PROVIDER_UNAVAILABLE
        await _audit_notification(db, override, actor=actor, error=override.notification_error)
        return

    subject, text_body, html_body = render_notification(override, agent, config)
    accepted = 0
    last_error: str | None = None
    for recipient in recipients:
        message = OutboundEmail(
            namespace="emergency-override",
            key=f"{override.id}/{recipient}",
            recipient=recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )
        try:
            await selected.send_message(message)
            accepted += 1
        except ProviderError as exc:
            last_error = exc.code
    override.notified_recipient_count = accepted
    if accepted:
        override.notified_at = _now()
        await _audit_notification(db, override, actor=actor, error=None)
    else:
        override.notification_error = (last_error or "provider_error")[:64]
        await _audit_notification(db, override, actor=actor, error=override.notification_error)


async def _audit_notification(
    db: AsyncSession, override: EmergencyOverride, *, actor: Operator, error: str | None
) -> None:
    # Two literal actions rather than one computed name: the audit producer
    # inventory is checked statically, and a computed action is invisible to it.
    if error is None:
        await audit.record(
            db,
            action="emergency_override.notified",
            actor=actor.email,
            actor_user_id=actor.id,
            agent_id=override.agent_id,
            organization_id=override.client_id,
            detail=overrides_core.audit_detail(
                override, recipient_count=override.notified_recipient_count
            ),
        )
        return
    await audit.record(
        db,
        action="emergency_override.notification_failed",
        actor=actor.email,
        actor_user_id=actor.id,
        agent_id=override.agent_id,
        organization_id=override.client_id,
        detail=overrides_core.audit_detail(
            override, recipient_count=override.notified_recipient_count, error=error
        ),
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _load_override(
    override_id: str, operator: Operator, db: AsyncSession
) -> EmergencyOverride:
    """Load an override the operator may see, expiring it lazily if due.

    Cross-tenant and non-existent are the same 404. Expiry is applied here so
    no read or action can observe an override as live past its deadline.
    """
    override = await db.get(EmergencyOverride, override_id)
    if override is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "emergency_override_not_found"},
        )
    await tenant_scope.assert_client_visible(
        operator, override.client_id, db, detail={"code": "emergency_override_not_found"}
    )
    if overrides_core.expire_if_due(override, _now()):
        await audit.record(
            db,
            action="emergency_override.expired",
            actor="system",
            agent_id=override.agent_id,
            organization_id=override.client_id,
            detail=overrides_core.audit_detail(override),
        )
        await db.commit()
    return override


def _out(override: EmergencyOverride) -> EmergencyOverrideOut:
    return EmergencyOverrideOut.model_validate(override)


async def _detail(override: EmergencyOverride, db: AsyncSession) -> EmergencyOverrideDetail:
    consumed_command_id = (
        await db.execute(
            select(Command.id)
            .where(Command.emergency_override_id == override.id)
            .order_by(Command.created_at)
            .limit(1)
        )
    ).scalars().first()
    return EmergencyOverrideDetail(
        **_out(override).model_dump(),
        payload=override.payload or {},
        payload_keys=sorted(override.payload or {}),
        revoke_reason=override.revoke_reason,
        review_note=override.review_note,
        consumed_command_id=consumed_command_id,
    )


async def _is_tenant_admin(operator: Operator, client_id: str | None, db: AsyncSession) -> bool:
    if operator.is_platform_admin:
        return True
    if client_id is None:
        return False
    membership = await tenant_scope.resolve_membership(operator, client_id, db)
    return membership is not None and tenant_scope.client_role_permits(
        membership.role, ClientRole.client_admin
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post(
    "/emergency-overrides",
    response_model=EmergencyOverrideDetail,
    status_code=status.HTTP_201_CREATED,
)
async def activate_emergency_override(
    body: EmergencyOverrideActivate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Take sole responsibility for one governed command.

    Refused unless a policy governs the kind for this endpoint *and* allows
    overrides, the caller is a tenant or platform admin, and the caller could
    have run the command themselves. Each refusal is audited with its code.
    """
    agent = await db.get(Agent, body.agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail={"code": "agent_not_found"}
        )
    await tenant_scope.assert_agent_visible(
        operator, agent, db, detail={"code": "agent_not_found"}
    )

    try:
        payload = validate_command_payload(body.payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "command_payload_invalid", "reason": str(exc)},
        ) from exc
    if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > MAX_COMMAND_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "command_payload_too_large"},
        )

    policy = await approvals_core.resolve_policy(db, agent, body.kind)
    eligibility = await overrides_core.activator_eligibility(
        db, operator, agent, body.kind, policy=policy
    )
    if not eligibility.eligible:
        await audit.record(
            db,
            action="emergency_override.denied",
            actor=operator.email,
            actor_user_id=operator.id,
            agent_id=agent.id,
            source_ip=client_ip(request),
            detail={
                "kind": body.kind.value,
                "agent_id": agent.id,
                "policy_id": policy.id if policy is not None else None,
                "reason": eligibility.reason,
            },
        )
        await db.commit()
        http_status = (
            status.HTTP_409_CONFLICT
            if eligibility.reason
            in ("emergency_override_not_required", "emergency_override_not_permitted")
            else status.HTTP_403_FORBIDDEN
        )
        raise HTTPException(status_code=http_status, detail={"code": eligibility.reason})
    assert policy is not None  # eligibility guarantees it

    client_id = await tenant_scope.agent_client_id(agent, db)
    open_count = (
        await db.execute(
            select(func.count())
            .select_from(EmergencyOverride)
            .where(
                EmergencyOverride.activated_by_operator_id == operator.id,
                EmergencyOverride.client_id == client_id,
                EmergencyOverride.status == EmergencyOverrideStatus.active,
                EmergencyOverride.expires_at > _now(),
            )
        )
    ).scalar_one()
    if open_count >= overrides_core.MAX_OPEN_OVERRIDES_PER_OPERATOR:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "emergency_override_limit_reached",
                "outstanding": open_count,
                "limit": overrides_core.MAX_OPEN_OVERRIDES_PER_OPERATOR,
            },
        )

    now = _now()
    override = EmergencyOverride(
        agent_id=agent.id,
        client_id=client_id,
        site_id=agent.site_id,
        kind=body.kind,
        payload=payload,
        payload_sha256=approvals_core.binding_digest(agent.id, body.kind, payload),
        policy_id=policy.id,
        required_approvals=policy.required_approvals,
        activated_by_operator_id=operator.id,
        activated_by_email=operator.email,
        justification=body.justification,
        status=EmergencyOverrideStatus.active,
        created_at=now,
        expires_at=overrides_core.override_expiry(body.ttl_seconds, now),
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
    )
    db.add(override)
    await db.flush()

    await audit.record(
        db,
        action="emergency_override.activated",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=agent.id,
        organization_id=client_id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail=overrides_core.audit_detail(
            override,
            justification=override.justification,
            expires_at=override.expires_at.isoformat(),
        ),
    )
    # The row and its activation event are committed before the notification
    # is attempted, so a provider that hangs or raises cannot lose the record
    # of the override itself.
    await db.commit()

    await _notify(db, override, agent, actor=operator)
    await db.commit()
    return await _detail(override, db)


@router.get("/emergency-overrides", response_model=list[EmergencyOverrideOut])
async def list_emergency_overrides(
    unreviewed_only: bool = Query(default=False),
    override_status: EmergencyOverrideStatus | None = Query(default=None, alias="status"),
    agent_id: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """The exception log and review queue, newest first, scoped to visible tenants."""
    stmt = (
        select(EmergencyOverride)
        .where(tenant_scope.client_id_filter(operator, EmergencyOverride.client_id))
        .order_by(EmergencyOverride.created_at.desc())
        .limit(limit)
    )
    if unreviewed_only:
        stmt = stmt.where(EmergencyOverride.reviewed_at.is_(None))
    if agent_id is not None:
        stmt = stmt.where(EmergencyOverride.agent_id == agent_id)
    if override_status is not None:
        stmt = stmt.where(EmergencyOverride.status == override_status)

    rows = list((await db.execute(stmt)).scalars().all())
    now = _now()
    changed = False
    for override in rows:
        if overrides_core.expire_if_due(override, now):
            changed = True
            await audit.record(
                db,
                action="emergency_override.expired",
                actor="system",
                agent_id=override.agent_id,
                organization_id=override.client_id,
                detail=overrides_core.audit_detail(override),
            )
    if changed:
        await db.commit()
    if override_status is not None:
        rows = [row for row in rows if row.status == override_status]
    return [_out(row) for row in rows]


@router.get("/emergency-overrides/{override_id}", response_model=EmergencyOverrideDetail)
async def get_emergency_override(
    override_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Everything a reviewer needs to judge one override, including the payload."""
    override = await _load_override(override_id, operator, db)
    return await _detail(override, db)


@router.post(
    "/emergency-overrides/{override_id}/revoke", response_model=EmergencyOverrideDetail
)
async def revoke_emergency_override(
    override_id: str,
    body: EmergencyOverrideRevoke,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Withdraw an unspent override. The activator or a tenant admin may."""
    override = await _load_override(override_id, operator, db)
    if operator.id != override.activated_by_operator_id and not await _is_tenant_admin(
        operator, override.client_id, db
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "emergency_override_revoke_not_permitted"},
        )
    if override.status != EmergencyOverrideStatus.active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "emergency_override_not_active"},
        )
    now = _now()
    override.status = EmergencyOverrideStatus.revoked
    override.revoked_at = now
    override.revoked_by_email = operator.email
    override.revoke_reason = body.reason
    await audit.record(
        db,
        action="emergency_override.revoked",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=override.agent_id,
        organization_id=override.client_id,
        source_ip=client_ip(request),
        detail=overrides_core.audit_detail(
            override,
            reason=body.reason,
            revoked_by_activator=operator.id == override.activated_by_operator_id,
        ),
    )
    await db.commit()
    return await _detail(override, db)


@router.post(
    "/emergency-overrides/{override_id}/review", response_model=EmergencyOverrideDetail
)
async def review_emergency_override(
    override_id: str,
    body: EmergencyOverrideReview,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Sign off one override as investigated.

    Only a tenant or platform admin may, and never the activator: the review
    is the second person the override skipped, arriving after the fact. Not
    step-up gated, for the same reason break-glass review is not -- it grants
    nothing, and making the accountable act harder than the privileged one
    would only discourage it.
    """
    override = await _load_override(override_id, operator, db)
    if operator.id == override.activated_by_operator_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "emergency_override_self_review_not_permitted"},
        )
    if not await _is_tenant_admin(operator, override.client_id, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "emergency_override_review_not_permitted"},
        )
    if override.reviewed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "emergency_override_already_reviewed"},
        )
    override.reviewed_at = _now()
    override.reviewed_by_email = operator.email
    override.review_note = body.note
    await audit.record(
        db,
        action="emergency_override.reviewed",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=override.agent_id,
        organization_id=override.client_id,
        source_ip=client_ip(request),
        detail=overrides_core.audit_detail(override, note=body.note),
    )
    await db.commit()
    return await _detail(override, db)
