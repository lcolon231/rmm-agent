# SPDX-License-Identifier: AGPL-3.0-only
"""Approval workflows and two-person authorization endpoints (issue #64).

Two resources, deliberately separated by who may touch them:

* ``/approval-policies`` — where approval is required and how many people it
  takes. Administrative configuration, so it is admin-only and, for a scoped
  policy, additionally gated on ``client_admin`` for the tenant it targets.
* ``/approval-requests`` — the proposed sensitive commands themselves and the
  verdicts on them. Visible to anyone who can see the tenant; actionable only
  by identities that could have run the command.

The decision rules all live in :mod:`app.core.approvals`; this module resolves
identities and tenancy, records evidence, and maps refusal codes to status
codes. Every refusal commits its audit event before raising, mirroring the
dispatch handler: a denial is evidence and must survive the rolled-back request
transaction.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_role
from app.core import approvals as approvals_core
from app.core import audit, tenant_scope
from app.core.clientip import client_ip
from app.core.command_envelope import validate_command_payload
from app.core.database import get_db
from app.core.script_authorization import authorize_command
from app.models.models import (
    Agent,
    ApprovalDecision,
    ApprovalDecisionKind,
    ApprovalPolicy,
    ApprovalRequest,
    ApprovalRequestStatus,
    Client,
    ClientRole,
    Command,
    MonitoringScope,
    Operator,
    OperatorRole,
    Site,
)
from app.schemas.approvals import (
    ApprovalDecisionOut,
    ApprovalDecisionCreate,
    ApprovalPolicyCreate,
    ApprovalPolicyOut,
    ApprovalPolicyUpdate,
    ApprovalRequestCreate,
    ApprovalRequestDetail,
    ApprovalRequestOut,
)
from app.schemas.schemas import MAX_COMMAND_PAYLOAD_BYTES

router = APIRouter(
    tags=["approvals"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)

# Page size ceiling for the reviewer queue. The queue is meant to be worked,
# not exported; evidence extraction goes through the audit APIs.
MAX_PAGE_SIZE = 200

# Outstanding requests one operator may hold per tenant. Bounds the work a
# single account can pile onto other people's review queues.
MAX_OPEN_REQUESTS_PER_OPERATOR = 50


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
async def _assert_policy_admin(
    operator: Operator, scope: MonitoringScope, scope_id: str | None, db: AsyncSession
) -> None:
    """Authorize administering a policy at ``scope``/``scope_id``.

    A global policy governs every tenant, so only a platform admin may write
    one. A scoped policy is administered by a ``client_admin`` on the tenant it
    targets, resolved through the site or agent for the narrower scopes. An
    unresolvable target is a 404 rather than a 400: it must not confirm the
    existence of an id in another tenant.
    """
    if scope == MonitoringScope.global_:
        if not operator.is_platform_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "approval_policy_global_requires_platform_admin"},
            )
        return

    client_id: str | None = None
    if scope == MonitoringScope.client:
        client_id = scope_id if await db.get(Client, scope_id) is not None else None
    elif scope == MonitoringScope.site:
        site = await db.get(Site, scope_id)
        client_id = site.client_id if site is not None else None
    elif scope == MonitoringScope.agent:
        agent = await db.get(Agent, scope_id)
        client_id = (
            await tenant_scope.agent_client_id(agent, db) if agent is not None else None
        )
    await tenant_scope.assert_client_action(
        operator,
        client_id,
        db,
        minimum=ClientRole.client_admin,
        detail={"code": "approval_policy_scope_target_not_found"},
    )


def _policy_out(policy: ApprovalPolicy) -> ApprovalPolicyOut:
    return ApprovalPolicyOut.model_validate(policy)


async def _visible_policies(operator: Operator, db: AsyncSession) -> list[ApprovalPolicy]:
    """Every policy whose scope target the operator can see.

    Global policies are visible to everyone: they govern the operator's own
    dispatches, so hiding them would leave a refusal unexplainable.
    """
    policies = (
        (await db.execute(select(ApprovalPolicy).order_by(ApprovalPolicy.created_at)))
        .scalars()
        .all()
    )
    if operator.is_platform_admin:
        return list(policies)

    visible: list[ApprovalPolicy] = []
    for policy in policies:
        if policy.scope == MonitoringScope.global_:
            visible.append(policy)
            continue
        client_id: str | None = None
        if policy.scope == MonitoringScope.client:
            client_id = policy.scope_id
        elif policy.scope == MonitoringScope.site:
            site = await db.get(Site, policy.scope_id)
            client_id = site.client_id if site is not None else None
        elif policy.scope == MonitoringScope.agent:
            agent = await db.get(Agent, policy.scope_id)
            client_id = (
                await tenant_scope.agent_client_id(agent, db)
                if agent is not None
                else None
            )
        if client_id is not None and await tenant_scope.is_client_visible(
            operator, client_id, db
        ):
            visible.append(policy)
    return visible


@router.get("/approval-policies", response_model=list[ApprovalPolicyOut])
async def list_approval_policies(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """The approval policies in force for tenants this operator can see."""
    return [_policy_out(policy) for policy in await _visible_policies(operator, db)]


@router.post(
    "/approval-policies",
    response_model=ApprovalPolicyOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_approval_policy(
    body: ApprovalPolicyCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Put a set of command kinds behind approval for one scope."""
    await _assert_policy_admin(operator, body.scope, body.scope_id, db)

    policy = ApprovalPolicy(
        name=body.name,
        scope=body.scope,
        scope_id=body.scope_id,
        command_kinds=[kind.value for kind in body.command_kinds],
        required_approvals=body.required_approvals,
        request_ttl_seconds=body.request_ttl_seconds,
        enabled=body.enabled,
        created_by=operator.email,
    )
    db.add(policy)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "approval_policy_name_conflict"},
        ) from exc

    await audit.record(
        db,
        action="approval_policy.created",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        detail={
            "policy_id": policy.id,
            "name": policy.name,
            "scope": policy.scope.value,
            "scope_id": policy.scope_id,
            "command_kinds": sorted(policy.command_kinds),
            "required_approvals": policy.required_approvals,
            "request_ttl_seconds": policy.request_ttl_seconds,
            "enabled": policy.enabled,
        },
    )
    await db.commit()
    await db.refresh(policy)
    return _policy_out(policy)


@router.patch("/approval-policies/{policy_id}", response_model=ApprovalPolicyOut)
async def update_approval_policy(
    policy_id: str,
    body: ApprovalPolicyUpdate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Change a policy's terms. Requests already in flight keep their own."""
    policy = await db.get(ApprovalPolicy, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "approval_policy_not_found"},
        )
    await _assert_policy_admin(operator, policy.scope, policy.scope_id, db)

    previous = {
        "command_kinds": sorted(policy.command_kinds or []),
        "required_approvals": policy.required_approvals,
        "request_ttl_seconds": policy.request_ttl_seconds,
        "enabled": policy.enabled,
    }
    if body.command_kinds is not None:
        policy.command_kinds = [kind.value for kind in body.command_kinds]
    if body.required_approvals is not None:
        policy.required_approvals = body.required_approvals
    if body.request_ttl_seconds is not None:
        policy.request_ttl_seconds = body.request_ttl_seconds
    if body.enabled is not None:
        policy.enabled = body.enabled
    policy.updated_at = _now()
    policy.updated_by = operator.email

    await audit.record(
        db,
        action="approval_policy.updated",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        detail={
            "policy_id": policy.id,
            "name": policy.name,
            "scope": policy.scope.value,
            "scope_id": policy.scope_id,
            "previous_command_kinds": previous["command_kinds"],
            "command_kinds": sorted(policy.command_kinds or []),
            "previous_required_approvals": previous["required_approvals"],
            "required_approvals": policy.required_approvals,
            "previous_request_ttl_seconds": previous["request_ttl_seconds"],
            "request_ttl_seconds": policy.request_ttl_seconds,
            "previous_enabled": previous["enabled"],
            "enabled": policy.enabled,
        },
    )
    await db.commit()
    await db.refresh(policy)
    return _policy_out(policy)


@router.delete("/approval-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_approval_policy(
    policy_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Remove a policy. Requests raised under it keep their recorded terms."""
    policy = await db.get(ApprovalPolicy, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "approval_policy_not_found"},
        )
    await _assert_policy_admin(operator, policy.scope, policy.scope_id, db)

    await audit.record(
        db,
        action="approval_policy.deleted",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        detail={
            "policy_id": policy.id,
            "name": policy.name,
            "scope": policy.scope.value,
            "scope_id": policy.scope_id,
            "command_kinds": sorted(policy.command_kinds or []),
            "required_approvals": policy.required_approvals,
        },
    )
    await db.delete(policy)
    await db.commit()
    return None


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #
async def _load_request(
    request_id: str, operator: Operator, db: AsyncSession
) -> ApprovalRequest:
    """Load a request the operator may see, expiring it lazily if it is due.

    Cross-tenant and non-existent are the same 404, as everywhere else. Expiry
    is applied here rather than only in a sweeper so no read or action can
    observe a request as live past its deadline.
    """
    approval = (
        await db.execute(
            select(ApprovalRequest)
            .where(ApprovalRequest.id == request_id)
            .options(selectinload(ApprovalRequest.decisions))
        )
    ).scalar_one_or_none()
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "approval_request_not_found"},
        )
    await tenant_scope.assert_client_visible(
        operator,
        approval.client_id,
        db,
        detail={"code": "approval_request_not_found"},
    )
    if approvals_core.expire_if_due(approval, _now()):
        await audit.record(
            db,
            action="approval_request.expired",
            actor="system",
            agent_id=approval.agent_id,
            detail=approvals_core.request_audit_detail(approval),
        )
        # No refresh: sessions are ``expire_on_commit=False``, so the object
        # still carries the transition just committed. Refreshing here would
        # expire the eagerly loaded ``decisions`` collection and turn the next
        # read of it into a lazy load in async context.
        await db.commit()
    return approval


def _request_out(approval: ApprovalRequest) -> ApprovalRequestOut:
    return ApprovalRequestOut(
        id=approval.id,
        agent_id=approval.agent_id,
        client_id=approval.client_id,
        site_id=approval.site_id,
        kind=approval.kind,
        status=approval.status,
        payload_sha256=approval.payload_sha256,
        policy_id=approval.policy_id,
        required_approvals=approval.required_approvals,
        approvals_recorded=approvals_core.approval_count(list(approval.decisions)),
        requested_by_email=approval.requested_by_email,
        requested_by_operator_id=approval.requested_by_operator_id,
        reason=approval.reason,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        decided_at=approval.decided_at,
        consumed_at=approval.consumed_at,
    )


@router.get("/approval-requests", response_model=list[ApprovalRequestOut])
async def list_approval_requests(
    request_status: ApprovalRequestStatus | None = Query(default=None, alias="status"),
    agent_id: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """The reviewer queue, newest first, scoped to visible tenants.

    Requests whose deadline has passed are reported as ``expired`` and are
    persisted as such, so the queue never shows work that can no longer be
    acted on.
    """
    stmt = (
        select(ApprovalRequest)
        .options(selectinload(ApprovalRequest.decisions))
        .order_by(ApprovalRequest.created_at.desc())
        .limit(limit)
    )
    # One path for every principal: the filter is the always-true clause for a
    # platform admin and a membership restriction for everyone else.
    stmt = stmt.where(tenant_scope.client_id_filter(operator, ApprovalRequest.client_id))
    if agent_id is not None:
        stmt = stmt.where(ApprovalRequest.agent_id == agent_id)
    if request_status is not None:
        stmt = stmt.where(ApprovalRequest.status == request_status)

    rows = list((await db.execute(stmt)).scalars().all())
    now = _now()
    changed = False
    for approval in rows:
        if approvals_core.expire_if_due(approval, now):
            changed = True
            await audit.record(
                db,
                action="approval_request.expired",
                actor="system",
                agent_id=approval.agent_id,
                detail=approvals_core.request_audit_detail(approval),
            )
    if changed:
        await db.commit()
    # A status filter is applied before lazy expiry, so drop rows that just
    # left the requested status rather than reporting them under it.
    if request_status is not None:
        rows = [row for row in rows if row.status == request_status]
    return [_request_out(row) for row in rows]


@router.get("/approval-requests/{request_id}", response_model=ApprovalRequestDetail)
async def get_approval_request(
    request_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Everything an approver needs to judge one request, including the payload."""
    approval = await _load_request(request_id, operator, db)
    # ``first``, not ``scalar_one_or_none``: consumption guarantees at most one
    # command per approval, but a read should not become a 500 if that invariant
    # is ever violated by direct data manipulation.
    consumed_command_id = (
        await db.execute(
            select(Command.id)
            .where(Command.approval_request_id == approval.id)
            .order_by(Command.created_at)
            .limit(1)
        )
    ).scalars().first()
    summary = _request_out(approval)
    return ApprovalRequestDetail(
        **summary.model_dump(),
        payload=approval.payload or {},
        payload_keys=sorted(approval.payload or {}),
        decisions=[
            ApprovalDecisionOut.model_validate(decision)
            # Normalize before sorting: SQLite hands back naive timestamps for a
            # reloaded row and aware ones for a row still in the session, which
            # cannot be compared to each other.
            for decision in sorted(
                approval.decisions,
                key=lambda d: approvals_core.as_utc(d.created_at),
            )
        ],
        closed_at=approval.closed_at,
        closed_by_email=approval.closed_by_email,
        closed_reason=approval.closed_reason,
        consumed_command_id=consumed_command_id,
    )


@router.post(
    "/approval-requests",
    response_model=ApprovalRequestDetail,
    status_code=status.HTTP_201_CREATED,
)
async def create_approval_request(
    body: ApprovalRequestCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Raise a request to run a command that policy puts behind approval.

    The requester must already be authorized to run the command themselves.
    Approval adds a second control on top of the existing ones; it is never a
    way to obtain authority the requester does not have, so an operator with no
    script permission for this endpoint is refused here exactly as they would
    be at dispatch.
    """
    agent = await db.get(Agent, body.agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail={"code": "agent_not_found"}
        )
    await tenant_scope.assert_agent_visible(
        operator,
        agent,
        db,
        minimum=ClientRole.client_operator,
        detail={"code": "agent_not_found"},
    )

    decision = authorize_command(operator, agent, body.kind)
    if not decision.allowed:
        await audit.record(
            db,
            action="approval_request.denied",
            actor=operator.email,
            actor_user_id=operator.id,
            agent_id=agent.id,
            source_ip=client_ip(request),
            detail={
                "kind": body.kind.value,
                "agent_id": agent.id,
                "policy": decision.policy,
                "reason": decision.reason,
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "approval_request_not_authorized"},
        )

    # Validate the proposed payload exactly as dispatch would, so an approval
    # can never be raised for something the dispatcher would reject.
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
    if policy is None:
        # Refusing here keeps the two paths honest: a request that no policy
        # requires would produce an approval the dispatcher never asks for, and
        # an audit trail implying a control that was not actually in force.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "approval_not_required"},
        )

    client_id = await tenant_scope.agent_client_id(agent, db)
    open_requests = (
        await db.execute(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(
                ApprovalRequest.requested_by_operator_id == operator.id,
                ApprovalRequest.client_id == client_id,
                ApprovalRequest.status.in_(
                    [ApprovalRequestStatus.pending, ApprovalRequestStatus.approved]
                ),
            )
        )
    ).scalar_one()
    if open_requests >= MAX_OPEN_REQUESTS_PER_OPERATOR:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "approval_request_limit_reached",
                "outstanding": open_requests,
                "limit": MAX_OPEN_REQUESTS_PER_OPERATOR,
            },
        )

    now = _now()
    approval = ApprovalRequest(
        agent_id=agent.id,
        client_id=client_id,
        site_id=agent.site_id,
        kind=body.kind,
        payload=payload,
        payload_sha256=approvals_core.binding_digest(agent.id, body.kind, payload),
        policy_id=policy.id,
        required_approvals=policy.required_approvals,
        requested_by_operator_id=operator.id,
        requested_by_email=operator.email,
        reason=body.reason,
        status=ApprovalRequestStatus.pending,
        created_at=now,
        expires_at=approvals_core.request_expiry(policy, now),
    )
    db.add(approval)
    await db.flush()

    await audit.record(
        db,
        action="approval_request.created",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=agent.id,
        organization_id=client_id,
        source_ip=client_ip(request),
        detail=approvals_core.request_audit_detail(
            approval,
            reason=approval.reason,
            expires_at=approval.expires_at.isoformat(),
        ),
    )
    await db.commit()
    return await get_approval_request(approval.id, operator, db)


async def _record_decision(
    request_id: str,
    body: ApprovalDecisionCreate,
    http_request: Request,
    operator: Operator,
    db: AsyncSession,
    *,
    verdict: ApprovalDecisionKind,
) -> ApprovalRequestDetail:
    """Shared approve/reject path.

    Both verdicts run identical eligibility and state checks; only the terminal
    transition differs. Keeping them in one function is what guarantees a
    rejection cannot be recorded by someone who would not have been allowed to
    approve.
    """
    approval = await _load_request(request_id, operator, db)
    agent = await db.get(Agent, approval.agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "approval_request_not_found"},
        )

    now = _now()
    refusal = approvals_core.decision_refusal(
        approval, list(approval.decisions), operator, now
    )
    if refusal is None:
        eligibility = await approvals_core.approver_eligibility(
            db,
            operator,
            agent,
            approval.kind,
            requester_operator_id=approval.requested_by_operator_id,
        )
        refusal = None if eligibility.eligible else eligibility.reason

    if refusal is not None:
        await audit.record(
            db,
            action="approval_request.decision_denied",
            actor=operator.email,
            actor_user_id=operator.id,
            agent_id=approval.agent_id,
            source_ip=client_ip(http_request),
            detail=approvals_core.request_audit_detail(
                approval, decision=verdict.value, reason=refusal
            ),
        )
        await db.commit()
        raise HTTPException(
            status_code=_decision_refusal_status(refusal),
            detail={"code": refusal},
        )

    decision = ApprovalDecision(
        request_id=approval.id,
        operator_id=operator.id,
        operator_email=operator.email,
        operator_role=operator.role,
        decision=verdict,
        reason=body.reason,
        created_at=now,
        source_ip=client_ip(http_request),
    )
    db.add(decision)
    try:
        await db.flush()
    except IntegrityError as exc:
        # Lost the race against this same account's concurrent decision. The
        # unique constraint, not the check above, is the real guarantee that one
        # identity counts once.
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "approval_already_recorded"},
        ) from exc

    recorded = list(approval.decisions) + [decision]
    if verdict == ApprovalDecisionKind.reject:
        approval.status = ApprovalRequestStatus.rejected
        approval.decided_at = now
        approval.closed_at = now
        approval.closed_by_email = operator.email
        approval.closed_reason = "rejected_by_approver"
    elif approvals_core.approval_count(recorded) >= approval.required_approvals:
        approval.status = ApprovalRequestStatus.approved
        approval.decided_at = now

    await audit.record(
        db,
        action="approval_request.decision_recorded",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=approval.agent_id,
        organization_id=approval.client_id,
        source_ip=client_ip(http_request),
        detail=approvals_core.request_audit_detail(
            approval,
            decision=verdict.value,
            reason=body.reason,
            approvals_recorded=approvals_core.approval_count(recorded),
        ),
    )
    await db.commit()
    # Sessions here are ``expire_on_commit=False``, so the identity-mapped
    # request still holds the decision collection as it was loaded. Refresh it
    # explicitly or the response would under-report the verdict just recorded.
    await db.refresh(approval, attribute_names=["decisions"])
    return await get_approval_request(approval.id, operator, db)


def _decision_refusal_status(reason: str) -> int:
    """Map a refusal code to a status: 403 for "not you", 409 for state."""
    if reason in {
        "approval_self_not_permitted",
        "approver_disabled",
        "approver_is_requester",
        "approver_tenant_not_visible",
        "approver_client_role_insufficient",
    } or reason.startswith("approver_"):
        return status.HTTP_403_FORBIDDEN
    return status.HTTP_409_CONFLICT


@router.post(
    "/approval-requests/{request_id}/approve", response_model=ApprovalRequestDetail
)
async def approve_request(
    request_id: str,
    body: ApprovalDecisionCreate,
    http_request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Record one identity's approval. Never the requester's own."""
    return await _record_decision(
        request_id,
        body,
        http_request,
        operator,
        db,
        verdict=ApprovalDecisionKind.approve,
    )


@router.post(
    "/approval-requests/{request_id}/reject", response_model=ApprovalRequestDetail
)
async def reject_request(
    request_id: str,
    body: ApprovalDecisionCreate,
    http_request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Refuse a request outright. Terminal: one rejection ends it."""
    return await _record_decision(
        request_id,
        body,
        http_request,
        operator,
        db,
        verdict=ApprovalDecisionKind.reject,
    )


@router.post(
    "/approval-requests/{request_id}/cancel", response_model=ApprovalRequestDetail
)
async def cancel_request(
    request_id: str,
    body: ApprovalDecisionCreate,
    http_request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Withdraw a request. Available to its requester and to tenant admins.

    Cancellation is terminal and applies to an already-approved request too:
    withdrawing work that turned out to be unnecessary must not leave a
    spendable approval lying around.
    """
    approval = await _load_request(request_id, operator, db)
    is_requester = approval.requested_by_operator_id == operator.id
    if not is_requester:
        await tenant_scope.assert_client_action(
            operator,
            approval.client_id,
            db,
            minimum=ClientRole.client_admin,
            detail={"code": "approval_request_not_found"},
        )
    if approval.status not in (
        ApprovalRequestStatus.pending,
        ApprovalRequestStatus.approved,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "approval_request_not_pending"},
        )

    now = _now()
    approval.status = ApprovalRequestStatus.cancelled
    approval.closed_at = now
    approval.closed_by_email = operator.email
    approval.closed_reason = body.reason

    await audit.record(
        db,
        action="approval_request.cancelled",
        actor=operator.email,
        actor_user_id=operator.id,
        agent_id=approval.agent_id,
        organization_id=approval.client_id,
        source_ip=client_ip(http_request),
        detail=approvals_core.request_audit_detail(
            approval,
            reason=body.reason,
            cancelled_by_requester=is_requester,
        ),
    )
    await db.commit()
    return await get_approval_request(approval.id, operator, db)
