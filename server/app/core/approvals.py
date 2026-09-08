# SPDX-License-Identifier: AGPL-3.0-only
"""Approval workflows and two-person authorization for sensitive commands (#64).

This module is the single decision point for "does this dispatch need other
people to agree, and did they?". The API layer transports and records; every
rule that decides an outcome lives here so it can be unit-tested without HTTP
and cannot drift between the three call sites that dispatch commands.

The control in one sentence: when a policy marks a command kind sensitive, the
operator must first raise an :class:`ApprovalRequest` describing the exact
command, and dispatch is refused until enough *other* eligible identities have
approved that exact request -- after which the approval is spent, once.

Four properties this is built to hold, and where each is enforced:

* **No self-approval.** :func:`decision_refusal` refuses the requester's own
  verdict, and :func:`consumption_refusal` re-checks it at dispatch, so a
  request whose requester somehow recorded a decision still cannot be spent.
* **Distinct identities.** The database unique constraint on
  ``(request_id, operator_id)`` is the real enforcement; the application check
  exists to return a clean 409 rather than an integrity error.
* **Nothing mutates between review and execution.** The approval binds the
  SHA-256 of the canonical ``(agent_id, kind, payload)`` tuple
  (:func:`binding_digest`). Dispatch recomputes it from what was actually
  submitted, so an approved payload cannot be swapped for another.
* **Authority must still exist when it is used.** Approver eligibility is
  re-evaluated live at dispatch (:func:`approver_eligibility`), never read from
  the snapshot stored on the decision row. An approver demoted, tenant-removed,
  disabled, or stripped of script permission after approving no longer counts,
  and a request that consequently falls below its bar fails closed.

Everything fails closed. An unresolvable policy, an unreadable request, a
mismatched digest, a lapsed expiry, and an ineligible approver all refuse the
dispatch; none of them fall through to "allowed".
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import tenant_scope
from app.core.script_authorization import authorize_command
from app.models.models import (
    Agent,
    ApprovalDecision,
    ApprovalDecisionKind,
    ApprovalPolicy,
    ApprovalRequest,
    ApprovalRequestStatus,
    ClientRole,
    CommandKind,
    MonitoringScope,
    Operator,
)

# Bounds on operator-supplied justification. A reason is mandatory in both
# directions (request and decision): an approval with no stated basis is not
# evidence. The floor is deliberately low enough not to encourage padding and
# the ceiling matches the power-operation reason bound.
MIN_REASON_BYTES = 10
MAX_REASON_BYTES = 512

# Ceiling on how long an approval stays spendable, independent of policy. A
# policy may choose less; it may not choose more. Seven days is well past any
# legitimate change window and short enough that an approval cannot outlive the
# fleet state it was granted against.
MAX_REQUEST_TTL_SECONDS = 7 * 24 * 3600
MIN_REQUEST_TTL_SECONDS = 60

# Most-specific-wins ordering, matching MonitoringPolicy/PatchApprovalPolicy.
_SCOPE_SPECIFICITY = {
    MonitoringScope.agent: 3,
    MonitoringScope.site: 2,
    MonitoringScope.client: 1,
    MonitoringScope.global_: 0,
}

# States from which a request can still become usable or be spent. Everything
# else is terminal and is never revived.
_LIVE_STATUSES = (ApprovalRequestStatus.pending, ApprovalRequestStatus.approved)


def as_utc(value: datetime | None) -> datetime | None:
    """Read a stored timestamp as timezone-aware UTC (SQLite returns naive)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def binding_digest(agent_id: str, kind: CommandKind, payload: dict) -> str:
    """SHA-256 over the canonical (agent, kind, payload) tuple.

    This is the execution binding. It is domain-separated by a version tag so a
    future change to what is bound cannot be confused with the current scheme,
    and it uses the same canonical JSON encoding as the command envelope
    (sorted keys, no insignificant whitespace) so an equivalent payload
    submitted with different key ordering still matches.
    """
    document = {
        "v": 1,
        "agent_id": agent_id,
        "kind": kind.value if isinstance(kind, CommandKind) else str(kind),
        "payload": payload,
    }
    blob = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


async def resolve_policy(
    db: AsyncSession, agent: Agent, kind: CommandKind
) -> ApprovalPolicy | None:
    """The single most specific enabled policy governing ``kind`` for ``agent``.

    Returns ``None`` when no policy applies, which means "dispatch under the
    existing role and script-scope rules, unchanged". That absence is what makes
    the capability opt-in: deploying this code changes no existing behavior
    until an administrator writes a policy.

    The read is a small unfiltered scan of the policy table. Policies are few
    and long-lived by nature (an administrator writes one per tenant, not one
    per endpoint), so this stays cheaper and far easier to reason about than
    four scope-specific queries; if a deployment ever accumulates enough
    policies for that to matter, this is the one function to change.

    Specificity, not union: an agent-scoped policy that omits a kind does not
    inherit the site policy's list for that kind. Scopes are evaluated
    independently and the most specific *match* wins, so a narrow policy can
    only be authored to add requirements, never to silently drop them from a
    broader one -- a broader policy still matches when the narrow one does not
    name the kind.
    """
    site_id = agent.site_id
    client_id = await tenant_scope.agent_client_id(agent, db)
    candidates = (
        await db.execute(
            select(ApprovalPolicy).where(ApprovalPolicy.enabled.is_(True))
        )
    ).scalars().all()

    matched: list[ApprovalPolicy] = []
    for policy in candidates:
        if kind.value not in (policy.command_kinds or []):
            continue
        if policy.scope == MonitoringScope.global_:
            matched.append(policy)
        elif policy.scope == MonitoringScope.client and policy.scope_id == client_id:
            matched.append(policy)
        elif policy.scope == MonitoringScope.site and policy.scope_id == site_id:
            matched.append(policy)
        elif policy.scope == MonitoringScope.agent and policy.scope_id == agent.id:
            matched.append(policy)
    if not matched:
        return None
    # Ties within a scope tier cannot happen for agent/site/client (one target
    # id) but can for two global policies naming the same kind. Break by oldest
    # first so the effective policy is deterministic rather than query-order
    # dependent. Timestamps are normalized before comparison: a row still in the
    # session is timezone-aware while a reloaded one is not, and the two cannot
    # be ordered against each other.
    matched.sort(
        key=lambda p: (-_SCOPE_SPECIFICITY[p.scope], as_utc(p.created_at), p.id)
    )
    return matched[0]


@dataclass(frozen=True)
class ApproverEligibility:
    """Whether one identity may act as an approver for one request."""

    eligible: bool
    reason: str


async def approver_eligibility(
    db: AsyncSession,
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
    *,
    requester_operator_id: str | None,
) -> ApproverEligibility:
    """Live eligibility check for an approver, used at decision *and* dispatch.

    An eligible approver is someone who could have dispatched the command
    themselves. Anything less would let approval launder authority: a readonly
    account, or an operator with no script permission for this endpoint, must
    not be able to unlock an action they are not trusted to perform.

    The checks, in fail-closed order: the account must be enabled, must not be
    the requester, must hold at least ``client_operator`` on the request's
    tenant, and must pass ``authorize_command`` for this exact agent and kind.
    """
    if operator.disabled:
        return ApproverEligibility(False, "approver_disabled")
    if requester_operator_id is not None and operator.id == requester_operator_id:
        return ApproverEligibility(False, "approver_is_requester")

    client_id = await tenant_scope.agent_client_id(agent, db)
    if not operator.is_platform_admin:
        membership = (
            await tenant_scope.resolve_membership(operator, client_id, db)
            if client_id is not None
            else None
        )
        if membership is None:
            return ApproverEligibility(False, "approver_tenant_not_visible")
        if not tenant_scope.client_role_permits(
            membership.role, ClientRole.client_operator
        ):
            return ApproverEligibility(False, "approver_client_role_insufficient")

    decision = authorize_command(operator, agent, kind)
    if not decision.allowed:
        return ApproverEligibility(False, f"approver_{decision.reason}")
    return ApproverEligibility(True, "approver_eligible")


def expire_if_due(request: ApprovalRequest, now: datetime) -> bool:
    """Flip a live request to ``expired`` when its deadline has passed.

    Expiry is evaluated on every read and on every use rather than only by a
    sweeper, so a request is never usable past ``expires_at`` even if no
    background pass has run. The caller records the audit event and commits;
    this returns whether the state actually changed.
    """
    if request.status not in _LIVE_STATUSES:
        return False
    expires_at = as_utc(request.expires_at)
    if expires_at is None or expires_at > now:
        return False
    request.status = ApprovalRequestStatus.expired
    request.closed_at = now
    request.closed_reason = "request_ttl_elapsed"
    return True


def approval_count(decisions: list[ApprovalDecision]) -> int:
    """How many distinct identities have approved."""
    return len({d.operator_id for d in decisions if d.decision == ApprovalDecisionKind.approve})


def has_rejection(decisions: list[ApprovalDecision]) -> bool:
    return any(d.decision == ApprovalDecisionKind.reject for d in decisions)


def decision_refusal(
    request: ApprovalRequest,
    decisions: list[ApprovalDecision],
    operator: Operator,
    now: datetime,
) -> str | None:
    """Why ``operator`` may not record a verdict now, or ``None`` if they may.

    Ordered so the most specific, least oracle-ish reason wins: state first,
    then self-approval, then duplication. Every return value is a stable code
    the API maps to a status and the audit log records verbatim.
    """
    if request.status == ApprovalRequestStatus.expired or (
        as_utc(request.expires_at) is not None
        and as_utc(request.expires_at) <= now
    ):
        return "approval_request_expired"
    if request.status not in _LIVE_STATUSES:
        return "approval_request_not_pending"
    if request.status == ApprovalRequestStatus.approved:
        # Already at its bar. Further verdicts would be recorded against a
        # decision that has already been made, which muddies the evidence.
        return "approval_request_already_approved"
    if operator.id == request.requested_by_operator_id:
        return "approval_self_not_permitted"
    if any(d.operator_id == operator.id for d in decisions):
        return "approval_already_recorded"
    return None


@dataclass(frozen=True)
class ConsumptionCheck:
    """The dispatch-time verdict on spending one approval."""

    allowed: bool
    reason: str
    approver_ids: tuple[str, ...] = ()


async def consumption_refusal(
    db: AsyncSession,
    request: ApprovalRequest,
    decisions: list[ApprovalDecision],
    *,
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
    payload: dict,
    now: datetime,
) -> ConsumptionCheck:
    """Full re-validation of an approval at the moment it would be spent.

    Nothing here trusts the state recorded when the approval was granted. The
    request must still be approved and unexpired, must still describe this
    operator's own request against this exact agent, kind, and payload, and
    every counted approver must *still* be eligible right now. The dispatcher
    additionally performs the atomic status transition, so this function decides
    and the caller commits.
    """
    if request.agent_id != agent.id:
        return ConsumptionCheck(False, "approval_request_agent_mismatch")
    if request.kind != kind:
        return ConsumptionCheck(False, "approval_request_kind_mismatch")
    if request.payload_sha256 != binding_digest(agent.id, kind, payload):
        return ConsumptionCheck(False, "approval_request_payload_mismatch")
    # The approval authorizes the person who asked for it. Letting a third
    # operator spend someone else's approval would break attribution and make
    # the two-person count meaningless (the spender was never counted).
    if request.requested_by_operator_id != operator.id:
        return ConsumptionCheck(False, "approval_request_requester_mismatch")
    # Expiry is reported before the generic state refusal. The caller has
    # usually just flipped a lapsed request to ``expired``, and "this approval
    # ran out" is the answer the operator can act on; "not approved" would send
    # them looking for a missing reviewer that does not exist.
    expires_at = as_utc(request.expires_at)
    if request.status == ApprovalRequestStatus.expired or (
        expires_at is None or expires_at <= now
    ):
        return ConsumptionCheck(False, "approval_request_expired")
    if request.status == ApprovalRequestStatus.consumed:
        return ConsumptionCheck(False, "approval_request_already_consumed")
    if request.status != ApprovalRequestStatus.approved:
        return ConsumptionCheck(False, "approval_request_not_approved")

    approvers = [d for d in decisions if d.decision == ApprovalDecisionKind.approve]
    still_eligible: list[str] = []
    for decision in approvers:
        approver = await db.get(Operator, decision.operator_id)
        if approver is None:
            continue
        verdict = await approver_eligibility(
            db,
            approver,
            agent,
            kind,
            requester_operator_id=request.requested_by_operator_id,
        )
        if verdict.eligible:
            still_eligible.append(approver.id)
    if len(still_eligible) < request.required_approvals:
        # Role loss, tenant removal, disablement, or a revoked script grant
        # since approval. Fail closed: the bar the policy set is not currently
        # met by identities that still hold the authority.
        return ConsumptionCheck(False, "approval_approver_no_longer_eligible")
    return ConsumptionCheck(True, "approval_satisfied", tuple(sorted(still_eligible)))


def request_expiry(policy: ApprovalPolicy, now: datetime) -> datetime:
    """Deadline for a request raised under ``policy``, clamped to the ceiling."""
    ttl = max(
        MIN_REQUEST_TTL_SECONDS,
        min(int(policy.request_ttl_seconds), MAX_REQUEST_TTL_SECONDS),
    )
    return now + timedelta(seconds=ttl)


def request_audit_detail(request: ApprovalRequest, **extra) -> dict:
    """Safe accountable metadata for an approval event.

    Never the payload values: only its key names and the binding digest, exactly
    like ``command.dispatched``. The justification prose is passed through as
    ``reason`` and digested by the central audit policy.
    """
    detail = {
        "approval_request_id": request.id,
        "kind": request.kind.value,
        "agent_id": request.agent_id,
        "client_id": request.client_id,
        "site_id": request.site_id,
        "policy_id": request.policy_id,
        "required_approvals": request.required_approvals,
        "payload_keys": sorted(request.payload or {}),
        "payload_sha256": request.payload_sha256,
        "status": request.status.value,
    }
    detail.update(extra)
    return detail
