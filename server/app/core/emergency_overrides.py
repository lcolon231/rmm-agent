# SPDX-License-Identifier: AGPL-3.0-only
"""Justified emergency override of an approval policy (#65).

This module is the single decision point for "may this person stand in for
the approvers right now, and is this override still good to spend?". It is the
dual-control analogue of a break-glass login: the approval policy from #64
stays in force, but one authorized identity may authorize one exact command
alone -- loudly, briefly, and on the record.

What keeps it an exception rather than a bypass, and where each property is
enforced:

* **Opt-in per policy.** :func:`activator_eligibility` refuses unless the
  governing policy has ``emergency_override_allowed`` set. No policy, or a
  policy without the flag, means no override exists for that command.
* **Authority, not convenience.** The activator must be a platform admin or
  hold ``client_admin`` on the endpoint's tenant *and* must pass the ordinary
  command authorization. An override never grants an action the activator
  could not have run with approval.
* **Nothing mutates between activation and execution.** The override binds the
  same canonical ``(agent_id, kind, payload)`` digest an approval does
  (:func:`app.core.approvals.binding_digest`); dispatch recomputes it.
* **Short-lived, single-use, revocable.** Expiry is bounded to minutes and
  evaluated on every read and use; consumption is a conditional status
  transition performed by the dispatcher; an unspent override can be revoked.
* **Authority must still exist when it is used.** The activator's eligibility
  is re-evaluated live at dispatch, never read from the row.

Everything fails closed: an unreadable override, a mismatched digest, a lapsed
expiry, a revoked row, and an activator who has since lost authority all refuse
the dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import approvals as approvals_core
from app.core import tenant_scope
from app.core.approvals import as_utc, binding_digest
from app.core.script_authorization import authorize_command
from app.models.models import (
    Agent,
    ApprovalPolicy,
    ClientRole,
    CommandKind,
    EmergencyOverride,
    EmergencyOverrideStatus,
    Operator,
)

# A justification is the whole basis of the exception, so the floor is higher
# than an approval reason's: a one-word override is a click, not a record.
MIN_JUSTIFICATION_BYTES = 20
MAX_JUSTIFICATION_BYTES = 512

# How long an override stays spendable. Fifteen minutes is enough to dispatch
# the command it was minted for and short enough that a forgotten override
# cannot outlive the incident. The ceiling is a hard bound the API cannot
# exceed whatever the caller asks for.
DEFAULT_TTL_SECONDS = 15 * 60
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 60 * 60

# Unspent overrides one operator may hold per tenant. An emergency is a small
# number of commands; a pile of open overrides is either abuse or a mistake.
MAX_OPEN_OVERRIDES_PER_OPERATOR = 5

# Notification outcome codes recorded on the row when no message was accepted.
NOTIFICATION_NO_RECIPIENTS = "no_recipients_configured"
NOTIFICATION_PROVIDER_UNAVAILABLE = "email_provider_unavailable"


@dataclass(frozen=True)
class ActivatorEligibility:
    """Whether one identity may activate (or still hold) an override."""

    eligible: bool
    reason: str


async def activator_eligibility(
    db: AsyncSession,
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
    *,
    policy: ApprovalPolicy | None,
) -> ActivatorEligibility:
    """Live eligibility check for an activator, used at activation *and* dispatch.

    Fail-closed order: account enabled, a policy that both governs the kind and
    allows overrides, tenant-admin standing (or platform admin), and the
    ordinary command authorization for this exact agent and kind. Every reason
    is a stable code the API maps to a status and the audit log records.
    """
    if operator.disabled:
        return ActivatorEligibility(False, "emergency_override_operator_disabled")
    if policy is None:
        return ActivatorEligibility(False, "emergency_override_not_required")
    if not policy.emergency_override_allowed:
        return ActivatorEligibility(False, "emergency_override_not_permitted")

    if not operator.is_platform_admin:
        client_id = await tenant_scope.agent_client_id(agent, db)
        membership = (
            await tenant_scope.resolve_membership(operator, client_id, db)
            if client_id is not None
            else None
        )
        if membership is None:
            return ActivatorEligibility(False, "emergency_override_tenant_not_visible")
        if not tenant_scope.client_role_permits(membership.role, ClientRole.client_admin):
            return ActivatorEligibility(False, "emergency_override_role_insufficient")

    decision = authorize_command(operator, agent, kind)
    if not decision.allowed:
        return ActivatorEligibility(False, f"emergency_override_{decision.reason}")
    return ActivatorEligibility(True, "emergency_override_activator_eligible")


def override_expiry(ttl_seconds: int | None, now: datetime) -> datetime:
    """Deadline for an override, clamped to the hard bounds."""
    requested = DEFAULT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
    ttl = max(MIN_TTL_SECONDS, min(requested, MAX_TTL_SECONDS))
    return now + timedelta(seconds=ttl)


def expire_if_due(override: EmergencyOverride, now: datetime) -> bool:
    """Flip an active override to ``expired`` once its deadline has passed.

    Evaluated on every read and use, so an override is never spendable past
    ``expires_at`` even if no sweeper has run. Returns whether state changed;
    the caller records the audit event and commits.
    """
    if override.status != EmergencyOverrideStatus.active:
        return False
    expires_at = as_utc(override.expires_at)
    if expires_at is None or expires_at > now:
        return False
    override.status = EmergencyOverrideStatus.expired
    return True


@dataclass(frozen=True)
class ConsumptionCheck:
    """The dispatch-time verdict on spending one override."""

    allowed: bool
    reason: str


async def consumption_refusal(
    db: AsyncSession,
    override: EmergencyOverride,
    *,
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
    payload: dict,
    now: datetime,
) -> ConsumptionCheck:
    """Full re-validation of an override at the moment it would be spent.

    Nothing here trusts the state recorded at activation. The override must
    describe this exact agent, kind, and payload; must be spent by the person
    who activated it; must still be active and unexpired; and the activator
    must *still* be eligible under the policy as it stands now (including the
    opt-in flag -- an administrator withdrawing the opt-in invalidates open
    overrides immediately). The dispatcher performs the atomic status
    transition; this function only decides.
    """
    if override.agent_id != agent.id:
        return ConsumptionCheck(False, "emergency_override_agent_mismatch")
    if override.kind != kind:
        return ConsumptionCheck(False, "emergency_override_kind_mismatch")
    if override.payload_sha256 != binding_digest(agent.id, kind, payload):
        return ConsumptionCheck(False, "emergency_override_payload_mismatch")
    # The override authorizes the person who took responsibility for it. A
    # third operator spending it would break the attribution the review rests
    # on.
    if override.activated_by_operator_id != operator.id:
        return ConsumptionCheck(False, "emergency_override_activator_mismatch")
    expires_at = as_utc(override.expires_at)
    if override.status == EmergencyOverrideStatus.expired or (
        expires_at is None or expires_at <= now
    ):
        return ConsumptionCheck(False, "emergency_override_expired")
    if override.status == EmergencyOverrideStatus.consumed:
        return ConsumptionCheck(False, "emergency_override_already_consumed")
    if override.status == EmergencyOverrideStatus.revoked:
        return ConsumptionCheck(False, "emergency_override_revoked")
    if override.status != EmergencyOverrideStatus.active:
        return ConsumptionCheck(False, "emergency_override_not_active")

    policy = await approvals_core.resolve_policy(db, agent, kind)
    eligibility = await activator_eligibility(db, operator, agent, kind, policy=policy)
    if not eligibility.eligible:
        # Role loss, tenant removal, disablement, a revoked script grant, or
        # the policy's opt-in withdrawn since activation. Fail closed.
        return ConsumptionCheck(False, "emergency_override_activator_no_longer_eligible")
    return ConsumptionCheck(True, "emergency_override_satisfied")


def audit_detail(override: EmergencyOverride, **extra) -> dict:
    """Safe accountable metadata for an override event.

    Never the payload values: only key names and the binding digest, exactly
    like ``command.dispatched`` and the approval events. Prose (justification,
    revoke reason, review note) is passed through by the caller under its own
    key and digested by the central audit policy.
    """
    detail = {
        "emergency_override_id": override.id,
        "kind": override.kind.value,
        "agent_id": override.agent_id,
        "client_id": override.client_id,
        "site_id": override.site_id,
        "policy_id": override.policy_id,
        "required_approvals": override.required_approvals,
        "payload_keys": sorted(override.payload or {}),
        "payload_sha256": override.payload_sha256,
        "status": override.status.value,
    }
    detail.update(extra)
    return detail
