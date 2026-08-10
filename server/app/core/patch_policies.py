# SPDX-License-Identifier: AGPL-3.0-only
"""Patch approval policy resolution and evaluation (issue #52).

* :func:`resolve_effective_patch_policy` picks the single most-specific enabled
  policy that targets an agent (agent > site > client > global). Unlike
  monitoring's per-check merge, patch rules are ordered and first-match, so a
  more-specific policy overrides a less-specific one wholesale — the model that
  keeps ordered rule evaluation unambiguous.
* :func:`evaluate_update` runs one scanned update through a revision's ordered
  rules (first match wins), falling back to the revision's ``default_action``.
  A ``defer`` rule approves only once the update is old enough; otherwise the
  update stays blocked, failing closed when its release date is unknown.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Agent,
    MonitoringScope,
    PatchApprovalPolicy,
    PatchApprovalPolicyRevision,
    Site,
)
from app.schemas.patch_policies import PatchAction, PatchDefaultAction, PatchRule

_SCOPE_PRECEDENCE: dict[MonitoringScope, int] = {
    MonitoringScope.global_: 0,
    MonitoringScope.client: 1,
    MonitoringScope.site: 2,
    MonitoringScope.agent: 3,
}


@dataclass(frozen=True)
class EffectivePatchPolicy:
    policy: PatchApprovalPolicy
    revision: PatchApprovalPolicyRevision


@dataclass(frozen=True)
class UpdateDecision:
    decision: str  # "approve" | "deny" | "defer"
    reason: str
    matched_rule_key: str | None


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def current_revision(
    db: AsyncSession, policy_id: str
) -> PatchApprovalPolicyRevision | None:
    return await db.scalar(
        select(PatchApprovalPolicyRevision)
        .where(PatchApprovalPolicyRevision.policy_id == policy_id)
        .order_by(PatchApprovalPolicyRevision.version.desc())
        .limit(1)
    )


async def _applicable_policies(
    db: AsyncSession, agent: Agent
) -> list[PatchApprovalPolicy]:
    site = await db.get(Site, agent.site_id)
    client_id = site.client_id if site else None

    from sqlalchemy import or_

    conditions = [PatchApprovalPolicy.scope == MonitoringScope.global_]
    if client_id is not None:
        conditions.append(
            (PatchApprovalPolicy.scope == MonitoringScope.client)
            & (PatchApprovalPolicy.scope_id == client_id)
        )
    conditions.append(
        (PatchApprovalPolicy.scope == MonitoringScope.site)
        & (PatchApprovalPolicy.scope_id == agent.site_id)
    )
    conditions.append(
        (PatchApprovalPolicy.scope == MonitoringScope.agent)
        & (PatchApprovalPolicy.scope_id == agent.id)
    )
    result = await db.execute(
        select(PatchApprovalPolicy).where(
            PatchApprovalPolicy.enabled.is_(True), or_(*conditions)
        )
    )
    return list(result.scalars().all())


async def resolve_effective_patch_policy(
    db: AsyncSession, agent: Agent
) -> EffectivePatchPolicy | None:
    """The single most-specific enabled policy for an agent, or None.

    Most-specific scope wins; within a scope the earliest-created policy is
    chosen for determinism.
    """
    policies = await _applicable_policies(db, agent)
    if not policies:
        return None
    policies.sort(key=lambda p: (-_SCOPE_PRECEDENCE[p.scope], p.created_at, p.id))
    winner = policies[0]
    revision = await current_revision(db, winner.id)
    if revision is None:
        return None
    return EffectivePatchPolicy(policy=winner, revision=revision)


def parse_rules(raw: list) -> list[PatchRule]:
    """Re-validate stored rules on read so a hand-edited row cannot inject an
    unparseable rule into evaluation."""
    return [PatchRule.model_validate(item) for item in raw or []]


def _facet_matches(values: list[str] | None, actual: str | None) -> bool:
    if values is None:
        return True  # facet not constrained by this rule
    if actual is None:
        return False
    folded = actual.strip().casefold()
    return any(value.strip().casefold() == folded for value in values)


def _kb_matches(kb_ids: list[str] | None, actual: str | None) -> bool:
    if kb_ids is None:
        return True
    if not actual:
        return False
    normalized = actual.strip().upper()
    return normalized in kb_ids


def _rule_matches(rule: PatchRule, update: dict) -> bool:
    # Facets within a rule are ANDed: a rule applies only when every constrained
    # facet matches. Use separate rules for OR semantics.
    return (
        _facet_matches(rule.match.classifications, update.get("classification"))
        and _facet_matches(rule.match.severities, update.get("severity"))
        and _kb_matches(rule.match.kb_ids, update.get("kb_id"))
    )


def _parse_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _defer_satisfied(update: dict, defer_days: int, now: datetime) -> bool:
    released = _parse_dt(update.get("last_deployment_change"))
    if released is None:
        return False  # unknown age → fail closed, stays deferred
    return now >= released + timedelta(days=defer_days)


def evaluate_update(
    rules: list[PatchRule],
    default_action: str,
    update: dict,
    now: datetime | None = None,
) -> UpdateDecision:
    now = now or _now()
    for rule in rules:
        if not _rule_matches(rule, update):
            continue
        if rule.action == PatchAction.deny:
            return UpdateDecision("deny", f"rule:{rule.key}", rule.key)
        if rule.action == PatchAction.approve:
            return UpdateDecision("approve", f"rule:{rule.key}", rule.key)
        # defer
        if _defer_satisfied(update, rule.defer_days or 0, now):
            return UpdateDecision("approve", f"rule:{rule.key}:deferral_elapsed", rule.key)
        return UpdateDecision("defer", f"rule:{rule.key}:deferred", rule.key)
    default = (
        "approve" if default_action == PatchDefaultAction.approve.value else "deny"
    )
    return UpdateDecision(default, "default", None)
