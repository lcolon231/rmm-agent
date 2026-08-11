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

from app.core import inventory, monitoring as monitoring_core
from app.core.command_envelope import format_command_time
from app.models.models import (
    Agent,
    Heartbeat,
    MonitoringScope,
    PatchApprovalPolicy,
    PatchApprovalPolicyRevision,
    Site,
)
from app.schemas.inventory import InventorySection
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


# --------------------------------------------------------------------------- #
# Install gate (issue #53): shared by the management endpoint and the scheduler
# --------------------------------------------------------------------------- #
#: Agents advertising this capability understand the #53 install-payload
#: extensions (``max_attempts`` and signed ``reboot`` evidence). The gate never
#: injects those extensions for an agent that does not advertise it, so a
#: mixed-version fleet is safe.
PATCH_REBOOT_CAPABILITY = "patch-reboot-v1"


async def latest_missing_updates(db: AsyncSession, agent_id: str) -> list[dict]:
    """The agent's latest scanned missing Windows updates, or an empty list."""
    sections = await inventory.latest_sections(db, agent_id)
    snapshot = sections.get(InventorySection.windows_updates.value)
    if snapshot is None:
        return []
    missing = (snapshot.payload or {}).get("missing")
    return [item for item in missing if isinstance(item, dict)] if isinstance(missing, list) else []


async def _latest_user_present(db: AsyncSession, agent: Agent) -> bool:
    """Whether the endpoint's latest heartbeat reports an interactive user.

    A missing heartbeat is treated as "present" so reboot policy fails safe.
    """
    heartbeat = (
        await db.execute(
            select(Heartbeat)
            .where(Heartbeat.agent_id == agent.id)
            .order_by(Heartbeat.ts.desc(), Heartbeat.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return bool(heartbeat is None or (heartbeat.logged_in_user or "").strip())


async def evaluate_patch_install(
    db: AsyncSession, agent: Agent, payload: dict, now: datetime
) -> dict | None:
    """Evaluate an install_updates dispatch against the effective patch policy.

    Returns None when no policy applies (opt-in: dispatch is unchanged). Otherwise
    a decision dict with the (possibly rewritten) ``payload``, the ``outcome``, and
    audit details. Reads only — callers record audit and either raise (the
    management endpoint) or skip (the scheduler). ``install_all`` is narrowed to the
    approved subset; an explicit selection is fail-closed. When the outcome is
    allowed and the agent advertises ``patch-reboot-v1`` the payload gains
    ``max_attempts`` and, if the policy opts into a reboot, signed ``reboot``
    evidence.
    """
    effective = await resolve_effective_patch_policy(db, agent)
    if effective is None:
        return None

    revision = effective.revision
    rules = parse_rules(revision.rules)
    missing = await latest_missing_updates(db, agent.id)
    by_kb = {(item.get("kb_id") or "").upper(): item for item in missing if item.get("kb_id")}
    by_id = {(item.get("update_id") or "").lower(): item for item in missing if item.get("update_id")}

    window_required = bool(revision.require_maintenance_window)
    windows: list = []
    if window_required:
        windows = await monitoring_core.active_maintenance_windows(db, agent, at=now)
    window_present = bool(windows) if window_required else True

    install_all = payload.get("install_all") is True
    approved = denied = deferred = 0
    blocked: list[str] = []
    approved_kbs: list[str] = []
    approved_ids: list[str] = []

    def classify(item: dict) -> bool:
        nonlocal approved, denied, deferred
        verdict = evaluate_update(rules, revision.default_action, item, now)
        if verdict.decision == "approve":
            approved += 1
            return True
        if verdict.decision == "deny":
            denied += 1
        else:
            deferred += 1
        return False

    if install_all:
        requested = len(missing)
        for item in missing:
            if classify(item):
                if item.get("kb_id"):
                    approved_kbs.append(item["kb_id"].upper())
                elif item.get("update_id"):
                    approved_ids.append(item["update_id"].lower())
        result_payload = {
            "install_all": False,
            "kb_ids": sorted(set(approved_kbs)),
            "update_ids": sorted(set(approved_ids)),
        }
    else:
        requested_kbs = [str(value).upper() for value in payload.get("kb_ids", [])]
        requested_ids = [str(value).lower() for value in payload.get("update_ids", [])]
        requested = len(requested_kbs) + len(requested_ids)
        for kb in requested_kbs:
            item = by_kb.get(kb)
            if item is None:
                denied += 1
                blocked.append(kb)
            elif not classify(item):
                blocked.append(kb)
        for uid in requested_ids:
            item = by_id.get(uid)
            if item is None:
                denied += 1
                blocked.append(uid)
            elif not classify(item):
                blocked.append(uid)
        result_payload = dict(payload)

    if window_required and not window_present:
        outcome = "maintenance_window_required"
    elif install_all and not approved_kbs and not approved_ids:
        outcome = "no_approved_updates"
    elif not install_all and blocked:
        outcome = "denied"
    else:
        outcome = "allowed"

    gated_detail = {
        "policy_id": effective.policy.id,
        "outcome": outcome,
        "install_all": install_all,
        "requested": requested,
        "approved": approved,
        "denied": denied,
        "deferred": deferred,
        "window_required": window_required,
        "window_present": window_present,
    }

    reboot_detail = None
    supports_reboot = PATCH_REBOOT_CAPABILITY in (agent.supported_capabilities or [])
    if outcome == "allowed" and supports_reboot:
        result_payload["max_attempts"] = revision.max_install_attempts
        if revision.reboot_policy != "never":
            user_present = await _latest_user_present(db, agent)
            reboot: dict = {
                "policy": revision.reboot_policy,
                "delay_seconds": revision.reboot_delay_seconds,
                "requires_no_user": bool(revision.reboot_requires_no_user),
                "user_present_at_dispatch": user_present,
                "maintenance_window_id": None,
                "maintenance_window_ends_at": None,
            }
            if window_required and window_present:
                def as_utc(value: datetime) -> datetime:
                    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

                window = min(windows, key=lambda item: (as_utc(item.ends_at), item.id))
                reboot["maintenance_window_id"] = window.id
                reboot["maintenance_window_ends_at"] = format_command_time(as_utc(window.ends_at))
            result_payload["reboot"] = reboot
            reboot_detail = {
                "policy_id": effective.policy.id,
                "reboot_policy": revision.reboot_policy,
                "delay_seconds": revision.reboot_delay_seconds,
                "requires_no_user": bool(revision.reboot_requires_no_user),
                "window_present": window_present if window_required else False,
                "user_present": user_present,
            }

    code = {
        "maintenance_window_required": "patch_install_maintenance_window_required",
        "no_approved_updates": "patch_install_no_approved_updates",
        "denied": "patch_install_denied",
    }.get(outcome)

    return {
        "outcome": outcome,
        "payload": result_payload,
        "gated_detail": gated_detail,
        "reboot_detail": reboot_detail,
        "blocked": blocked,
        "policy_id": effective.policy.id,
        "code": code,
    }
