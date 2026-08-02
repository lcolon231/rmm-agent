# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy resolution, offline evaluation, and result storage.

Responsibilities:

* :func:`resolve_effective_policy` computes the check set that actually applies
  to one agent by merging the policies at every scope level that targets it
  (global -> client -> site -> agent) with **most-specific-wins** per check key.
  Issue #42 uses this seam for agent assignments and server-owned offline checks.
* :func:`record_check_result` / :func:`prune_check_results` persist and bound the
  check-result contract. #42's authenticated ingestion route calls it with a
  durable agent-generated result ID.
* :func:`evaluate_offline_checks` records due heartbeat-age checks in the
  server sweeper with the same cadence and hysteresis semantics.

Offline checks are evaluated here because an unreachable endpoint cannot report
itself. Alert state and maintenance-window suppression remain #43+.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Agent,
    CheckResult,
    CheckResultStatus,
    MaintenanceWindow,
    MonitoringPolicy,
    MonitoringPolicyRevision,
    MonitoringScope,
    Site,
)
from app.schemas.monitoring import CheckDefinition, Threshold, ThresholdOp

# Scope precedence, least- to most-specific. A check defined at a higher number
# overrides the same key from a lower one.
_SCOPE_PRECEDENCE: dict[MonitoringScope, int] = {
    MonitoringScope.global_: 0,
    MonitoringScope.client: 1,
    MonitoringScope.site: 2,
    MonitoringScope.agent: 3,
}

MAX_CHECK_RESULT_DETAIL_BYTES = 16 * 1024
_CHECK_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EffectiveCheck:
    """One resolved check plus the policy it won from."""

    definition: CheckDefinition
    source_scope: MonitoringScope
    source_policy_id: str
    source_revision_id: str
    source_policy_name: str


async def current_revision(
    db: AsyncSession, policy_id: str
) -> MonitoringPolicyRevision | None:
    """The highest-version (current) revision of a policy, or None if it has
    somehow never been given one."""
    return await db.scalar(
        select(MonitoringPolicyRevision)
        .where(MonitoringPolicyRevision.policy_id == policy_id)
        .order_by(MonitoringPolicyRevision.version.desc())
        .limit(1)
    )


def _parse_checks(raw: list) -> list[CheckDefinition]:
    # Stored check sets were validated on write; re-validate on read so a
    # hand-edited or migrated row cannot inject an unparseable definition.
    return [CheckDefinition.model_validate(item) for item in raw or []]


async def _applicable_policies(
    db: AsyncSession, agent: Agent
) -> list[MonitoringPolicy]:
    """Enabled policies whose (scope, scope_id) targets this agent.

    The agent is reachable from four scope levels: global (all agents), its
    client (via its site), its site, and itself.
    """
    site = await db.get(Site, agent.site_id)
    client_id = site.client_id if site else None

    conditions = [MonitoringPolicy.scope == MonitoringScope.global_]
    if client_id is not None:
        conditions.append(
            (MonitoringPolicy.scope == MonitoringScope.client)
            & (MonitoringPolicy.scope_id == client_id)
        )
    conditions.append(
        (MonitoringPolicy.scope == MonitoringScope.site)
        & (MonitoringPolicy.scope_id == agent.site_id)
    )
    conditions.append(
        (MonitoringPolicy.scope == MonitoringScope.agent)
        & (MonitoringPolicy.scope_id == agent.id)
    )

    from sqlalchemy import or_

    result = await db.execute(
        select(MonitoringPolicy)
        .where(MonitoringPolicy.enabled.is_(True), or_(*conditions))
        # Stable order so a same-scope key conflict resolves deterministically:
        # later-created policy at the same scope wins.
        .order_by(MonitoringPolicy.created_at, MonitoringPolicy.id)
    )
    return list(result.scalars().all())


async def resolve_effective_policy(
    db: AsyncSession, agent: Agent
) -> list[EffectiveCheck]:
    """Merge all applicable policies into the agent's effective check set.

    Iterating in (precedence, created_at) order, each check key is overwritten
    by a more specific scope. A check marked ``enabled=false`` at a more
    specific scope *removes* the key — that is how an agent- or site-level
    policy opts out of a check its client or the global default would apply.
    """
    policies = await _applicable_policies(db, agent)
    policies.sort(key=lambda p: (_SCOPE_PRECEDENCE[p.scope], p.created_at, p.id))

    effective: dict[str, EffectiveCheck] = {}
    for policy in policies:
        revision = await current_revision(db, policy.id)
        if revision is None:
            continue
        for definition in _parse_checks(revision.checks):
            if not definition.enabled:
                # A disabled check at this (>=) scope suppresses the key.
                effective.pop(definition.key, None)
                continue
            effective[definition.key] = EffectiveCheck(
                definition=definition,
                source_scope=policy.scope,
                source_policy_id=policy.id,
                source_revision_id=revision.id,
                source_policy_name=policy.name,
            )
    # Deterministic output order by check key.
    return [effective[key] for key in sorted(effective)]


async def active_maintenance_windows(
    db: AsyncSession, agent: Agent, at: datetime | None = None
) -> list[MaintenanceWindow]:
    """Maintenance windows covering this agent that are open at ``at``.

    Provided as the seam #43/#44 will consult to suppress alerts; #41 does not
    itself suppress anything.
    """
    at = at or _now()
    site = await db.get(Site, agent.site_id)
    client_id = site.client_id if site else None

    from sqlalchemy import or_

    scope_match = [MaintenanceWindow.scope == MonitoringScope.global_]
    if client_id is not None:
        scope_match.append(
            (MaintenanceWindow.scope == MonitoringScope.client)
            & (MaintenanceWindow.scope_id == client_id)
        )
    scope_match.append(
        (MaintenanceWindow.scope == MonitoringScope.site)
        & (MaintenanceWindow.scope_id == agent.site_id)
    )
    scope_match.append(
        (MaintenanceWindow.scope == MonitoringScope.agent)
        & (MaintenanceWindow.scope_id == agent.id)
    )
    result = await db.execute(
        select(MaintenanceWindow).where(
            MaintenanceWindow.starts_at <= at,
            MaintenanceWindow.ends_at > at,
            or_(*scope_match),
        )
    )
    return list(result.scalars().all())


async def record_check_result(
    db: AsyncSession,
    *,
    agent_id: str,
    check_key: str,
    status: CheckResultStatus,
    value: float | None = None,
    detail: dict | None = None,
    evaluated_at: datetime | None = None,
    policy_id: str | None = None,
    policy_revision_id: str | None = None,
    result_id: str | None = None,
) -> CheckResult:
    """Append one check-result row. The caller owns the transaction/commit.

    Agent ingestion and server-owned offline evaluation both call this seam.
    """
    if not _CHECK_KEY_PATTERN.fullmatch(check_key):
        raise ValueError("check_key must be a lowercase slug up to 64 characters")
    if evaluated_at is not None and evaluated_at.tzinfo is None:
        raise ValueError("evaluated_at must include a timezone offset")
    if detail is not None:
        if not isinstance(detail, dict):
            raise ValueError("check result detail must be an object")
        try:
            encoded_detail = json.dumps(
                detail,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("check result detail must be finite JSON") from exc
        if len(encoded_detail) > MAX_CHECK_RESULT_DETAIL_BYTES:
            raise ValueError(
                f"check result detail exceeds {MAX_CHECK_RESULT_DETAIL_BYTES} bytes"
            )
    row = CheckResult(
        **({"id": result_id} if result_id is not None else {}),
        agent_id=agent_id,
        policy_id=policy_id,
        policy_revision_id=policy_revision_id,
        check_key=check_key,
        status=status,
        value=value,
        detail=detail,
        evaluated_at=evaluated_at or _now(),
    )
    db.add(row)
    await db.flush()
    return row


def classify_numeric(value: float, threshold: Threshold) -> CheckResultStatus:
    """Classify a finite sample, checking critical before warning."""

    def breached(bound: float | None) -> bool:
        if bound is None:
            return False
        return {
            ThresholdOp.gt: value > bound,
            ThresholdOp.gte: value >= bound,
            ThresholdOp.lt: value < bound,
            ThresholdOp.lte: value <= bound,
        }[threshold.op]

    if breached(threshold.critical):
        return CheckResultStatus.critical
    if breached(threshold.warning):
        return CheckResultStatus.warning
    return CheckResultStatus.ok


def _apply_hysteresis(
    raw: CheckResultStatus,
    definition: CheckDefinition,
    previous: CheckResult | None,
) -> tuple[CheckResultStatus, str | None, int]:
    """Return stable status plus the pending transition carried in detail."""
    if raw == CheckResultStatus.unknown:
        return raw, None, 0
    if previous is None:
        required = (
            definition.hysteresis.raise_samples
            if raw in {CheckResultStatus.warning, CheckResultStatus.critical}
            else 1
        )
        if required == 1:
            return raw, None, 0
        return CheckResultStatus.unknown, raw.value, 1

    current = previous.status
    if raw == current:
        return current, None, 0
    severity = {
        CheckResultStatus.unknown: -1,
        CheckResultStatus.ok: 0,
        CheckResultStatus.warning: 1,
        CheckResultStatus.critical: 2,
    }
    required = (
        definition.hysteresis.raise_samples
        if severity[raw] > severity[current]
        else definition.hysteresis.clear_samples
    )
    if current == CheckResultStatus.unknown and raw == CheckResultStatus.ok:
        required = 1
    prior_detail = previous.detail if isinstance(previous.detail, dict) else {}
    prior_hysteresis = prior_detail.get("hysteresis", {})
    pending_status = prior_hysteresis.get("pending_status")
    pending_count = int(prior_hysteresis.get("pending_count", 0) or 0)
    count = pending_count + 1 if pending_status == raw.value else 1
    if count >= required:
        return raw, None, 0
    return current, raw.value, count


async def evaluate_offline_checks(
    db: AsyncSession, agent: Agent, at: datetime | None = None
) -> int:
    """Evaluate due server-owned offline checks for one endpoint."""
    at = at or _now()
    written = 0
    for assignment in await resolve_effective_policy(db, agent):
        definition = assignment.definition
        if definition.type.value != "offline":
            continue
        previous = await db.scalar(
            select(CheckResult)
            .where(
                CheckResult.agent_id == agent.id,
                CheckResult.check_key == definition.key,
            )
            .order_by(CheckResult.evaluated_at.desc(), CheckResult.id.desc())
            .limit(1)
        )
        if previous is not None and (
            previous.policy_id != assignment.source_policy_id
            or previous.policy_revision_id != assignment.source_revision_id
        ):
            # A new revision may change thresholds, cadence, or hysteresis.
            # Never carry transition state or its due time across that boundary.
            previous = None
        if previous is not None:
            elapsed = (at - previous.evaluated_at.replace(
                tzinfo=previous.evaluated_at.tzinfo or timezone.utc
            )).total_seconds()
            if elapsed < definition.schedule.interval_seconds:
                continue

        if agent.last_seen_at is None:
            value = None
            raw = CheckResultStatus.unknown
            reason = "agent_has_never_checked_in"
        else:
            last_seen = agent.last_seen_at.replace(
                tzinfo=agent.last_seen_at.tzinfo or timezone.utc
            )
            value = max(0.0, (at - last_seen).total_seconds())
            raw = classify_numeric(value, definition.threshold)  # type: ignore[arg-type]
            reason = (
                "heartbeat_within_threshold"
                if raw == CheckResultStatus.ok
                else "heartbeat_overdue"
            )
        stable, pending_status, pending_count = _apply_hysteresis(
            raw, definition, previous
        )
        detail = {
            "check_type": "offline",
            "reason": reason,
            "raw_status": raw.value,
            "hysteresis": {
                "pending_status": pending_status,
                "pending_count": pending_count,
            },
        }
        await record_check_result(
            db,
            agent_id=agent.id,
            policy_id=assignment.source_policy_id,
            policy_revision_id=assignment.source_revision_id,
            check_key=definition.key,
            status=stable,
            value=value,
            detail=detail,
            evaluated_at=at,
        )
        written += 1
    return written


async def prune_check_results(db: AsyncSession, keep: int) -> int:
    """Keep the newest ``keep`` results per ``(agent_id, check_key)``.

    Mirrors inventory-history pruning: the newest row is the agent's current
    state for that check and is never a deletion candidate whatever ``keep`` is.
    """
    if keep <= 0:
        return 0
    groups = (
        await db.execute(
            select(
                CheckResult.agent_id,
                CheckResult.check_key,
                func.count().label("total"),
            )
            .group_by(CheckResult.agent_id, CheckResult.check_key)
            .having(func.count() > keep)
        )
    ).all()

    deleted = 0
    for agent_id, check_key, _total in groups:
        survivors = (
            select(CheckResult.id)
            .where(
                CheckResult.agent_id == agent_id,
                CheckResult.check_key == check_key,
            )
            .order_by(CheckResult.received_at.desc(), CheckResult.id.desc())
            .limit(keep)
        )
        keep_ids = [row[0] for row in (await db.execute(survivors)).all()]
        result = await db.execute(
            delete(CheckResult).where(
                CheckResult.agent_id == agent_id,
                CheckResult.check_key == check_key,
                CheckResult.id.not_in(keep_ids),
            ),
            execution_options={"synchronize_session": False},
        )
        deleted += result.rowcount or 0
    return deleted
