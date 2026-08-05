# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy resolution, evaluation, result storage, and alert state.

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
* :func:`apply_check_result_to_alert` serializes one durable alert identity per
  policy/endpoint/check, including recovery, retrigger, suppression,
  exactly-once observation evidence, and immutable lifecycle history (#43/#44).

Offline checks are evaluated here because an unreachable endpoint cannot report
itself. Technician actions live at the authenticated management boundary.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import email_notifications, metrics, webhook_notifications
from app.models.models import (
    Agent,
    Alert,
    AlertEvent,
    AlertEventType,
    AlertObservation,
    AlertState,
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


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def _append_alert_event(
    db: AsyncSession,
    alert: Alert,
    event_type: AlertEventType,
    *,
    from_state: AlertState | None,
    to_state: AlertState | None,
    source_result_id: str | None = None,
    at: datetime | None = None,
) -> None:
    """Append system-owned lifecycle evidence inside the caller's transaction."""
    event = AlertEvent(
        id=str(uuid.uuid4()),
        alert_id=alert.id,
        generation=alert.generation,
        event_type=event_type,
        from_state=from_state,
        to_state=to_state,
        actor="system",
        source_result_id=source_result_id,
        created_at=at or _now(),
    )
    db.add(event)
    email_notifications.enqueue_alert_event(db, alert, event)
    await webhook_notifications.enqueue_alert_event(db, alert, event)


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


async def _resolve_superseded_alerts(
    db: AsyncSession, result: CheckResult
) -> int:
    """Resolve another policy's active alert for the same endpoint/check."""
    alerts = list(
        (
            await db.execute(
                select(Alert).where(
            Alert.agent_id == result.agent_id,
            Alert.check_key == result.check_key,
            Alert.policy_id != result.policy_id,
            Alert.state != AlertState.resolved,
                ).with_for_update()
            )
        ).scalars().all()
    )
    for alert in alerts:
        previous = alert.state
        alert.state = AlertState.resolved
        alert.resolved_at = result.evaluated_at
        alert.resolution_reason = "policy_superseded"
        alert.suppression_window_id = None
        alert.suppressed_until = None
        alert.version += 1
        alert.updated_at = _now()
        await _append_alert_event(
            db,
            alert,
            AlertEventType.policy_superseded,
            from_state=previous,
            to_state=AlertState.resolved,
            at=result.evaluated_at,
        )
    changed = len(alerts)
    if changed:
        metrics.increment("monitoring_alert_recovered_total", changed)
        metrics.increment("monitoring_alert_policy_superseded_total", changed)
    return changed


async def _ensure_alert_shell(db: AsyncSession, result: CheckResult) -> None:
    """Insert the identity row once; concurrent evaluators may race safely."""
    now = _now()
    values = {
        "id": str(uuid.uuid4()),
        "agent_id": result.agent_id,
        "policy_id": result.policy_id,
        "policy_revision_id": result.policy_revision_id,
        "check_key": result.check_key,
        "state": AlertState.resolved,
        "last_result_status": result.status,
        "occurrence_count": 0,
        "total_occurrence_count": 0,
        "generation": 0,
        "created_at": now,
        "updated_at": now,
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgresql_insert(Alert).values(**values).on_conflict_do_nothing(
            constraint="ux_alert_identity"
        )
    elif dialect == "sqlite":
        statement = sqlite_insert(Alert).values(**values).on_conflict_do_nothing(
            index_elements=["agent_id", "policy_id", "check_key"]
        )
    else:  # pragma: no cover - supported deployments are PostgreSQL/SQLite tests
        raise RuntimeError(f"unsupported alert upsert dialect: {dialect}")
    await db.execute(statement)


async def _record_alert_observation(
    db: AsyncSession, alert: Alert, result: CheckResult
) -> bool:
    """Record a result once. Return false when it was already applied."""
    values = {
        "check_result_id": result.id,
        "alert_id": alert.id,
        "status": result.status,
        "value": result.value,
        "evaluated_at": result.evaluated_at,
        "out_of_order": False,
        "created_at": _now(),
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(AlertObservation)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["check_result_id"])
        )
    elif dialect == "sqlite":
        statement = (
            sqlite_insert(AlertObservation)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["check_result_id"])
        )
    else:  # pragma: no cover
        raise RuntimeError(f"unsupported alert observation dialect: {dialect}")
    return ((await db.execute(statement)).rowcount or 0) == 1


async def apply_check_result_to_alert(
    db: AsyncSession, result: CheckResult
) -> Alert | None:
    """Apply one revision-pinned result to its deduplicated alert identity.

    PostgreSQL row locking serializes concurrent results for the same identity.
    A deterministic ``(evaluated_at, result_id)`` order prevents a delayed older
    result from recovering or downgrading newer state. Results without policy
    provenance are historical/test seam rows and intentionally do not alert.
    """
    if result.policy_id is None or result.policy_revision_id is None:
        return None

    await _resolve_superseded_alerts(db, result)
    failing = result.status != CheckResultStatus.ok
    if failing:
        await _ensure_alert_shell(db, result)

    alert = await db.scalar(
        select(Alert)
        .where(
            Alert.agent_id == result.agent_id,
            Alert.policy_id == result.policy_id,
            Alert.check_key == result.check_key,
        )
        .with_for_update()
    )
    if alert is None:
        return None

    if not await _record_alert_observation(db, alert, result):
        metrics.increment("monitoring_alert_duplicate_observation_total")
        return alert

    evaluated_at = _utc(result.evaluated_at)
    if alert.last_evaluated_at is not None:
        prior_order = (_utc(alert.last_evaluated_at), alert.last_result_id or "")
        if (evaluated_at, result.id) <= prior_order:
            await db.execute(
                update(AlertObservation)
                .where(AlertObservation.check_result_id == result.id)
                .values(out_of_order=True)
            )
            if failing:
                alert.total_occurrence_count += 1
                if (
                    alert.state != AlertState.resolved
                    and alert.opened_at is not None
                    and evaluated_at >= _utc(alert.opened_at)
                ):
                    alert.occurrence_count += 1
                metrics.increment("monitoring_alert_occurrence_total")
            metrics.increment("monitoring_alert_out_of_order_total")
            return alert

    alert.policy_revision_id = result.policy_revision_id
    alert.last_result_status = result.status
    alert.last_evaluated_at = evaluated_at
    alert.last_result_id = result.id
    alert.last_value = result.value
    alert.updated_at = _now()

    if not failing:
        alert.suppression_window_id = None
        alert.suppressed_until = None
        if alert.state != AlertState.resolved:
            previous = alert.state
            alert.state = AlertState.resolved
            alert.resolved_at = evaluated_at
            alert.resolution_reason = "automatic_recovery"
            alert.version += 1
            await _append_alert_event(
                db,
                alert,
                AlertEventType.automatic_recovery,
                from_state=previous,
                to_state=AlertState.resolved,
                source_result_id=result.id,
                at=evaluated_at,
            )
            metrics.increment("monitoring_alert_recovered_total")
        return alert

    agent = await db.get(Agent, result.agent_id)
    if agent is None:  # The result FK makes this unreachable in a valid DB.
        raise ValueError("alert result agent does not exist")
    windows = await active_maintenance_windows(db, agent, evaluated_at)
    if windows:
        latest_window = max(windows, key=lambda item: _utc(item.ends_at))
        alert.suppression_window_id = latest_window.id
        alert.suppressed_until = latest_window.ends_at
        metrics.increment("monitoring_alert_suppressed_occurrence_total")
    else:
        alert.suppression_window_id = None
        alert.suppressed_until = None

    alert.last_observed_at = evaluated_at
    alert.total_occurrence_count += 1
    if alert.state == AlertState.resolved:
        first_open = alert.generation == 0
        previous = alert.state
        alert.state = AlertState.open
        alert.generation += 1
        alert.occurrence_count = 1
        alert.opened_at = evaluated_at
        alert.resolved_at = None
        alert.resolution_reason = None
        if alert.first_opened_at is None:
            alert.first_opened_at = evaluated_at
        alert.acknowledged_at = None
        alert.acknowledged_by = None
        alert.version += 1
        await _append_alert_event(
            db,
            alert,
            AlertEventType.opened if first_open else AlertEventType.reopened,
            from_state=previous,
            to_state=AlertState.open,
            source_result_id=result.id,
            at=evaluated_at,
        )
        metrics.increment(
            "monitoring_alert_opened_total"
            if first_open
            else "monitoring_alert_reopened_total"
        )
    else:
        alert.occurrence_count += 1
    metrics.increment("monitoring_alert_occurrence_total")
    return alert


async def resolve_policy_alerts(
    db: AsyncSession,
    policy_id: str,
    *,
    active_check_keys: set[str] | None = None,
    reason: str,
    at: datetime | None = None,
) -> int:
    """Resolve active alerts invalidated by a policy revision or deletion."""
    at = at or _now()
    conditions = [
        Alert.policy_id == policy_id,
        Alert.state != AlertState.resolved,
    ]
    if active_check_keys:
        conditions.append(Alert.check_key.not_in(active_check_keys))
    alerts = list(
        (
            await db.execute(select(Alert).where(*conditions).with_for_update())
        ).scalars().all()
    )
    event_type = {
        "policy_revised": AlertEventType.policy_revised,
        "policy_deleted": AlertEventType.policy_deleted,
    }.get(reason, AlertEventType.policy_superseded)
    for alert in alerts:
        previous = alert.state
        alert.state = AlertState.resolved
        alert.resolved_at = at
        alert.resolution_reason = reason
        alert.suppression_window_id = None
        alert.suppressed_until = None
        alert.version += 1
        alert.updated_at = _now()
        await _append_alert_event(
            db,
            alert,
            event_type,
            from_state=previous,
            to_state=AlertState.resolved,
            at=at,
        )
    changed = len(alerts)
    if changed:
        metrics.increment("monitoring_alert_recovered_total", changed)
        metrics.increment("monitoring_alert_policy_change_total", changed)
    return changed


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
    await apply_check_result_to_alert(db, row)
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
        doomed_ids = select(CheckResult.id).where(
            CheckResult.agent_id == agent_id,
            CheckResult.check_key == check_key,
            CheckResult.id.not_in(keep_ids),
        )
        # PostgreSQL enforces the observation FK cascade. Delete explicitly as
        # well so SQLite tests and any non-enforcing maintenance connection
        # preserve the same bounded-storage contract.
        await db.execute(
            delete(AlertObservation).where(
                AlertObservation.check_result_id.in_(doomed_ids)
            ),
            execution_options={"synchronize_session": False},
        )
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
