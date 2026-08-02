# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy resolution and check-result storage (issue #41).

Two responsibilities:

* :func:`resolve_effective_policy` computes the check set that actually applies
  to one agent by merging the policies at every scope level that targets it
  (global -> client -> site -> agent) with **most-specific-wins** per check key.
  This is the seam #42 will call before evaluating checks.
* :func:`record_check_result` / :func:`prune_check_results` persist and bound the
  check-result contract. #41 provides these and an operator read API; the agent
  ingestion route is #42.

Nothing here evaluates checks, raises alerts, or applies maintenance-window
suppression — those are #42/#43+.
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
from app.schemas.monitoring import CheckDefinition

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
) -> CheckResult:
    """Append one check-result row. The caller owns the transaction/commit.

    This is the storage seam #42's ingestion route will call; #41 exercises it
    directly from tests.
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
