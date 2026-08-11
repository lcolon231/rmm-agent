# SPDX-License-Identifier: AGPL-3.0-only
"""Patch compliance computation (issue #54).

Read-only aggregation over data that already exists: an endpoint's effective
patch approval policy (#52/#53) and its latest scanned Windows Update inventory.
No new storage — every value is derived on demand.

An endpoint is **non_compliant** when any update its effective policy *approves*
is still missing; deferred/denied-missing updates are intentionally not required
and do not count against it. Precedence of the reported state:

  exempt   — no effective policy applies (patch policies are opt-in)
  unknown  — never scanned, or the scan could not be trusted
  stale    — scanned, but older than the staleness threshold
  non_compliant — a fresh scan with at least one approved-but-missing update
  compliant     — a fresh scan with no approved-but-missing update
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import inventory
from app.core.patch_policies import (
    evaluate_update,
    parse_rules,
    resolve_effective_patch_policy,
)
from app.models.models import Agent, AgentInventorySnapshot, Client, Site
from app.schemas.inventory import InventorySection

STATE_COMPLIANT = "compliant"
STATE_NON_COMPLIANT = "non_compliant"
STATE_STALE = "stale"
STATE_UNKNOWN = "unknown"
STATE_EXEMPT = "exempt"

COMPLIANCE_STATES = (
    STATE_COMPLIANT,
    STATE_NON_COMPLIANT,
    STATE_STALE,
    STATE_UNKNOWN,
    STATE_EXEMPT,
)

# Section statuses whose missing[] list is meaningful for evaluation.
_USABLE_STATUSES = {"ok", "partial"}


@dataclass(frozen=True)
class EndpointCompliance:
    agent_id: str
    hostname: str
    site_id: str
    site_name: str
    client_id: str
    client_name: str
    state: str
    policy_id: str | None
    scanned_at: datetime | None
    total_missing: int
    approved_missing: int
    deferred_missing: int
    denied_missing: int


@dataclass(frozen=True)
class ComplianceSummary:
    total_endpoints: int
    compliant: int
    non_compliant: int
    stale: int
    unknown: int
    exempt: int
    total_approved_missing: int
    truncated: bool


@dataclass(frozen=True)
class HistoryPoint:
    scanned_at: datetime | None
    received_at: datetime
    total_missing: int
    approved_missing: int


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _parse_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, str):
        try:
            return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _scan_datetime(snapshot: AgentInventorySnapshot | None) -> datetime | None:
    if snapshot is None:
        return None
    payload = snapshot.payload or {}
    return _parse_dt(payload.get("scanned_at")) or _utc(snapshot.collected_at)


def _tally(rules, default_action: str, missing: list[dict], now: datetime) -> tuple[int, int, int]:
    approved = deferred = denied = 0
    for item in missing:
        decision = evaluate_update(rules, default_action, item, now).decision
        if decision == "approve":
            approved += 1
        elif decision == "defer":
            deferred += 1
        else:
            denied += 1
    return approved, deferred, denied


def _missing_rows(snapshot: AgentInventorySnapshot) -> list[dict]:
    payload = snapshot.payload or {}
    rows = payload.get("missing")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _usable(snapshot: AgentInventorySnapshot) -> bool:
    payload = snapshot.payload or {}
    return snapshot.status in _USABLE_STATUSES and not payload.get("error_code")


async def endpoint_compliance(
    db: AsyncSession,
    agent: Agent,
    now: datetime,
    *,
    stale_after: timedelta,
    site: Site | None = None,
    client: Client | None = None,
) -> EndpointCompliance:
    """Compute one endpoint's compliance. ``site``/``client`` may be supplied to
    avoid per-agent lookups when iterating a scope."""
    if site is None:
        site = await db.get(Site, agent.site_id)
    if client is None and site is not None:
        client = await db.get(Client, site.client_id)
    identity = dict(
        agent_id=agent.id,
        hostname=agent.hostname,
        site_id=site.id if site else agent.site_id,
        site_name=site.name if site else "",
        client_id=client.id if client else "",
        client_name=client.name if client else "",
    )

    effective = await resolve_effective_patch_policy(db, agent)
    if effective is None:
        return EndpointCompliance(
            **identity, state=STATE_EXEMPT, policy_id=None, scanned_at=None,
            total_missing=0, approved_missing=0, deferred_missing=0, denied_missing=0,
        )

    sections = await inventory.latest_sections(db, agent.id)
    snapshot = sections.get(InventorySection.windows_updates.value)
    policy_id = effective.policy.id

    if snapshot is None or not _usable(snapshot):
        return EndpointCompliance(
            **identity, state=STATE_UNKNOWN, policy_id=policy_id,
            scanned_at=_scan_datetime(snapshot), total_missing=0,
            approved_missing=0, deferred_missing=0, denied_missing=0,
        )

    missing = _missing_rows(snapshot)
    rules = parse_rules(effective.revision.rules)
    approved, deferred, denied = _tally(rules, effective.revision.default_action, missing, now)
    scanned_at = _scan_datetime(snapshot)

    if scanned_at is None or now - scanned_at > stale_after:
        state = STATE_STALE
    elif approved > 0:
        state = STATE_NON_COMPLIANT
    else:
        state = STATE_COMPLIANT

    return EndpointCompliance(
        **identity, state=state, policy_id=policy_id, scanned_at=scanned_at,
        total_missing=len(missing), approved_missing=approved,
        deferred_missing=deferred, denied_missing=denied,
    )


def summarize(rows: list[EndpointCompliance], *, truncated: bool) -> ComplianceSummary:
    counts = {state: 0 for state in COMPLIANCE_STATES}
    total_approved = 0
    for row in rows:
        counts[row.state] += 1
        total_approved += row.approved_missing
    return ComplianceSummary(
        total_endpoints=len(rows),
        compliant=counts[STATE_COMPLIANT],
        non_compliant=counts[STATE_NON_COMPLIANT],
        stale=counts[STATE_STALE],
        unknown=counts[STATE_UNKNOWN],
        exempt=counts[STATE_EXEMPT],
        total_approved_missing=total_approved,
        truncated=truncated,
    )


async def endpoint_history(
    db: AsyncSession, agent: Agent, now: datetime, limit: int
) -> list[HistoryPoint]:
    """A per-endpoint approved-missing time-series over the retained Windows Update
    snapshots, evaluated against the CURRENT effective policy (labelled as such in
    the API). Newest first."""
    effective = await resolve_effective_patch_policy(db, agent)
    rules = parse_rules(effective.revision.rules) if effective else []
    default_action = effective.revision.default_action if effective else "deny"
    snapshots = (
        await db.execute(
            select(AgentInventorySnapshot)
            .where(
                AgentInventorySnapshot.agent_id == agent.id,
                AgentInventorySnapshot.section == InventorySection.windows_updates.value,
            )
            .order_by(
                AgentInventorySnapshot.received_at.desc(),
                AgentInventorySnapshot.id.desc(),
            )
            .limit(limit)
        )
    ).scalars().all()

    points: list[HistoryPoint] = []
    for snapshot in snapshots:
        missing = _missing_rows(snapshot) if _usable(snapshot) else []
        approved = 0
        if effective is not None and missing:
            approved, _, _ = _tally(rules, default_action, missing, now)
        points.append(
            HistoryPoint(
                scanned_at=_scan_datetime(snapshot),
                received_at=_utc(snapshot.received_at),
                total_missing=len(missing),
                approved_missing=approved,
            )
        )
    return points
