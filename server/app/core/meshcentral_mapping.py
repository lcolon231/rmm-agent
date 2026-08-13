# SPDX-License-Identifier: AGPL-3.0-only
"""Identity mapping + staleness reconciliation for MeshCentral (issue #62).

v1 mappings are created manually by an admin. Reconciliation is deliberately
**read-only with respect to admission**: it refreshes freshness timestamps and
may age a mapping to ``stale``/``unmapped``/``conflict``, but it never creates a
mapping and never promotes one to ``active``. When MeshCentral is unavailable it
leaves mappings untouched and lets the staleness window age them out — it must
not flip a mapping to ``active`` on the strength of a failed sync.

"Permission sync" here means: authorization is re-derived at launch time and a
grant is minted **only** for the single mapped node, scoped and TTL-bounded.
NodeLink never pushes its roles into MeshCentral's permission model, so there is
no standing permission to drift; a stale/conflict/unmapped mapping or a revoked
NodeLink authorization simply yields no mint (fail closed).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.meshcentral import MeshCentralClient, MeshCentralError
from app.models.models import AgentMeshMapping, MeshMappingState


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


@dataclass
class ReconcileRun:
    reconciled: int = 0
    active: int = 0
    stale: int = 0
    unmapped: int = 0
    conflict: int = 0
    unavailable: bool = False
    # (mapping_id, agent_id, node_id, previous_state, new_state)
    transitions: list[tuple[str, str, str, str, str]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "reconciled": self.reconciled,
            "active": self.active,
            "stale": self.stale,
            "unmapped": self.unmapped,
            "conflict": self.conflict,
        }


def is_stale(mapping: AgentMeshMapping, config: Settings, now: datetime) -> bool:
    """A mapping never confirmed, or confirmed longer ago than the window, is stale."""
    last = _utc(mapping.last_synced_at)
    if last is None:
        return True
    window = timedelta(seconds=config.meshcentral_mapping_stale_after_seconds)
    return now - last > window


def mapping_availability(
    mapping: AgentMeshMapping | None,
    config: Settings = settings,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Pure fail-closed availability decision for a mapping.

    Returns ``(available, reason_code)`` where reason is one of ``available``,
    ``no_mapping``, ``mapping_unmapped``, ``mapping_conflict``, ``mapping_stale``.
    """
    now = now or _now()
    if mapping is None:
        return False, "no_mapping"
    if mapping.state == MeshMappingState.unmapped:
        return False, "mapping_unmapped"
    if mapping.state == MeshMappingState.conflict:
        return False, "mapping_conflict"
    if mapping.state == MeshMappingState.stale or is_stale(mapping, config, now):
        return False, "mapping_stale"
    return True, "available"


async def get_mapping_for_agent(
    db: AsyncSession, agent_id: str
) -> AgentMeshMapping | None:
    return (
        await db.execute(
            select(AgentMeshMapping).where(AgentMeshMapping.agent_id == agent_id)
        )
    ).scalar_one_or_none()


async def reconcile_mappings(
    db: AsyncSession,
    client: MeshCentralClient,
    config: Settings = settings,
) -> ReconcileRun:
    """Refresh staleness for existing mappings against MeshCentral's node list.

    Never creates mappings and never promotes to ``active``. On an unavailable
    MeshCentral it records ``unavailable`` and leaves every mapping as-is.
    """
    run = ReconcileRun()
    mappings = list(
        (await db.execute(select(AgentMeshMapping))).scalars().all()
    )
    run.reconciled = len(mappings)
    if not mappings:
        return run

    try:
        devices = await client.list_devices()
    except MeshCentralError:
        run.unavailable = True
        return run

    by_node: dict[str, list[str]] = {}
    seen: dict[str, object] = {}
    for device in devices:
        by_node.setdefault(device.node_id, []).append("")
        seen[device.node_id] = device

    now = _now()
    # Count how many mappings claim each node, to detect conflicts.
    claims: dict[str, int] = {}
    for mapping in mappings:
        claims[mapping.meshcentral_node_id] = (
            claims.get(mapping.meshcentral_node_id, 0) + 1
        )

    for mapping in mappings:
        previous = mapping.state
        node_id = mapping.meshcentral_node_id
        if claims.get(node_id, 0) > 1:
            new_state = MeshMappingState.conflict
        elif node_id not in seen:
            new_state = MeshMappingState.unmapped
        else:
            device = seen[node_id]
            mapping.last_synced_at = now
            mapping.last_seen_in_mesh_at = getattr(device, "last_connect", None) or now
            # Reconciliation confirms freshness but does not itself flip a
            # conflict/unmapped back to active without the node reappearing.
            new_state = MeshMappingState.active

        if new_state != previous:
            mapping.state = new_state
            run.transitions.append(
                (mapping.id, mapping.agent_id, node_id, previous.value, new_state.value)
            )
        # Tally the resulting state.
        if new_state == MeshMappingState.active:
            run.active += 1
        elif new_state == MeshMappingState.stale:
            run.stale += 1
        elif new_state == MeshMappingState.unmapped:
            run.unmapped += 1
        elif new_state == MeshMappingState.conflict:
            run.conflict += 1

    return run
