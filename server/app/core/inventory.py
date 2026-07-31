# SPDX-License-Identifier: AGPL-3.0-only
"""Inventory snapshot storage and refresh negotiation (issue #35).

The agent advertises a per-section content hash on every heartbeat; this module
decides which sections are worth asking for, and stores what comes back. A
section is only persisted when its content actually changed, so the table is
both the current state and the change history that #40 renders as diffs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AgentInventorySnapshot
from app.schemas.inventory import InventorySection

#: How long a stored section stays fresh. Hardware changes rarely, and the hash
#: comparison already catches every change an agent notices; this interval only
#: bounds how long a *missed* change can hide — for example a section collected
#: while a server was mid-rollout, or an agent whose local cache was lost.
INVENTORY_REFRESH_INTERVAL = timedelta(hours=24)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def latest_sections(
    db: AsyncSession, agent_id: str
) -> dict[str, AgentInventorySnapshot]:
    """The newest stored snapshot per section for one agent."""
    newest = (
        select(
            AgentInventorySnapshot.section,
            func.max(AgentInventorySnapshot.received_at).label("received_at"),
        )
        .where(AgentInventorySnapshot.agent_id == agent_id)
        .group_by(AgentInventorySnapshot.section)
        .subquery()
    )
    rows = (
        await db.execute(
            select(AgentInventorySnapshot)
            .join(
                newest,
                (AgentInventorySnapshot.section == newest.c.section)
                & (AgentInventorySnapshot.received_at == newest.c.received_at),
            )
            .where(AgentInventorySnapshot.agent_id == agent_id)
        )
    ).scalars().all()
    # A tie on received_at (same-instant inserts for one section) would yield
    # two rows; keep the later id so the result is deterministic either way.
    latest: dict[str, AgentInventorySnapshot] = {}
    for row in rows:
        current = latest.get(row.section)
        if current is None or row.id > current.id:
            latest[row.section] = row
    return latest


def sections_to_request(
    stored: dict[str, AgentInventorySnapshot],
    advertised: dict[str, str],
    now: datetime | None = None,
) -> list[str]:
    """Which sections the agent should resend.

    A section is requested when the agent advertises a hash we do not hold,
    when we hold nothing for it, or when what we hold has gone stale. Sections
    the agent does not advertise are never requested: the agent is the only
    party that knows what it can collect, so asking for a section it cannot
    produce would loop forever.
    """
    now = now or _now()
    requested: list[str] = []
    for section in InventorySection:
        name = section.value
        advertised_hash = advertised.get(name)
        if advertised_hash is None:
            continue
        current = stored.get(name)
        if current is None or current.content_hash != advertised_hash:
            requested.append(name)
            continue
        received_at = current.received_at
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)
        if now - received_at >= INVENTORY_REFRESH_INTERVAL:
            requested.append(name)
    return requested


async def store_section(
    db: AsyncSession,
    *,
    agent_id: str,
    section: str,
    status: str,
    schema_version: int,
    payload: dict,
    content_hash: str,
    byte_size: int,
    collected_at: datetime,
) -> AgentInventorySnapshot | None:
    """Persist one section, or return None when nothing changed.

    Dedup is by content hash against the newest stored row for the section, so
    a re-reported identical section costs one comparison and no storage. The
    status is part of the comparison: a section that degrades from ``ok`` to
    ``unavailable`` with an unchanged payload is a real change a technician
    needs to see.
    """
    stored = (await latest_sections(db, agent_id)).get(section)
    if (
        stored is not None
        and stored.content_hash == content_hash
        and stored.status == status
        and stored.schema_version == schema_version
    ):
        return None

    snapshot = AgentInventorySnapshot(
        agent_id=agent_id,
        section=section,
        status=status,
        schema_version=schema_version,
        content_hash=content_hash,
        byte_size=byte_size,
        payload=payload,
        collected_at=collected_at,
        received_at=_now(),
    )
    db.add(snapshot)
    await db.flush()
    return snapshot
