# SPDX-License-Identifier: AGPL-3.0-only
"""Background maintenance tasks."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core import audit
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.models import Agent, AgentStatus


async def _sweep_once() -> None:
    """Flag agents that have missed too many heartbeats as offline, and emit an
    audit event for each transition."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.offline_threshold_seconds
    )
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Agent).where(
                Agent.status == AgentStatus.online,
                Agent.last_seen_at < cutoff,
            )
        )
        for agent in result.scalars().all():
            last_seen = agent.last_seen_at
            if last_seen is not None and last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            agent.status = AgentStatus.offline
            await audit.record(
                db,
                action="agent.offline",
                actor="system",
                agent_id=agent.id,
                detail={"last_seen_at": last_seen.isoformat() if last_seen else None},
            )
        await db.commit()


async def offline_sweeper(stop: asyncio.Event) -> None:
    """Run the offline sweep on the heartbeat cadence until told to stop."""
    interval = settings.heartbeat_interval_seconds
    while not stop.is_set():
        try:
            await _sweep_once()
        except Exception as exc:  # keep the loop alive on transient DB errors
            print(f"[offline_sweeper] error: {exc}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def _publish_once() -> None:
    from app.core import anchor_publish

    backend = anchor_publish.build_publisher(settings)
    if backend is None:
        return
    async with AsyncSessionLocal() as db:
        await anchor_publish.ensure_current_anchor(db)
        await anchor_publish.publish_pending(db, backend)
        status = await anchor_publish.publication_status(db)
        await db.commit()
    if status.lag_alert:
        age = status.oldest_unpublished_age_seconds
        print(
            f"[anchor_publisher] WARNING publication lag: {status.pending} anchor(s) "
            f"unpublished, oldest {age:.0f}s old"
            + (f"; last error: {status.last_error}" if status.last_error else "")
        )


async def anchor_publisher(stop: asyncio.Event) -> None:
    """Create and externally publish audit anchors on a schedule.

    Publication is opt-in: with no backend configured this logs a warning in
    production (so the gap is visible) and otherwise does nothing.
    """
    from app.core.anchor_publish import build_publisher
    from app.core.prodcheck import is_production

    if build_publisher(settings) is None:
        if is_production(settings):
            print(
                "[anchor_publisher] WARNING no anchor_publish_backend configured; "
                "audit anchors are NOT externally published and a database-owning "
                "attacker could rewrite history undetected (issue #76)"
            )
        return

    interval = settings.anchor_publish_interval_seconds
    while not stop.is_set():
        try:
            await _publish_once()
        except Exception as exc:  # keep the loop alive on transient errors
            print(f"[anchor_publisher] error: {exc}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
