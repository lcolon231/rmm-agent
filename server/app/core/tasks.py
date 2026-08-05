# SPDX-License-Identifier: AGPL-3.0-only
"""Background maintenance tasks."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core import audit, metrics, monitoring
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.models import Agent, AgentStatus, AgentTrustState


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
        active_agents = (
            await db.execute(
                select(Agent).where(Agent.trust_state == AgentTrustState.active)
            )
        ).scalars().all()
        evaluated = 0
        for agent in active_agents:
            evaluated += await monitoring.evaluate_offline_checks(db, agent)
        metrics.increment("monitoring_offline_evaluation_total", evaluated)
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


async def _retention_once() -> None:
    """Prune expired telemetry and command output, then log a warning if any
    storage class has breached its observability threshold (issue #114)."""
    from app.core import retention

    async with AsyncSessionLocal() as db:
        result = await retention.prune_expired(db, settings)
        await db.commit()
        status = await retention.storage_status(db, settings)
    if result.heartbeats_deleted or result.command_outputs_cleared:
        print(
            f"[retention] pruned {result.heartbeats_deleted} heartbeat(s), "
            f"cleared output on {result.command_outputs_cleared} command(s)"
        )
    if status["alert"]:
        print(f"[retention] WARNING storage threshold breached: {status}")


async def retention_sweeper(stop: asyncio.Event) -> None:
    """Bound storage growth on a schedule. Audit-safe: only telemetry and aged
    command output are pruned; audit events and anchors are never touched."""
    interval = settings.retention_sweep_interval_seconds
    while not stop.is_set():
        try:
            await _retention_once()
        except Exception as exc:  # keep the loop alive on transient DB errors
            print(f"[retention] error: {exc}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def email_alert_sender(stop: asyncio.Event) -> None:
    """Deliver durable alert emails without coupling provider health to alerts."""
    from app.core import email_notifications

    config_status = email_notifications.configuration_status(settings)
    if not config_status["enabled"]:
        return
    if not config_status["valid"]:
        print("[email_alert_sender] WARNING invalid email configuration; sender disabled")
        return
    interval = settings.email_alert_poll_interval_seconds
    while not stop.is_set():
        try:
            result = await email_notifications.process_due_deliveries(settings)
            if result.failed:
                print(
                    "[email_alert_sender] WARNING "
                    f"{result.failed} delivery attempt(s) exhausted or failed permanently"
                )
        except Exception as exc:  # keep the loop alive; never expose provider detail
            print(f"[email_alert_sender] error: {type(exc).__name__}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def webhook_sender(stop: asyncio.Event) -> None:
    """Deliver signed webhooks without coupling destinations to alert writes."""
    from app.core import webhook_notifications

    interval = settings.webhook_poll_interval_seconds
    while not stop.is_set():
        try:
            result = await webhook_notifications.process_due_deliveries(settings)
            if result.failed:
                print(
                    "[webhook_sender] WARNING "
                    f"{result.failed} delivery attempt(s) exhausted or failed permanently"
                )
        except Exception as exc:
            print(f"[webhook_sender] error: {type(exc).__name__}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


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
