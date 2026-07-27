# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded storage growth: retention pruning and observable capacity (issue #114).

Two responsibilities:

* :func:`prune_expired` bounds the two unbounded, high-volume data classes —
  telemetry heartbeats and captured command output — on a schedule. It is
  **audit-safe by construction**: it only ever deletes heartbeat rows and clears
  command stdout/stderr *text*; it never touches ``AuditEvent``, ``AuditAnchor``,
  or ``AnchorPublication``, so hash-chain and external-anchor verification remain
  reproducible over the full history. Command rows and their accountability
  metadata (exit code, truncation totals, timestamps) are preserved; only the
  heavy output text is dropped once it ages past retention.

* :func:`storage_status` reports per-class counts, oldest-age, backlog, host disk
  headroom, and unpublished-anchor lag, with threshold-breach flags an operator
  can alert on. It never mutates anything.

Retention that could break audit accountability is intentionally impossible
here: the pruners simply do not target audit tables.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import anchor_publish
from app.core.config import Settings, settings
from app.models.models import AuditEvent, Command, Heartbeat


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PruneResult:
    heartbeats_deleted: int
    command_outputs_cleared: int


async def prune_expired(
    db: AsyncSession, s: Settings = settings, now: datetime | None = None
) -> PruneResult:
    """Delete expired heartbeats and clear aged command output. Audit-safe.

    Caller owns the surrounding transaction/commit. A retention setting of 0 (or
    less) disables that class's pruning.
    """
    now = now or _now()
    heartbeats_deleted = 0
    command_outputs_cleared = 0

    # synchronize_session=False: these are bulk DML statements; we do not need
    # (and must not force) in-Python evaluation of the criteria against loaded
    # objects, which also avoids naive/aware datetime comparison on SQLite.
    if s.telemetry_retention_days > 0:
        cutoff = now - timedelta(days=s.telemetry_retention_days)
        res = await db.execute(
            delete(Heartbeat).where(Heartbeat.ts < cutoff),
            execution_options={"synchronize_session": False},
        )
        heartbeats_deleted = res.rowcount or 0

    if s.command_output_retention_days > 0:
        cutoff = now - timedelta(days=s.command_output_retention_days)
        res = await db.execute(
            update(Command)
            .where(
                Command.completed_at.is_not(None),
                Command.completed_at < cutoff,
                or_(Command.stdout.is_not(None), Command.stderr.is_not(None)),
            )
            .values(stdout=None, stderr=None),
            execution_options={"synchronize_session": False},
        )
        command_outputs_cleared = res.rowcount or 0

    return PruneResult(
        heartbeats_deleted=heartbeats_deleted,
        command_outputs_cleared=command_outputs_cleared,
    )


async def _age_seconds(db: AsyncSession, column) -> float | None:
    oldest = (await db.execute(select(func.min(column)))).scalar_one_or_none()
    if oldest is None:
        return None
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=timezone.utc)
    return (_now() - oldest).total_seconds()


async def storage_status(db: AsyncSession, s: Settings = settings) -> dict:
    """Observable capacity/backlog for every persistent data class, plus
    threshold-breach alert flags. Read-only."""
    heartbeat_count = (
        await db.execute(select(func.count()).select_from(Heartbeat))
    ).scalar_one()
    command_count = (
        await db.execute(select(func.count()).select_from(Command))
    ).scalar_one()
    command_output_count = (
        await db.execute(
            select(func.count())
            .select_from(Command)
            .where(or_(Command.stdout.is_not(None), Command.stderr.is_not(None)))
        )
    ).scalar_one()
    audit_count = (
        await db.execute(select(func.count()).select_from(AuditEvent))
    ).scalar_one()

    pub = await anchor_publish.publication_status(db, s)

    # Host disk headroom for logs/backups (and a local DB). A missing path is
    # reported rather than raised, so status never fails closed on this.
    disk_free = disk_total = None
    try:
        usage = shutil.disk_usage(s.retention_disk_path)
        disk_free, disk_total = usage.free, usage.total
    except OSError:
        pass

    heartbeat_alert = heartbeat_count > s.heartbeat_backlog_alert
    command_alert = command_count > s.command_backlog_alert
    disk_alert = disk_free is not None and disk_free < s.disk_free_alert_bytes
    anchor_alert = pub.lag_alert

    status = {
        "retention_policy": {
            "telemetry_retention_days": s.telemetry_retention_days,
            "command_output_retention_days": s.command_output_retention_days,
        },
        "heartbeats": {
            "count": heartbeat_count,
            "oldest_age_seconds": await _age_seconds(db, Heartbeat.ts),
            "backlog_alert": heartbeat_alert,
        },
        "commands": {
            "count": command_count,
            "with_output": command_output_count,
            "backlog_alert": command_alert,
        },
        "audit": {
            # Audit data is append-only and never pruned; exposed for capacity
            # planning, not for retention.
            "event_count": audit_count,
            "oldest_age_seconds": await _age_seconds(db, AuditEvent.ts),
        },
        "anchor_publication": {
            "backend": pub.backend,
            "pending": pub.pending,
            "oldest_unpublished_age_seconds": pub.oldest_unpublished_age_seconds,
            "lag_alert": anchor_alert,
        },
        "disk": {
            "path": s.retention_disk_path,
            "free_bytes": disk_free,
            "total_bytes": disk_total,
            "free_alert": disk_alert,
        },
    }
    status["alert"] = bool(
        heartbeat_alert or command_alert or disk_alert or anchor_alert
    )
    return status


# asdict is re-exported for callers that want the dataclass form of PruneResult.
__all__ = ["PruneResult", "prune_expired", "storage_status", "asdict"]
