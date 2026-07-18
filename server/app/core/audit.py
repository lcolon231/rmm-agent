# SPDX-License-Identifier: AGPL-3.0-only
"""Append-only, hash-chained audit log.

Each event stores `prev_hash` (the hash of the previous event in the chain) and
`event_hash` (the hash of this event's canonical content *including* prev_hash).
Because every event commits to its predecessor, altering or removing any event
breaks the chain from that point forward — which a periodic verifier will
detect. This is the local half of the dual-layer verifiable-audit design; the
`event_hash` values are what you'd batch and anchor externally.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditEvent

_GENESIS = "0" * 64


def _hash_event(prev_hash: str, ts_iso: str, actor: str, action: str,
                agent_id: str | None, detail: dict) -> str:
    doc = {
        "prev_hash": prev_hash,
        "ts": ts_iso,
        "actor": actor,
        "action": action,
        "agent_id": agent_id,
        "detail": detail,
    }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


async def _latest_hash(db: AsyncSession) -> str:
    result = await db.execute(
        select(AuditEvent.event_hash).order_by(AuditEvent.ts.desc()).limit(1)
    )
    row = result.scalar_one_or_none()
    return row or _GENESIS


async def record(
    db: AsyncSession,
    *,
    action: str,
    actor: str = "system",
    agent_id: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Append a new audit event to the chain. Caller is responsible for the
    surrounding transaction/commit."""
    detail = detail or {}
    prev = await _latest_hash(db)
    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat()
    event = AuditEvent(
        ts=ts,
        ts_iso=ts_iso,
        actor=actor,
        action=action,
        agent_id=agent_id,
        detail=detail,
        prev_hash=prev,
    )
    event.event_hash = _hash_event(
        prev, ts_iso, actor, action, agent_id, detail
    )
    db.add(event)
    await db.flush()  # assign event.id
    return event


async def verify_chain(db: AsyncSession) -> tuple[bool, str | None]:
    """Walk the chain oldest→newest and confirm every link. Returns
    (ok, first_broken_event_id)."""
    result = await db.execute(select(AuditEvent).order_by(AuditEvent.ts.asc()))
    events = result.scalars().all()
    prev = _GENESIS
    for ev in events:
        if ev.prev_hash != prev:
            return False, ev.id
        expected = _hash_event(
            ev.prev_hash, ev.ts_iso, ev.actor, ev.action,
            ev.agent_id, ev.detail,
        )
        if expected != ev.event_hash:
            return False, ev.id
        prev = ev.event_hash
    return True, None
