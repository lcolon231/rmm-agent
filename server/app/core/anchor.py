# SPDX-License-Identifier: AGPL-3.0-only
"""Merkle anchoring of the audit chain.

The hash chain in `audit.py` proves internal consistency: you cannot alter one
event without breaking every link after it. What it cannot prove is that the
WHOLE chain wasn't quietly rebuilt by someone with database access. Anchoring
closes that: periodically commit to the chain's current state with a Merkle
root over all `event_hash` values and publish that root OUTSIDE the system.
Once a root exists externally, no rewrite of the covered prefix — however
consistent — can escape detection, because the recomputed root won't match.

This module computes and verifies the roots. Publishing them is deliberately
out of scope: the root is a 64-char hex string; put it wherever your threat
model demands (transparency log, on-chain, printed in the monthly compliance
report). See docs/threat-model.md.

Merkle construction (documented so external verifiers can reimplement it):
leaves are the `event_hash` values, hex-decoded, of the first `event_count`
events in (ts, id) order. Each level pairs nodes left to right and hashes
SHA-256(left || right); an unpaired trailing node is carried up unchanged.
The root of a single leaf is the leaf itself.
"""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditAnchor, AuditEvent


def merkle_root(leaf_hashes: list[str]) -> str:
    """Fold hex-encoded leaves into a single hex root. Raises on empty input."""
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle root over zero leaves")
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # odd node is carried up unchanged
        level = nxt
    return level[0].hex()


async def _covered_events(db: AsyncSession, limit: int | None = None) -> list[AuditEvent]:
    """Events in canonical anchoring order: (ts, id), oldest first."""
    stmt = select(AuditEvent).order_by(AuditEvent.ts.asc(), AuditEvent.id.asc())
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def create_anchor(db: AsyncSession) -> AuditAnchor | None:
    """Anchor the entire chain as it stands. Returns None when there is
    nothing to anchor (no events yet). Caller owns the transaction."""
    events = await _covered_events(db)
    if not events:
        return None
    anchor = AuditAnchor(
        event_count=len(events),
        last_event_id=events[-1].id,
        merkle_root=merkle_root([ev.event_hash for ev in events]),
    )
    db.add(anchor)
    await db.flush()
    return anchor


async def verify_anchor(db: AsyncSession, anchor: AuditAnchor) -> tuple[bool, str | None]:
    """Recompute the root over the anchor's covered prefix and compare.

    Returns (ok, reason). A False result means the covered events no longer
    reproduce the anchored root — something in the prefix was altered,
    removed, or reordered since the anchor was made.
    """
    events = await _covered_events(db, limit=anchor.event_count)
    if len(events) < anchor.event_count:
        return False, "covered events missing (chain shorter than anchor)"
    if events[-1].id != anchor.last_event_id:
        return False, "covered prefix ends on a different event"
    recomputed = merkle_root([ev.event_hash for ev in events])
    if recomputed != anchor.merkle_root:
        return False, "merkle root mismatch"
    return True, None
