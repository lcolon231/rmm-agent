# SPDX-License-Identifier: AGPL-3.0-only
"""Append-only, hash-chained audit log with monotonic sequence numbers.

Each event stores `prev_hash` (the hash of the previous event in the chain)
and `event_hash` (the hash of this event's canonical content *including*
prev_hash). Because every event commits to its predecessor, altering or
removing any event breaks the chain from that point forward — which a
periodic verifier will detect.

Ordering is explicit, not inferred: every event carries a strictly monotonic
`seq` (1, 2, 3, ... with no gaps) assigned inside a serialized append. On
PostgreSQL a transaction-scoped advisory lock serializes concurrent appends;
everywhere, the unique constraint on `seq` turns a lost race into a failed
transaction rather than a silently forked chain. Verification walks the chain
in seq order and treats a gap, duplicate, or reordering as tampering.

Hash schemas:
  1 — legacy events written before sequences existed. Their `seq` was
      backfilled by migration 0007 from the historical (ts, id) order and is
      NOT part of the hashed document (rewriting history to pretend it was
      would be exactly the kind of tampering this log exists to catch).
  2 — current: `seq` is bound into `event_hash`, so renumbering an event
      breaks its own hash, not just its neighbors' links.
All schema-1 events precede all schema-2 events; a schema-1 event appearing
after the cutover fails verification.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redaction import redact_detail
from app.models.models import AuditEvent

_GENESIS = "0" * 64

# Arbitrary but fixed application-wide key for pg_advisory_xact_lock. The lock
# is transaction-scoped: it releases automatically on commit/rollback.
_APPEND_LOCK_KEY = 0x4E4C_41554449  # "NL AUDIT"

HASH_SCHEMA_LEGACY = 1
HASH_SCHEMA_SEQUENCED = 2


def _hash_event(prev_hash: str, ts_iso: str, actor: str, action: str,
                agent_id: str | None, detail: dict,
                seq: int | None = None,
                hash_schema: int = HASH_SCHEMA_SEQUENCED) -> str:
    doc = {
        "prev_hash": prev_hash,
        "ts": ts_iso,
        "actor": actor,
        "action": action,
        "agent_id": agent_id,
        "detail": detail,
    }
    if hash_schema >= HASH_SCHEMA_SEQUENCED:
        doc["seq"] = seq
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


async def _serialize_append(db: AsyncSession) -> None:
    """Serialize concurrent appends for the rest of this transaction.

    PostgreSQL gets an advisory transaction lock. SQLite serializes writers
    via its file lock already. In both cases the unique constraint on seq is
    the fail-closed backstop: two appends that somehow read the same tail
    cannot both commit.
    """
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": _APPEND_LOCK_KEY}
        )


async def _chain_tail(db: AsyncSession) -> tuple[str, int]:
    """(hash, seq) of the newest event, or (GENESIS, 0) for an empty chain."""
    result = await db.execute(
        select(AuditEvent.event_hash, AuditEvent.seq)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    )
    row = result.first()
    if row is None:
        return _GENESIS, 0
    return row[0], row[1] or 0


async def record(
    db: AsyncSession,
    *,
    action: str,
    actor: str = "system",
    agent_id: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Append a new audit event to the chain. Caller is responsible for the
    surrounding transaction/commit.

    Every event's ``detail`` passes through the central redaction boundary
    (:func:`app.core.redaction.redact_detail`) before it is hashed and stored,
    so no producer can commit a secret into the tamper-evident chain. Redaction
    is deterministic, so the stored (redacted) representation is the only one
    that is ever hashed and chain/anchor verification stays reproducible.
    """
    detail = redact_detail(detail or {})
    await _serialize_append(db)
    prev, prev_seq = await _chain_tail(db)
    seq = prev_seq + 1
    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat()
    event = AuditEvent(
        seq=seq,
        hash_schema=HASH_SCHEMA_SEQUENCED,
        ts=ts,
        ts_iso=ts_iso,
        actor=actor,
        action=action,
        agent_id=agent_id,
        detail=detail,
        prev_hash=prev,
    )
    event.event_hash = _hash_event(
        prev, ts_iso, actor, action, agent_id, detail,
        seq=seq, hash_schema=HASH_SCHEMA_SEQUENCED,
    )
    db.add(event)
    await db.flush()  # assign event.id; unique(seq) rejects a lost race here
    return event


async def verify_chain(db: AsyncSession) -> tuple[bool, str | None]:
    """Walk the chain in sequence order and confirm every link. Returns
    (ok, first_broken_event_id).

    Detects: content edits (hash mismatch), removed or inserted events and
    renumbering (sequence gap/duplicate/reorder), a missing sequence, and a
    legacy-schema event appearing after the sequenced cutover.
    """
    result = await db.execute(
        select(AuditEvent).order_by(AuditEvent.seq.asc())
    )
    events = result.scalars().all()
    prev = _GENESIS
    expected_seq = 1
    seen_sequenced_schema = False
    for ev in events:
        if ev.seq != expected_seq:
            return False, ev.id  # gap, duplicate, NULL, or reorder
        if ev.hash_schema >= HASH_SCHEMA_SEQUENCED:
            seen_sequenced_schema = True
        elif seen_sequenced_schema:
            return False, ev.id  # legacy event after the cutover
        if ev.prev_hash != prev:
            return False, ev.id
        expected = _hash_event(
            ev.prev_hash, ev.ts_iso, ev.actor, ev.action,
            ev.agent_id, ev.detail,
            seq=ev.seq, hash_schema=ev.hash_schema,
        )
        if expected != ev.event_hash:
            return False, ev.id
        prev = ev.event_hash
        expected_seq += 1
    return True, None
