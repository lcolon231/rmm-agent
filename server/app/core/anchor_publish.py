# SPDX-License-Identifier: AGPL-3.0-only
"""Publish audit-anchor Merkle roots to an external immutable destination.

The local hash chain and the `AuditAnchor` rows prove internal consistency but
nothing against an attacker who owns this database — they can rewrite the
events and the anchors together. The root only becomes un-rewritable once a
copy exists somewhere the operator cannot alter. This module carries the root
out: it computes a canonical anchor document, publishes it through the shared
write-once store, and records a tamper-evident receipt of that publication.

The destination backends themselves live in :mod:`app.core.immutable_store`,
which audit anchors share with compliance evidence artifacts; `PublishError`
and `PublishResult` are re-exported here so existing callers keep working.
`build_publisher` maps the deployment's ``anchor_*`` settings onto that store.

Publication is idempotent: the destination key is deterministic in the
anchor's content, so a retry after a crash re-writes identical bytes rather
than forking, and a publication row is unique per (anchor, backend).

Design note on secrets: a receipt is stored in the database and returned by the
API. It must never contain credentials — no access keys, no presigned URLs. S3
credentials come from the standard AWS chain and stay in the client only.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.immutable_store import (  # re-exported for existing callers
    PublishError,
    PublishResult,
    StoreConfig,
    build_backend,
)
from app.models.models import AnchorPublication, AuditAnchor, AuditEvent

__all__ = [
    "ANCHOR_DOCUMENT_FORMAT",
    "ANCHOR_DOCUMENT_VERSION",
    "PublicationStatus",
    "PublishError",
    "PublishResult",
    "build_publisher",
    "canonical_anchor_document",
    "ensure_current_anchor",
    "publication_status",
    "publish_pending",
    "receipt_digest",
    "verify_receipt",
]

ANCHOR_DOCUMENT_FORMAT = "nodelink-audit-anchor"
ANCHOR_DOCUMENT_VERSION = 1


def canonical_anchor_document(anchor: AuditAnchor) -> bytes:
    """The exact bytes published externally and re-read by the clean-room
    verifier. Deterministic (sorted keys, no whitespace) so the same anchor
    always serializes identically."""
    created = anchor.created_at
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    doc = {
        "format": ANCHOR_DOCUMENT_FORMAT,
        "version": ANCHOR_DOCUMENT_VERSION,
        "anchor_id": anchor.id,
        "merkle_root": anchor.merkle_root,
        "event_count": anchor.event_count,
        "last_event_id": anchor.last_event_id,
        "created_at": created.isoformat() if created else None,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def receipt_digest(receipt: dict) -> str:
    """SHA-256 over the canonical receipt, so a later edit of the stored
    receipt is detectable."""
    blob = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _object_name(anchor: AuditAnchor) -> str:
    """The anchor's file name at the destination. Zero-padded event_count keeps
    lexical order == chain order; the root makes it content-addressed and
    collision-free. The backend adds its own prefix, if any."""
    return f"anchor-{anchor.event_count:012d}-{anchor.merkle_root}.json"


class AnchorPublisher:
    """Binds an anchor to a destination: names the object and writes it.

    The store knows nothing about anchors, so this adapter owns the anchor's
    key derivation and leaves the bytes-to-destination step to the backend.
    """

    def __init__(self, backend):
        self._backend = backend

    @property
    def name(self) -> str:
        return self._backend.name

    def object_key(self, anchor: AuditAnchor) -> str:
        return self._backend.object_key(_object_name(anchor))

    def publish(self, key: str, payload: bytes) -> PublishResult:
        return self._backend.publish(key, payload, content_type="application/json")


def build_publisher(s: Settings = settings):
    """Construct the configured anchor publisher, or None when publication is
    disabled. Maps the deployment's ``anchor_*`` settings onto the shared
    write-once store."""
    backend = build_backend(
        StoreConfig(
            backend=s.anchor_publish_backend,
            directory=s.anchor_publish_dir,
            bucket=s.anchor_s3_bucket,
            prefix=s.anchor_s3_prefix,
            region=s.anchor_s3_region,
            endpoint_url=s.anchor_s3_endpoint_url,
            object_lock_mode=s.anchor_s3_object_lock_mode,
            retain_days=s.anchor_s3_retain_days,
        )
    )
    return None if backend is None else AnchorPublisher(backend)


# --------------------------------------------------------------------------- #
# Anchor creation + publication over the database
# --------------------------------------------------------------------------- #
async def ensure_current_anchor(db: AsyncSession) -> AuditAnchor | None:
    """Create a new anchor if events exist beyond the newest anchor. Idempotent
    — no new anchor when the chain has not grown. Caller owns the transaction."""
    from app.core.anchor import create_anchor  # avoid import cycle at module load

    total = (
        await db.execute(select(func.count()).select_from(AuditEvent))
    ).scalar_one()
    if total == 0:
        return None
    covered = (
        await db.execute(select(func.max(AuditAnchor.event_count)))
    ).scalar_one() or 0
    if covered >= total:
        return None
    return await create_anchor(db)


async def _unpublished_anchors(db: AsyncSession, backend_name: str) -> list[AuditAnchor]:
    """Anchors with no successful publication for this backend, oldest first."""
    published_ids = select(AnchorPublication.anchor_id).where(
        AnchorPublication.backend == backend_name,
        AnchorPublication.status == "published",
    )
    result = await db.execute(
        select(AuditAnchor)
        .where(AuditAnchor.id.not_in(published_ids))
        .order_by(AuditAnchor.event_count.asc())
    )
    return list(result.scalars().all())


async def _publication_row(db: AsyncSession, anchor_id: str, backend_name: str) -> AnchorPublication:
    row = (
        await db.execute(
            select(AnchorPublication).where(
                AnchorPublication.anchor_id == anchor_id,
                AnchorPublication.backend == backend_name,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = AnchorPublication(anchor_id=anchor_id, backend=backend_name, status="pending")
        db.add(row)
        await db.flush()
    return row


async def publish_pending(db: AsyncSession, backend) -> dict:
    """Publish every unpublished anchor for `backend`. Never raises for a
    destination failure — it records the error on the row and moves on so one
    bad anchor cannot stall the rest. Caller owns the transaction.

    Publication is deliberately NOT recorded as an audit-chain event: doing so
    would grow the chain every cycle and force a fresh anchor on the next one
    (perpetual churn). The AnchorPublication row is the operational evidence —
    status, receipt, timestamp, and error — and the external receipt is
    self-securing."""
    published, failed = 0, 0
    for anchor in await _unpublished_anchors(db, backend.name):
        row = await _publication_row(db, anchor.id, backend.name)
        payload = canonical_anchor_document(anchor)
        row.attempts += 1
        try:
            result = await asyncio.to_thread(backend.publish, backend.object_key(anchor), payload)
        except Exception as exc:
            row.status = "pending"
            row.last_error = str(exc)[:500]
            failed += 1
            continue
        row.status = "published"
        row.uri = result.uri
        row.receipt = result.receipt
        row.receipt_sha256 = receipt_digest(result.receipt)
        row.last_error = None
        row.published_at = datetime.now(timezone.utc)
        published += 1
    return {"published": published, "failed": failed}


@dataclass
class PublicationStatus:
    backend: str | None
    total_anchors: int
    published: int
    pending: int
    oldest_unpublished_age_seconds: float | None
    lag_alert: bool
    last_error: str | None


async def publication_status(db: AsyncSession, s: Settings = settings) -> PublicationStatus:
    backend = (s.anchor_publish_backend or "none").strip().lower()
    backend_name = None if backend == "none" else backend
    total = (await db.execute(select(func.count()).select_from(AuditAnchor))).scalar_one()

    if backend_name is None:
        # Publication disabled: every anchor is unpublished by definition.
        return PublicationStatus(None, total, 0, total, None, total > 0, None)

    published = (
        await db.execute(
            select(func.count()).select_from(AnchorPublication).where(
                AnchorPublication.backend == backend_name,
                AnchorPublication.status == "published",
            )
        )
    ).scalar_one()
    pending = total - published

    oldest_age = None
    lag_alert = False
    if pending > 0:
        published_ids = select(AnchorPublication.anchor_id).where(
            AnchorPublication.backend == backend_name,
            AnchorPublication.status == "published",
        )
        oldest = (
            await db.execute(
                select(AuditAnchor.created_at)
                .where(AuditAnchor.id.not_in(published_ids))
                .order_by(AuditAnchor.created_at.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if oldest is not None:
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            oldest_age = (datetime.now(timezone.utc) - oldest).total_seconds()
            lag_alert = oldest_age > s.anchor_publish_lag_alert_seconds

    last_error = (
        await db.execute(
            select(AnchorPublication.last_error)
            .where(
                AnchorPublication.backend == backend_name,
                AnchorPublication.last_error.is_not(None),
            )
            .order_by(AnchorPublication.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return PublicationStatus(
        backend_name, total, published, pending, oldest_age, lag_alert, last_error
    )


def verify_receipt(publication: AnchorPublication) -> tuple[bool, str | None]:
    """Recompute the receipt digest and compare — detects a tampered receipt."""
    if publication.status != "published" or publication.receipt is None:
        return False, "not published"
    if receipt_digest(publication.receipt) != publication.receipt_sha256:
        return False, "receipt digest mismatch"
    return True, None
