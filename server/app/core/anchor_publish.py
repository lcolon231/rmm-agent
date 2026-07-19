# SPDX-License-Identifier: AGPL-3.0-only
"""Publish audit-anchor Merkle roots to an external immutable destination.

The local hash chain and the `AuditAnchor` rows prove internal consistency but
nothing against an attacker who owns this database — they can rewrite the
events and the anchors together. The root only becomes un-rewritable once a
copy exists somewhere the operator cannot alter. This module carries the root
out: it computes a canonical anchor document, publishes it to a configured
backend, and records a tamper-evident receipt of that publication.

Backends (see build_publisher):
  filesystem  append-only directory; real immutability only on a WORM /
              object-lock mount. Always available; the CI test vehicle.
  s3          S3-compatible bucket with Object Lock (AWS S3, MinIO, Backblaze
              B2, ...). The receipt is the object version-id + ETag.

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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.models.models import AnchorPublication, AuditAnchor, AuditEvent

ANCHOR_DOCUMENT_FORMAT = "nodelink-audit-anchor"
ANCHOR_DOCUMENT_VERSION = 1


class PublishError(RuntimeError):
    """A backend failed to publish. The scheduler records it and retries."""


@dataclass
class PublishResult:
    uri: str
    receipt: dict  # JSON-serializable, MUST NOT contain secrets


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


def _object_key(anchor: AuditAnchor, prefix: str = "") -> str:
    # Zero-padded event_count keeps lexical order == chain order; the root makes
    # it content-addressed and collision-free.
    name = f"anchor-{anchor.event_count:012d}-{anchor.merkle_root}.json"
    return f"{prefix.rstrip('/')}/{name}" if prefix else name


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class FilesystemBackend:
    name = "filesystem"

    def __init__(self, directory: str):
        self.directory = Path(directory)

    def object_key(self, anchor: AuditAnchor) -> str:
        return _object_key(anchor)

    def publish(self, key: str, payload: bytes) -> PublishResult:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / key
        sha = hashlib.sha256(payload).hexdigest()
        if path.exists():
            # Idempotent re-publish only if the content matches; a differing
            # file at the same content-addressed key means corruption or a WORM
            # violation, and we fail closed rather than overwrite evidence.
            existing = path.read_bytes()
            if existing != payload:
                raise PublishError(f"existing anchor artifact differs at {path}")
        else:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(payload)
            tmp.replace(path)
            try:
                path.chmod(0o444)  # best-effort read-only; real WORM is the mount
            except OSError:
                pass
        return PublishResult(
            uri=f"file://{path}",
            receipt={"backend": self.name, "path": str(path), "sha256": sha,
                     "bytes": len(payload)},
        )


class S3Backend:
    name = "s3"

    def __init__(self, s: Settings):
        if not s.anchor_s3_bucket:
            raise PublishError("anchor_s3_bucket is required for the s3 backend")
        self.bucket = s.anchor_s3_bucket
        self.prefix = s.anchor_s3_prefix
        self.region = s.anchor_s3_region
        self.endpoint_url = s.anchor_s3_endpoint_url
        self.lock_mode = s.anchor_s3_object_lock_mode
        self.retain_days = s.anchor_s3_retain_days
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy: only deployments using s3 need boto3 installed

            self._client = boto3.client(
                "s3", region_name=self.region, endpoint_url=self.endpoint_url
            )
        return self._client

    def object_key(self, anchor: AuditAnchor) -> str:
        return _object_key(anchor, self.prefix)

    def publish(self, key: str, payload: bytes) -> PublishResult:
        client = self._get_client()
        args = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": payload,
            "ContentType": "application/json",
        }
        retain_until = None
        if self.retain_days > 0:
            retain_until = datetime.now(timezone.utc) + timedelta(days=self.retain_days)
            args["ObjectLockMode"] = self.lock_mode
            args["ObjectLockRetainUntilDate"] = retain_until
        try:
            resp = client.put_object(**args)
        except Exception as exc:  # boto/network/permission error
            raise PublishError(f"s3 put_object failed: {exc}") from exc
        receipt = {
            "backend": self.name,
            "bucket": self.bucket,
            "key": key,
            "version_id": resp.get("VersionId"),
            "etag": (resp.get("ETag") or "").strip('"'),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        if retain_until is not None:
            receipt["object_lock_mode"] = self.lock_mode
            receipt["retain_until"] = retain_until.isoformat()
        return PublishResult(uri=f"s3://{self.bucket}/{key}", receipt=receipt)


def build_publisher(s: Settings = settings):
    """Construct the configured backend, or None when publication is disabled."""
    backend = (s.anchor_publish_backend or "none").strip().lower()
    if backend == "none":
        return None
    if backend == "filesystem":
        return FilesystemBackend(s.anchor_publish_dir)
    if backend == "s3":
        return S3Backend(s)
    raise PublishError(f"unknown anchor_publish_backend {backend!r}")


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
