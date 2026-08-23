# SPDX-License-Identifier: AGPL-3.0-only
"""Write-once external storage shared by every artifact NodeLink must not be
able to rewrite (issue #81).

This module is the destination half of :mod:`app.core.anchor_publish`, lifted
out so audit anchors and compliance evidence write through the same code path
instead of growing a second, subtly different one. It knows how to put bytes at
a key and hand back a credential-free receipt; it knows nothing about anchors,
tenants, or evidence.

Backends:
  filesystem  append-only directory; real immutability only on a WORM /
              object-lock mount. Always available; the CI test vehicle.
  s3          S3-compatible bucket with Object Lock (AWS S3, MinIO, Backblaze
              B2, ...). The receipt is the object version-id + ETag.

Two properties every caller depends on:

* **Content-addressed idempotency.** Callers derive the key from a digest of
  the payload, so a retry after a crash rewrites identical bytes at the same
  key rather than forking. A *differing* object already at that key is a WORM
  violation or corruption, and both backends fail closed rather than overwrite
  evidence.
* **No secrets in a receipt.** A receipt is persisted and returned by the API.
  It carries no access keys and no presigned URLs; S3 credentials come from the
  standard AWS chain and stay inside the client.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_CONTENT_TYPE = "application/json"


class PublishError(RuntimeError):
    """A backend failed to write. Callers record it and retry later."""


@dataclass
class PublishResult:
    uri: str
    receipt: dict  # JSON-serializable, MUST NOT contain secrets


@dataclass(frozen=True)
class StoreConfig:
    """One destination's configuration, independent of what is being stored.

    Built from the ``anchor_*`` settings for anchor publication and from the
    ``evidence_*`` settings for evidence artifacts, so the two can point at
    different buckets, prefixes, or retention windows without either one
    reaching into the other's configuration.
    """

    backend: str = "none"  # none | filesystem | s3
    directory: str = ""
    bucket: str | None = None
    prefix: str = ""
    region: str | None = None
    endpoint_url: str | None = None
    object_lock_mode: str = "COMPLIANCE"  # GOVERNANCE | COMPLIANCE
    retain_days: int = 0


def _retain_until(retain_until: datetime | None, retain_days: int) -> datetime | None:
    """Resolve the object-lock retain-until date.

    An explicit date always wins: an evidence artifact freezes its own
    ``retain_until`` at creation, and resolving it again at write time would let
    a later configuration change move it. Only when the caller has no opinion
    does the destination's own ``retain_days`` window apply, which is how anchor
    publication has always behaved.
    """
    if retain_until is not None:
        return retain_until
    if retain_days > 0:
        return datetime.now(timezone.utc) + timedelta(days=retain_days)
    return None


class FilesystemBackend:
    """Append-only directory. Immutability is the operator's WORM mount; the
    read-only mode bit here is a best-effort guard, not a control."""

    name = "filesystem"

    def __init__(self, directory: str):
        self.directory = Path(directory)

    def object_key(self, name: str) -> str:
        return name

    def publish(
        self,
        key: str,
        payload: bytes,
        *,
        content_type: str = DEFAULT_CONTENT_TYPE,
        retain_until: datetime | None = None,
    ) -> PublishResult:
        path = self.directory / key
        # parents=True covers a key with directory components (evidence keys are
        # tenant/date-partitioned); for a flat key this is the directory itself.
        path.parent.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(payload).hexdigest()
        if path.exists():
            # Idempotent re-publish only if the content matches; a differing
            # file at the same content-addressed key means corruption or a WORM
            # violation, and we fail closed rather than overwrite evidence.
            existing = path.read_bytes()
            if existing != payload:
                raise PublishError(f"existing artifact differs at {path}")
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
    """S3-compatible bucket, written with Object Lock when a retention window
    applies. The receipt is the destination's own proof: version-id and ETag."""

    name = "s3"

    def __init__(self, config: StoreConfig):
        if not config.bucket:
            raise PublishError("a bucket is required for the s3 backend")
        self.bucket = config.bucket
        self.prefix = config.prefix
        self.region = config.region
        self.endpoint_url = config.endpoint_url
        self.lock_mode = config.object_lock_mode
        self.retain_days = config.retain_days
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy: only deployments using s3 need boto3 installed

            self._client = boto3.client(
                "s3", region_name=self.region, endpoint_url=self.endpoint_url
            )
        return self._client

    def object_key(self, name: str) -> str:
        return f"{self.prefix.rstrip('/')}/{name}" if self.prefix else name

    def publish(
        self,
        key: str,
        payload: bytes,
        *,
        content_type: str = DEFAULT_CONTENT_TYPE,
        retain_until: datetime | None = None,
    ) -> PublishResult:
        client = self._get_client()
        args = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": payload,
            "ContentType": content_type,
        }
        retain = _retain_until(retain_until, self.retain_days)
        if retain is not None:
            args["ObjectLockMode"] = self.lock_mode
            args["ObjectLockRetainUntilDate"] = retain
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
        if retain is not None:
            receipt["object_lock_mode"] = self.lock_mode
            receipt["retain_until"] = retain.isoformat()
        return PublishResult(uri=f"s3://{self.bucket}/{key}", receipt=receipt)


def build_backend(config: StoreConfig):
    """Construct the configured backend, or None when storage is disabled."""
    backend = (config.backend or "none").strip().lower()
    if backend == "none":
        return None
    if backend == "filesystem":
        return FilesystemBackend(config.directory)
    if backend == "s3":
        return S3Backend(config)
    raise PublishError(f"unknown storage backend {backend!r}")
