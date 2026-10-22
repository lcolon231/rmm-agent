# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence storage, retention enforcement, and legal hold (issue #81).

A signed evidence package (issue #80) proves what NodeLink said at export time,
and it embeds the external anchor receipts (issue #76) that bind the audit
prefix it covers. This module retains those packages where they cannot be
quietly replaced or destroyed:

* **Store** writes the exact package bytes to a configured backend under a
  content-addressed key, with a retention date and, when a tenant hold is
  active, a legal hold. An S3 Object Lock backend enforces both in the storage
  itself; the filesystem backend is application-enforced only.
* **Verify** re-reads the object and checks its digest, its signed manifest,
  the stored receipt, and (on S3) that the storage lock is at least as strong
  as recorded. Outage, absence, substitution, and lock weakening are distinct
  states, never folded into "ok".
* **Legal hold** suspends deletion for one package or a whole tenant. The hold
  row is authoritative; the storage-level hold is defense in depth, applied
  eagerly and reconciled by the sweep if the backend was unreachable.
* **Disposal** is an explicit administrator action that is refused while any
  hold covers the package or its retention has not elapsed. Nothing here
  deletes evidence on a timer.

Receipts and errors never carry credentials: S3 access comes from the standard
AWS chain and stays inside the client.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import evidence_packages
from app.core.config import Settings, settings
from app.models.models import EvidenceLegalHold, EvidenceVaultRecord

PACKAGE_KIND = "evidence_package"
APPLICATION_RETENTION = "application"
LOCK_MODES = ("COMPLIANCE", "GOVERNANCE")
# Integrity states that mean "this evidence can no longer be trusted as-is".
FAILING_STATES = frozenset({"tampered", "missing", "lock_drift"})
# Clock skew tolerated when comparing a storage retention date to the record.
_RETENTION_SLACK = timedelta(seconds=1)


class VaultError(RuntimeError):
    """Stable API failure (code/state/status), mirroring EvidencePackageError."""

    def __init__(self, code: str, *, state: str, status_code: int):
        super().__init__(code)
        self.code = code
        self.state = state
        self.status_code = status_code


class BackendUnavailable(RuntimeError):
    """The storage could not be reached or refused the request transiently."""


class BackendMisconfigured(RuntimeError):
    """The storage cannot provide the immutability it is configured for."""


class ObjectMissing(RuntimeError):
    """The recorded object (or version) no longer exists in storage."""


class ObjectConflict(RuntimeError):
    """Different bytes already occupy a content-addressed key."""


class DeletionRefused(RuntimeError):
    """The storage itself refused to delete the object (lock still in force)."""


@dataclass(frozen=True)
class PutResult:
    uri: str
    receipt: dict
    retention_mode: str


@dataclass(frozen=True)
class LockState:
    mode: str | None
    retain_until: datetime | None
    legal_hold: bool


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def receipt_digest(receipt: dict) -> str:
    blob = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(blob)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def object_name(client_id: str, package_id: str) -> str:
    return f"{client_id}/evidence-package-{package_id}.zip"


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class FilesystemVault:
    """Read-only files under a directory. Retention and hold are enforced by
    NodeLink only; the mount decides whether the bytes are truly immutable."""

    name = "filesystem"
    enforces_lock = False

    def __init__(self, directory: str):
        self.directory = Path(directory)

    def object_key(self, client_id: str, package_id: str) -> str:
        return object_name(client_id, package_id)

    def _path(self, key: str) -> Path:
        path = (self.directory / key).resolve()
        if self.directory.resolve() not in path.parents:
            raise BackendMisconfigured("object key escapes the vault directory")
        return path

    def put(self, key: str, payload: bytes, *, retain_until: datetime, legal_hold: bool) -> PutResult:
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if path.read_bytes() != payload:
                    raise ObjectConflict("different bytes already stored at this key")
            else:
                tmp = path.with_suffix(path.suffix + ".tmp")
                tmp.write_bytes(payload)
                tmp.replace(path)
                try:
                    path.chmod(0o444)
                except OSError:
                    pass
        except (ObjectConflict, BackendMisconfigured):
            raise
        except OSError as exc:
            raise BackendUnavailable(f"filesystem write failed: {exc.strerror or exc}") from exc
        receipt = {
            "backend": self.name,
            "key": key,
            "sha256": _sha256(payload),
            "bytes": len(payload),
        }
        return PutResult(uri=f"file://{path.as_posix()}", receipt=receipt,
                         retention_mode=APPLICATION_RETENTION)

    def get(self, key: str, receipt: dict) -> bytes:
        path = self._path(key)
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise ObjectMissing("object not found") from exc
        except OSError as exc:
            raise BackendUnavailable(f"filesystem read failed: {exc.strerror or exc}") from exc

    def lock_state(self, key: str, receipt: dict) -> LockState | None:
        return None  # nothing below NodeLink enforces a lock

    def set_legal_hold(self, key: str, receipt: dict, on: bool) -> None:
        return None

    def delete(self, key: str, receipt: dict) -> None:
        path = self._path(key)
        try:
            path.chmod(0o644)
            path.unlink()
        except FileNotFoundError:
            return
        except PermissionError as exc:
            # A WORM mount refusing the unlink is the storage doing its job.
            raise DeletionRefused("storage refused deletion") from exc
        except OSError as exc:
            raise BackendUnavailable(f"filesystem delete failed: {exc.strerror or exc}") from exc


class S3Vault:
    """S3-compatible bucket with Object Lock. Every operation addresses the
    exact object *version* recorded in the receipt, so a later upload to the
    same key can never stand in for the retained one."""

    name = "s3"
    enforces_lock = True

    def __init__(self, s: Settings):
        if not s.evidence_vault_s3_bucket:
            raise BackendMisconfigured("evidence_vault_s3_bucket is required for the s3 backend")
        mode = (s.evidence_vault_s3_object_lock_mode or "").upper()
        if mode not in LOCK_MODES:
            raise BackendMisconfigured("evidence_vault_s3_object_lock_mode must be COMPLIANCE or GOVERNANCE")
        self.bucket = s.evidence_vault_s3_bucket
        self.prefix = s.evidence_vault_s3_prefix
        self.region = s.evidence_vault_s3_region
        self.endpoint_url = s.evidence_vault_s3_endpoint_url
        self.lock_mode = mode
        self._client = None
        self._lock_confirmed = False

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy: only s3 deployments need boto3 at runtime

            self._client = boto3.client("s3", region_name=self.region, endpoint_url=self.endpoint_url)
        return self._client

    @staticmethod
    def _error_code(exc: Exception) -> str:
        response = getattr(exc, "response", None) or {}
        return str((response.get("Error") or {}).get("Code") or "")

    def _call(self, operation: str, **kwargs):
        try:
            return getattr(self._get_client(), operation)(**kwargs)
        except Exception as exc:
            code = self._error_code(exc)
            if code in ("NoSuchKey", "NoSuchVersion", "404", "NotFound"):
                raise ObjectMissing(f"s3 {operation}: {code}") from exc
            if code == "AccessDenied" and operation == "delete_object":
                raise DeletionRefused("storage refused deletion") from exc
            if code in ("ObjectLockConfigurationNotFoundError", "InvalidRequest"):
                raise BackendMisconfigured(f"s3 {operation}: {code}") from exc
            # Only the error code leaves this function: boto messages can echo
            # request parameters and must not reach the API or the database.
            raise BackendUnavailable(f"s3 {operation} failed: {code or type(exc).__name__}") from exc

    def _ensure_object_lock(self) -> None:
        if self._lock_confirmed:
            return
        config = self._call("get_object_lock_configuration", Bucket=self.bucket)
        enabled = (config.get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled")
        if enabled != "Enabled":
            raise BackendMisconfigured("bucket does not have Object Lock enabled")
        self._lock_confirmed = True

    def object_key(self, client_id: str, package_id: str) -> str:
        name = object_name(client_id, package_id)
        return f"{self.prefix.rstrip('/')}/{name}" if self.prefix else name

    def put(self, key: str, payload: bytes, *, retain_until: datetime, legal_hold: bool) -> PutResult:
        self._ensure_object_lock()
        sha = _sha256(payload)
        resp = self._call(
            "put_object",
            Bucket=self.bucket,
            Key=key,
            Body=payload,
            ContentType=evidence_packages.ZIP_MEDIA_TYPE,
            Metadata={"sha256": sha},
            ObjectLockMode=self.lock_mode,
            ObjectLockRetainUntilDate=retain_until,
            ObjectLockLegalHoldStatus="ON" if legal_hold else "OFF",
        )
        version_id = resp.get("VersionId")
        if not version_id:
            raise BackendMisconfigured("bucket did not return an object version")
        receipt = {
            "backend": self.name,
            "bucket": self.bucket,
            "key": key,
            "version_id": version_id,
            "etag": (resp.get("ETag") or "").strip('"'),
            "sha256": sha,
            "bytes": len(payload),
            "object_lock_mode": self.lock_mode,
            "retain_until": retain_until.isoformat(),
        }
        # Read the lock back rather than trusting the request: a bucket that
        # silently ignored the lock headers must not be recorded as immutable.
        state = self.lock_state(key, receipt)
        if (
            state is None
            or state.mode != self.lock_mode
            or state.retain_until is None
            or state.retain_until + _RETENTION_SLACK < retain_until
        ):
            raise BackendMisconfigured("object lock was not applied as requested")
        return PutResult(uri=f"s3://{self.bucket}/{key}", receipt=receipt,
                         retention_mode=self.lock_mode)

    def get(self, key: str, receipt: dict) -> bytes:
        resp = self._call("get_object", Bucket=self.bucket, Key=key, VersionId=receipt["version_id"])
        try:
            return resp["Body"].read()
        except Exception as exc:
            raise BackendUnavailable(f"s3 read failed: {type(exc).__name__}") from exc

    def lock_state(self, key: str, receipt: dict) -> LockState | None:
        # HEAD on the exact version returns retention and legal hold together.
        head = self._call("head_object", Bucket=self.bucket, Key=key, VersionId=receipt["version_id"])
        return LockState(
            mode=head.get("ObjectLockMode"),
            retain_until=_aware(head.get("ObjectLockRetainUntilDate")),
            legal_hold=head.get("ObjectLockLegalHoldStatus") == "ON",
        )

    def set_legal_hold(self, key: str, receipt: dict, on: bool) -> None:
        self._call(
            "put_object_legal_hold",
            Bucket=self.bucket,
            Key=key,
            VersionId=receipt["version_id"],
            LegalHold={"Status": "ON" if on else "OFF"},
        )

    def delete(self, key: str, receipt: dict) -> None:
        self._call("delete_object", Bucket=self.bucket, Key=key, VersionId=receipt["version_id"])


def build_vault(s: Settings = settings):
    """The configured backend, or None when the vault is disabled."""
    backend = (s.evidence_vault_backend or "none").strip().lower()
    if backend == "none":
        return None
    if backend == "filesystem":
        return FilesystemVault(s.evidence_vault_dir)
    if backend == "s3":
        return S3Vault(s)
    raise BackendMisconfigured(f"unknown evidence_vault_backend {backend!r}")


def require_vault(s: Settings = settings):
    """The configured backend, or a stable error when it is absent/broken."""
    try:
        vault = build_vault(s)
    except BackendMisconfigured as exc:
        raise VaultError("evidence_vault_misconfigured", state="unavailable", status_code=503) from exc
    if vault is None:
        raise VaultError("evidence_vault_disabled", state="unsupported", status_code=503)
    return vault


def require_same_backend(vault, record: EvidenceVaultRecord) -> None:
    if record.backend != vault.name:
        raise VaultError("evidence_vault_backend_mismatch", state="unsupported", status_code=409)


# --------------------------------------------------------------------------- #
# Hold coverage
# --------------------------------------------------------------------------- #
def _covering_hold_clause(record_client_id, record_id):
    return exists().where(
        EvidenceLegalHold.client_id == record_client_id,
        EvidenceLegalHold.status == "active",
        or_(EvidenceLegalHold.record_id.is_(None), EvidenceLegalHold.record_id == record_id),
    )


async def hold_active_for(db: AsyncSession, record: EvidenceVaultRecord) -> bool:
    return bool(
        (await db.execute(select(_covering_hold_clause(record.client_id, record.id)))).scalar()
    )


async def tenant_hold_active(db: AsyncSession, client_id: str) -> bool:
    clause = exists().where(
        EvidenceLegalHold.client_id == client_id,
        EvidenceLegalHold.status == "active",
        EvidenceLegalHold.record_id.is_(None),
    )
    return bool((await db.execute(select(clause))).scalar())


async def reconcile_hold(db: AsyncSession, vault, record: EvidenceVaultRecord) -> bool:
    """Make the storage-level hold match the authoritative hold rows. Returns
    True when storage now agrees. Never raises for a backend outage: the hold
    row already blocks deletion, so a pending storage hold is reported, not
    fatal, and the sweep retries it."""
    if not vault.enforces_lock or record.state != "stored":
        return True
    expected = await hold_active_for(db, record)
    if record.backend_legal_hold == expected:
        return True
    try:
        await asyncio.to_thread(vault.set_legal_hold, record.object_key, record.storage_receipt, expected)
    except (BackendUnavailable, BackendMisconfigured, ObjectMissing) as exc:
        record.last_verify_error = str(exc)[:500]
        return False
    record.backend_legal_hold = expected
    return True


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class StoreOutcome:
    record: EvidenceVaultRecord
    created: bool


def resolve_retention_days(requested: int | None, s: Settings = settings) -> int:
    floor = max(1, s.evidence_vault_retention_days)
    ceiling = max(floor, s.evidence_vault_max_retention_days)
    days = floor if requested is None else requested
    if days < floor:
        raise VaultError("evidence_retention_below_minimum", state="invalid", status_code=422)
    if days > ceiling:
        raise VaultError("evidence_retention_above_maximum", state="invalid", status_code=422)
    return days


async def store_package(
    db: AsyncSession,
    vault,
    *,
    client_id: str,
    artifact,
    from_seq: int,
    package: evidence_packages.PackageArtifact,
    retention_days: int,
    operator_id: str | None,
    operator_email: str,
    now: datetime | None = None,
) -> StoreOutcome:
    """Write one signed package and record it. Idempotent per package ID: a
    repeat returns the existing record without touching storage, so a client
    retry can never shorten or reset retention."""
    existing = (
        await db.execute(
            select(EvidenceVaultRecord).where(
                EvidenceVaultRecord.backend == vault.name,
                EvidenceVaultRecord.package_id == package.package_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.state != "stored":
            raise VaultError("evidence_package_disposed", state="invalid", status_code=409)
        return StoreOutcome(existing, False)

    now = now or datetime.now(timezone.utc)
    retain_until = now + timedelta(days=retention_days)
    held = await tenant_hold_active(db, client_id)
    key = vault.object_key(client_id, package.package_id)
    try:
        result = await asyncio.to_thread(
            vault.put, key, package.content, retain_until=retain_until, legal_hold=held
        )
    except ObjectConflict as exc:
        raise VaultError("evidence_object_conflict", state="tampered", status_code=409) from exc
    except BackendMisconfigured as exc:
        raise VaultError("evidence_vault_misconfigured", state="unavailable", status_code=503) from exc
    except (BackendUnavailable, ObjectMissing) as exc:
        raise VaultError("evidence_vault_unavailable", state="unavailable", status_code=503) from exc

    record = EvidenceVaultRecord(
        client_id=client_id,
        kind=PACKAGE_KIND,
        package_id=package.package_id,
        bundle_id=artifact.bundle_id,
        from_seq=from_seq,
        through_seq=artifact.through_seq,
        record_count=artifact.total_records,
        signing_key_id=package.signing_key_id,
        backend=vault.name,
        object_key=key,
        uri=result.uri,
        sha256=_sha256(package.content),
        size_bytes=len(package.content),
        storage_receipt=result.receipt,
        receipt_sha256=receipt_digest(result.receipt),
        retention_mode=result.retention_mode,
        retain_until=retain_until,
        backend_legal_hold=held and vault.enforces_lock,
        state="stored",
        integrity_state="intact",
        last_verified_at=now,
        stored_at=now,
        stored_by_operator_id=operator_id,
        stored_by_email=operator_email,
    )
    db.add(record)
    await db.flush()
    return StoreOutcome(record, True)


# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VerifyOutcome:
    previous_state: str
    integrity_state: str
    reason: str | None


async def _check(vault, record: EvidenceVaultRecord, hold_expected: bool) -> tuple[str, str | None]:
    if receipt_digest(record.storage_receipt) != record.receipt_sha256:
        return "tampered", "receipt_digest_mismatch"
    try:
        payload = await asyncio.to_thread(vault.get, record.object_key, record.storage_receipt)
    except ObjectMissing:
        return "missing", "object_not_found"
    except (BackendUnavailable, BackendMisconfigured):
        return "unavailable", "storage_unreachable"
    if len(payload) != record.size_bytes or _sha256(payload) != record.sha256:
        return "tampered", "content_digest_mismatch"
    try:
        verified = evidence_packages.verify_signed_package(payload)
    except (evidence_packages.PackageVerificationError, ValueError):
        return "tampered", "package_verification_failed"
    if verified.package_id != record.package_id:
        return "tampered", "package_id_mismatch"
    if vault.enforces_lock:
        try:
            lock = await asyncio.to_thread(vault.lock_state, record.object_key, record.storage_receipt)
        except ObjectMissing:
            return "missing", "object_not_found"
        except (BackendUnavailable, BackendMisconfigured):
            return "unavailable", "storage_unreachable"
        retain_until = _aware(record.retain_until)
        if lock is None or lock.mode != record.retention_mode:
            return "lock_drift", "retention_mode_weakened"
        if lock.retain_until is None or lock.retain_until + _RETENTION_SLACK < retain_until:
            return "lock_drift", "retention_shortened"
        if hold_expected and not lock.legal_hold:
            return "lock_drift", "legal_hold_not_applied"
    return "intact", None


async def verify_record(
    db: AsyncSession, vault, record: EvidenceVaultRecord, *, now: datetime | None = None
) -> VerifyOutcome:
    if record.state != "stored":
        raise VaultError("evidence_record_disposed", state="invalid", status_code=409)
    previous = record.integrity_state
    await reconcile_hold(db, vault, record)
    hold_expected = await hold_active_for(db, record)
    state, reason = await _check(vault, record, hold_expected)
    record.integrity_state = state
    record.last_verified_at = now or datetime.now(timezone.utc)
    record.last_verify_error = reason
    return VerifyOutcome(previous, state, reason)


async def read_verified(vault, record: EvidenceVaultRecord) -> bytes:
    """The stored bytes, returned only when they still match the record."""
    if record.state != "stored":
        raise VaultError("evidence_record_disposed", state="invalid", status_code=409)
    try:
        payload = await asyncio.to_thread(vault.get, record.object_key, record.storage_receipt)
    except ObjectMissing as exc:
        record.integrity_state = "missing"
        raise VaultError("evidence_object_missing", state="missing", status_code=409) from exc
    except (BackendUnavailable, BackendMisconfigured) as exc:
        raise VaultError("evidence_vault_unavailable", state="unavailable", status_code=503) from exc
    if _sha256(payload) != record.sha256:
        record.integrity_state = "tampered"
        raise VaultError("evidence_integrity_failed", state="tampered", status_code=409)
    return payload


# --------------------------------------------------------------------------- #
# Legal hold
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HoldOutcome:
    hold: EvidenceLegalHold
    covered: int
    storage_synced: int
    storage_pending: int


async def _covered_records(db: AsyncSession, hold: EvidenceLegalHold) -> list[EvidenceVaultRecord]:
    stmt = select(EvidenceVaultRecord).where(
        EvidenceVaultRecord.client_id == hold.client_id,
        EvidenceVaultRecord.state == "stored",
    )
    if hold.record_id is not None:
        stmt = stmt.where(EvidenceVaultRecord.id == hold.record_id)
    return list((await db.execute(stmt.order_by(EvidenceVaultRecord.stored_at))).scalars().all())


async def _sync_holds(db: AsyncSession, vault, hold: EvidenceLegalHold) -> tuple[int, int, int]:
    records = await _covered_records(db, hold)
    synced = pending = 0
    for record in records:
        if await reconcile_hold(db, vault, record):
            synced += 1
        else:
            pending += 1
    return len(records), synced, pending


async def place_hold(
    db: AsyncSession,
    vault,
    *,
    client_id: str,
    record: EvidenceVaultRecord | None,
    reason: str,
    operator_id: str | None,
    operator_email: str,
) -> HoldOutcome:
    """Place a hold. The row commits even when storage is unreachable — a hold
    must never be lost to an outage — and the storage hold is reconciled."""
    scope_key = record.id if record is not None else "*"
    conflict = (
        await db.execute(
            select(EvidenceLegalHold.id).where(
                EvidenceLegalHold.client_id == client_id,
                EvidenceLegalHold.scope_key == scope_key,
                EvidenceLegalHold.status == "active",
            )
        )
    ).scalar_one_or_none()
    if conflict is not None:
        raise VaultError("legal_hold_conflict", state="invalid", status_code=409)
    hold = EvidenceLegalHold(
        client_id=client_id,
        record_id=record.id if record is not None else None,
        scope_key=scope_key,
        status="active",
        reason=reason,
        placed_by_operator_id=operator_id,
        placed_by_email=operator_email,
        placed_at=datetime.now(timezone.utc),
    )
    db.add(hold)
    try:
        await db.flush()
    except IntegrityError as exc:
        # Lost a race with a concurrent placement on the same scope: the
        # partial unique index is the arbiter, and the answer is the same 409.
        raise VaultError("legal_hold_conflict", state="invalid", status_code=409) from exc
    covered, synced, pending = (0, 0, 0) if vault is None else await _sync_holds(db, vault, hold)
    if vault is None:
        covered = len(await _covered_records(db, hold))
    return HoldOutcome(hold, covered, synced, pending)


async def release_hold(
    db: AsyncSession,
    vault,
    hold: EvidenceLegalHold,
    *,
    reason: str,
    operator_email: str,
) -> HoldOutcome:
    """Release a hold. A storage hold is lifted only for packages no other
    active hold still covers; an unreachable backend leaves it ON (the safe
    direction) and the sweep lifts it later."""
    if hold.status != "active":
        raise VaultError("legal_hold_not_active", state="invalid", status_code=409)
    hold.status = "released"
    hold.released_at = datetime.now(timezone.utc)
    hold.released_by_email = operator_email
    hold.release_reason = reason
    await db.flush()
    if vault is None:
        return HoldOutcome(hold, len(await _covered_records(db, hold)), 0, 0)
    covered, synced, pending = await _sync_holds(db, vault, hold)
    return HoldOutcome(hold, covered, synced, pending)


# --------------------------------------------------------------------------- #
# Disposal
# --------------------------------------------------------------------------- #
def deletion_denial(
    record: EvidenceVaultRecord, *, hold_active: bool, now: datetime
) -> str | None:
    """Why ``record`` may not be disposed of right now, or None if it may.

    Returns one stable refusal code. The caller audits the refusal and answers
    409 with it, so the code is operator-visible and must not leak anything the
    record view does not already show.
    """
    if record.state != "stored":
        return "evidence_record_disposed"
    # A hold outranks retention: it is the reason that survives expiry, so it
    # is the one an operator needs to see.
    if hold_active:
        return "evidence_legal_hold_active"
    if _aware(record.retain_until) > now:
        return "evidence_retention_active"
    return None


async def dispose_record(
    db: AsyncSession, vault, record: EvidenceVaultRecord, *, operator_email: str,
    now: datetime | None = None,
) -> None:
    """Delete the stored object once policy allows it. Raises VaultError with
    the refusal code otherwise; the row is kept as a ``deleted`` tombstone."""
    now = now or datetime.now(timezone.utc)
    denial = deletion_denial(record, hold_active=await hold_active_for(db, record), now=now)
    if denial is not None:
        raise VaultError(denial, state="denied", status_code=409)
    try:
        await asyncio.to_thread(vault.delete, record.object_key, record.storage_receipt)
    except DeletionRefused as exc:
        # NodeLink thought retention had elapsed but storage disagrees: the
        # storage clock/lock wins, and the drift is worth investigating.
        record.integrity_state = "lock_drift"
        record.last_verify_error = "storage_refused_deletion"
        raise VaultError("evidence_storage_refused_deletion", state="denied", status_code=409) from exc
    except (BackendUnavailable, BackendMisconfigured) as exc:
        raise VaultError("evidence_vault_unavailable", state="unavailable", status_code=503) from exc
    except ObjectMissing:
        pass  # already gone (e.g. lifecycle rule); record the disposal anyway
    record.state = "deleted"
    record.deleted_at = now
    record.deleted_by_email = operator_email


# --------------------------------------------------------------------------- #
# Sweep + status
# --------------------------------------------------------------------------- #
@dataclass
class SweepResult:
    verified: int = 0
    newly_failing: list[tuple[EvidenceVaultRecord, VerifyOutcome]] | None = None
    holds_reconciled: int = 0
    holds_pending: int = 0


async def sweep(db: AsyncSession, vault, s: Settings = settings) -> SweepResult:
    """One bounded pass: reconcile storage holds that drifted from the hold
    rows (e.g. placed during an outage), then re-verify the least recently
    verified packages. Caller owns the transaction and the audit of failures."""
    result = SweepResult(newly_failing=[])
    batch = max(1, s.evidence_vault_verify_batch_size)
    if vault.enforces_lock:
        covered = _covering_hold_clause(EvidenceVaultRecord.client_id, EvidenceVaultRecord.id)
        drifted = (
            await db.execute(
                select(EvidenceVaultRecord)
                .where(
                    EvidenceVaultRecord.state == "stored",
                    EvidenceVaultRecord.backend == vault.name,
                    or_(
                        and_(covered, EvidenceVaultRecord.backend_legal_hold.is_(False)),
                        and_(~covered, EvidenceVaultRecord.backend_legal_hold.is_(True)),
                    ),
                )
                .limit(batch)
            )
        ).scalars().all()
        for record in drifted:
            if await reconcile_hold(db, vault, record):
                result.holds_reconciled += 1
            else:
                result.holds_pending += 1

    queue = (
        await db.execute(
            select(EvidenceVaultRecord)
            .where(EvidenceVaultRecord.state == "stored", EvidenceVaultRecord.backend == vault.name)
            .order_by(EvidenceVaultRecord.last_verified_at.asc().nulls_first())
            .limit(batch)
        )
    ).scalars().all()
    for record in queue:
        outcome = await verify_record(db, vault, record)
        result.verified += 1
        if outcome.integrity_state in FAILING_STATES and outcome.previous_state != outcome.integrity_state:
            result.newly_failing.append((record, outcome))
    return result


async def vault_status(db: AsyncSession, tenant_filter, s: Settings = settings) -> dict:
    """Operator-visible state, restricted by the caller's tenant filter."""
    backend = (s.evidence_vault_backend or "none").strip().lower()
    enforcement = {"none": "disabled", "filesystem": "application_only", "s3": "storage_object_lock"}.get(
        backend, "misconfigured"
    )
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(EvidenceVaultRecord.state, EvidenceVaultRecord.integrity_state, func.count())
            .where(tenant_filter(EvidenceVaultRecord.client_id))
            .group_by(EvidenceVaultRecord.state, EvidenceVaultRecord.integrity_state)
        )
    ).all()
    by_state: dict[str, int] = {}
    by_integrity: dict[str, int] = {}
    for state, integrity, count in rows:
        by_state[state] = by_state.get(state, 0) + count
        if state == "stored":
            by_integrity[integrity] = by_integrity.get(integrity, 0) + count
    covered = _covering_hold_clause(EvidenceVaultRecord.client_id, EvidenceVaultRecord.id)
    disposable = (
        await db.execute(
            select(func.count()).select_from(EvidenceVaultRecord).where(
                tenant_filter(EvidenceVaultRecord.client_id),
                EvidenceVaultRecord.state == "stored",
                EvidenceVaultRecord.retain_until <= now,
                ~covered,
            )
        )
    ).scalar_one()
    hold_pending = 0
    if enforcement == "storage_object_lock":
        hold_pending = (
            await db.execute(
                select(func.count()).select_from(EvidenceVaultRecord).where(
                    tenant_filter(EvidenceVaultRecord.client_id),
                    EvidenceVaultRecord.state == "stored",
                    or_(
                        and_(covered, EvidenceVaultRecord.backend_legal_hold.is_(False)),
                        and_(~covered, EvidenceVaultRecord.backend_legal_hold.is_(True)),
                    ),
                )
            )
        ).scalar_one()
    active_holds = (
        await db.execute(
            select(func.count()).select_from(EvidenceLegalHold).where(
                tenant_filter(EvidenceLegalHold.client_id),
                EvidenceLegalHold.status == "active",
            )
        )
    ).scalar_one()
    failing = sum(by_integrity.get(state, 0) for state in FAILING_STATES)
    return {
        "backend": None if backend == "none" else backend,
        "enforcement": enforcement,
        "records": {"by_state": by_state, "stored_by_integrity": by_integrity},
        "retention_elapsed_unheld": disposable,
        "active_legal_holds": active_holds,
        "storage_hold_reconciliation_pending": hold_pending,
        "integrity_failures": failing,
        # A disabled vault is only an alert once evidence depends on it.
        "alert": failing > 0
        or hold_pending > 0
        or (enforcement in ("disabled", "misconfigured") and by_state.get("stored", 0) > 0),
    }
