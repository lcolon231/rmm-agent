# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence vault, retention, and legal-hold API (issue #81).

Authorization follows the tenant boundary (issue #66): reads need the global
``readonly`` role and visibility of the tenant; storing needs ``operator`` and
``client_operator``; placing/releasing holds and disposing of evidence need
``admin`` and ``client_admin``. Every resource that resolves to another tenant
answers 404, exactly like one that does not exist.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit, evidence_bundles, evidence_packages, evidence_vault
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.tenant_scope import assert_client_action, assert_client_visible, client_id_filter
from app.models.models import (
    Client,
    ClientRole,
    EvidenceLegalHold,
    EvidenceVaultRecord,
    Operator,
    OperatorRole,
)

router = APIRouter(tags=["evidence-vault"])

_NOT_FOUND = {"code": "evidence_record_not_found"}
_HOLD_NOT_FOUND = {"code": "legal_hold_not_found"}


class StoreRequest(BaseModel):
    organization_id: str = Field(min_length=1, max_length=36)
    from_seq: int = Field(default=1, ge=1)
    through_seq: int | None = Field(default=None, ge=0)
    record_limit: int = Field(
        default=evidence_bundles.DEFAULT_RECORD_LIMIT,
        ge=1,
        le=evidence_bundles.MAX_RECORD_LIMIT,
    )
    retention_days: int | None = Field(default=None, ge=1)


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class HoldRequest(ReasonRequest):
    organization_id: str = Field(min_length=1, max_length=36)
    record_id: str | None = Field(default=None, min_length=1, max_length=36)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _record_view(record: EvidenceVaultRecord, *, hold_active: bool) -> dict:
    return {
        "id": record.id,
        "organization_id": record.client_id,
        "kind": record.kind,
        "package_id": record.package_id,
        "bundle_id": record.bundle_id,
        "from_seq": record.from_seq,
        "through_seq": record.through_seq,
        "record_count": record.record_count,
        "signing_key_id": record.signing_key_id,
        "backend": record.backend,
        "uri": record.uri,
        "sha256": record.sha256,
        "size_bytes": record.size_bytes,
        "storage_receipt": record.storage_receipt,
        "receipt_intact": evidence_vault.receipt_digest(record.storage_receipt) == record.receipt_sha256,
        "retention_mode": record.retention_mode,
        "retain_until": _iso(record.retain_until),
        "legal_hold_active": hold_active,
        "storage_legal_hold": record.backend_legal_hold,
        "state": record.state,
        "integrity_state": record.integrity_state,
        "last_verified_at": _iso(record.last_verified_at),
        "last_verify_error": record.last_verify_error,
        "stored_at": _iso(record.stored_at),
        "stored_by": record.stored_by_email,
        "deleted_at": _iso(record.deleted_at),
        "deleted_by": record.deleted_by_email,
    }


def _hold_view(hold: EvidenceLegalHold) -> dict:
    return {
        "id": hold.id,
        "organization_id": hold.client_id,
        "record_id": hold.record_id,
        "scope": "record" if hold.record_id else "tenant",
        "status": hold.status,
        "reason": hold.reason,
        "placed_by": hold.placed_by_email,
        "placed_at": _iso(hold.placed_at),
        "released_by": hold.released_by_email,
        "released_at": _iso(hold.released_at),
        "release_reason": hold.release_reason,
    }


def _raise(exc: evidence_vault.VaultError) -> None:
    raise HTTPException(
        status_code=exc.status_code, detail={"code": exc.code, "state": exc.state}
    ) from exc


async def _visible_record(
    db: AsyncSession, operator: Operator, record_id: str
) -> EvidenceVaultRecord:
    record = await db.get(EvidenceVaultRecord, record_id)
    await assert_client_visible(
        operator, record.client_id if record else None, db, detail=_NOT_FOUND
    )
    assert record is not None
    return record


def _request_meta(request: Request) -> dict:
    return {
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


@router.post("/evidence/vault/records")
async def store_evidence(
    body: StoreRequest,
    request: Request,
    response: Response,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Build a signed package for one tenant and retain it immutably.

    201 when newly stored, 200 when the identical package (same pinned
    ``through_seq`` and unchanged inputs) is already retained.
    """
    tenant = await db.get(Client, body.organization_id)
    await assert_client_action(
        operator, tenant.id if tenant else None, db,
        minimum=ClientRole.client_operator, detail={"code": "tenant_not_found"},
    )
    assert tenant is not None
    try:
        vault = evidence_vault.require_vault()
        retention_days = evidence_vault.resolve_retention_days(body.retention_days)
    except evidence_vault.VaultError as exc:
        _raise(exc)
    try:
        artifact = await evidence_bundles.build_bundle(
            db,
            tenant=tenant,
            from_seq=body.from_seq,
            through_seq=body.through_seq,
            record_limit=body.record_limit,
        )
        package = evidence_packages.build_signed_package(artifact)
    except (evidence_bundles.EvidenceBundleError, evidence_packages.EvidencePackageError) as exc:
        raise HTTPException(
            status_code=exc.status_code, detail={"code": exc.code, "state": exc.state}
        ) from exc
    try:
        outcome = await evidence_vault.store_package(
            db,
            vault,
            client_id=tenant.id,
            artifact=artifact,
            from_seq=body.from_seq,
            package=package,
            retention_days=retention_days,
            operator_id=operator.id,
            operator_email=operator.email,
        )
    except evidence_vault.VaultError as exc:
        # Nothing was written to the session before the storage call, so the
        # failure event commits on its own.
        await audit.record(
            db,
            action="evidence_vault.store_failed",
            actor=operator.email,
            actor_user_id=operator.id,
            organization_id=tenant.id,
            **_request_meta(request),
            detail={
                "tenant_id": tenant.id,
                "package_id": package.package_id,
                "backend": vault.name,
                "code": exc.code,
            },
        )
        await db.commit()
        _raise(exc)
    record = outcome.record
    hold_active = await evidence_vault.hold_active_for(db, record)
    if outcome.created:
        await audit.record(
            db,
            action="evidence_vault.stored",
            actor=operator.email,
            actor_user_id=operator.id,
            organization_id=tenant.id,
            **_request_meta(request),
            detail={
                "record_id": record.id,
                "tenant_id": tenant.id,
                "package_id": record.package_id,
                "bundle_id": record.bundle_id,
                "backend": record.backend,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "retention_mode": record.retention_mode,
                "retain_until": _iso(record.retain_until),
                "legal_hold": hold_active,
            },
        )
    response.status_code = status.HTTP_201_CREATED if outcome.created else status.HTTP_200_OK
    return {"created": outcome.created, "record": _record_view(record, hold_active=hold_active)}


@router.get("/evidence/vault/records")
async def list_evidence(
    organization_id: str | None = Query(default=None, max_length=36),
    state: Literal["stored", "deleted"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(EvidenceVaultRecord).where(
        client_id_filter(operator, EvidenceVaultRecord.client_id)
    )
    if organization_id is not None:
        stmt = stmt.where(EvidenceVaultRecord.client_id == organization_id)
    if state is not None:
        stmt = stmt.where(EvidenceVaultRecord.state == state)
    records = (
        await db.execute(
            stmt.order_by(EvidenceVaultRecord.stored_at.desc(), EvidenceVaultRecord.id)
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    items = [
        _record_view(r, hold_active=await evidence_vault.hold_active_for(db, r)) for r in records
    ]
    return {"items": items, "limit": limit, "offset": offset}


@router.get("/evidence/vault/status")
async def evidence_vault_status(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    return await evidence_vault.vault_status(
        db, lambda column: client_id_filter(operator, column)
    )


@router.get("/evidence/vault/records/{record_id}")
async def get_evidence(
    record_id: str,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    record = await _visible_record(db, operator, record_id)
    return _record_view(record, hold_active=await evidence_vault.hold_active_for(db, record))


@router.get("/evidence/vault/records/{record_id}/content")
async def download_evidence(
    record_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """The retained package bytes, released only if they still match the
    recorded digest. Verify independently with verify_evidence_package.py."""
    record = await _visible_record(db, operator, record_id)
    try:
        vault = evidence_vault.require_vault()
        evidence_vault.require_same_backend(vault, record)
        payload = await evidence_vault.read_verified(vault, record)
    except evidence_vault.VaultError as exc:
        await db.commit()  # keep a detected missing/tampered state
        _raise(exc)
    await audit.record(
        db,
        action="evidence_vault.retrieved",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=record.client_id,
        **_request_meta(request),
        detail={
            "record_id": record.id,
            "tenant_id": record.client_id,
            "package_id": record.package_id,
            "sha256": record.sha256,
        },
    )
    return Response(
        content=payload,
        media_type=evidence_packages.ZIP_MEDIA_TYPE,
        headers={
            "Content-Disposition": (
                f'attachment; filename="nodelink-evidence-{record.client_id}-'
                f'{record.package_id[:12]}.zip"'
            ),
            "Cache-Control": "no-store",
            "ETag": f'"sha256:{record.sha256}"',
            "X-NodeLink-Evidence-Package-ID": record.package_id,
        },
    )


@router.post("/evidence/vault/records/{record_id}/verify")
async def verify_evidence(
    record_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    record = await _visible_record(db, operator, record_id)
    try:
        vault = evidence_vault.require_vault()
        evidence_vault.require_same_backend(vault, record)
        outcome = await evidence_vault.verify_record(db, vault, record)
    except evidence_vault.VaultError as exc:
        _raise(exc)
    await audit.record(
        db,
        action="evidence_vault.verified",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=record.client_id,
        **_request_meta(request),
        detail={
            "record_id": record.id,
            "tenant_id": record.client_id,
            "trigger": "operator",
            "integrity_state": outcome.integrity_state,
            "reason": outcome.reason,
        },
    )
    return _record_view(record, hold_active=await evidence_vault.hold_active_for(db, record))


@router.post("/evidence/vault/records/{record_id}/dispose")
async def dispose_evidence(
    record_id: str,
    body: ReasonRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Delete a retained package after retention, with no active hold. Every
    refusal is audited; the ledger row is kept as a tombstone."""
    record = await db.get(EvidenceVaultRecord, record_id)
    await assert_client_action(
        operator, record.client_id if record else None, db,
        minimum=ClientRole.client_admin, detail=_NOT_FOUND,
    )
    assert record is not None
    try:
        vault = evidence_vault.require_vault()
        evidence_vault.require_same_backend(vault, record)
        await evidence_vault.dispose_record(db, vault, record, operator_email=operator.email)
    except evidence_vault.VaultError as exc:
        if exc.state == "denied":
            await audit.record(
                db,
                action="evidence_vault.deletion_denied",
                actor=operator.email,
                actor_user_id=operator.id,
                organization_id=record.client_id,
                **_request_meta(request),
                detail={
                    "record_id": record.id,
                    "tenant_id": record.client_id,
                    "code": exc.code,
                    "retain_until": _iso(record.retain_until),
                },
            )
            await db.commit()
        _raise(exc)
    await audit.record(
        db,
        action="evidence_vault.deleted",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=record.client_id,
        **_request_meta(request),
        detail={
            "record_id": record.id,
            "tenant_id": record.client_id,
            "package_id": record.package_id,
            "sha256": record.sha256,
            "reason": body.reason,
        },
    )
    return _record_view(record, hold_active=False)


@router.post("/evidence/legal-holds", status_code=status.HTTP_201_CREATED)
async def place_legal_hold(
    body: HoldRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Suspend deletion for one package (``record_id``) or a whole tenant.

    The hold is recorded even when storage is unreachable; the response says
    how many packages already carry the storage-level hold and how many are
    pending reconciliation.
    """
    tenant = await db.get(Client, body.organization_id)
    await assert_client_action(
        operator, tenant.id if tenant else None, db,
        minimum=ClientRole.client_admin, detail={"code": "tenant_not_found"},
    )
    assert tenant is not None
    record = None
    if body.record_id is not None:
        record = await db.get(EvidenceVaultRecord, body.record_id)
        if record is None or record.client_id != tenant.id:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        if record.state != "stored":
            raise HTTPException(
                status_code=409, detail={"code": "evidence_record_disposed", "state": "invalid"}
            )
    try:
        vault = evidence_vault.build_vault()
    except evidence_vault.BackendMisconfigured:
        vault = None  # the hold row alone still blocks disposal
    try:
        outcome = await evidence_vault.place_hold(
            db,
            vault,
            client_id=tenant.id,
            record=record,
            reason=body.reason,
            operator_id=operator.id,
            operator_email=operator.email,
        )
    except evidence_vault.VaultError as exc:
        _raise(exc)
    hold = outcome.hold
    await audit.record(
        db,
        action="evidence_legal_hold.placed",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=tenant.id,
        **_request_meta(request),
        detail={
            "hold_id": hold.id,
            "tenant_id": tenant.id,
            "record_id": hold.record_id,
            "scope": "record" if hold.record_id else "tenant",
            "reason": body.reason,
            "covered_records": outcome.covered,
            "storage_pending": outcome.storage_pending,
        },
    )
    return {
        "hold": _hold_view(hold),
        "covered_records": outcome.covered,
        "storage_synced": outcome.storage_synced,
        "storage_pending": outcome.storage_pending,
    }


@router.get("/evidence/legal-holds")
async def list_legal_holds(
    organization_id: str | None = Query(default=None, max_length=36),
    hold_status: Literal["active", "released"] | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(EvidenceLegalHold).where(client_id_filter(operator, EvidenceLegalHold.client_id))
    if organization_id is not None:
        stmt = stmt.where(EvidenceLegalHold.client_id == organization_id)
    if hold_status is not None:
        stmt = stmt.where(EvidenceLegalHold.status == hold_status)
    holds = (
        await db.execute(
            stmt.order_by(EvidenceLegalHold.placed_at.desc(), EvidenceLegalHold.id)
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {"items": [_hold_view(h) for h in holds], "limit": limit, "offset": offset}


@router.post("/evidence/legal-holds/{hold_id}/release")
async def release_legal_hold(
    hold_id: str,
    body: ReasonRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    hold = await db.get(EvidenceLegalHold, hold_id)
    await assert_client_action(
        operator, hold.client_id if hold else None, db,
        minimum=ClientRole.client_admin, detail=_HOLD_NOT_FOUND,
    )
    assert hold is not None
    try:
        vault = evidence_vault.build_vault()
    except evidence_vault.BackendMisconfigured:
        vault = None
    try:
        outcome = await evidence_vault.release_hold(
            db, vault, hold, reason=body.reason, operator_email=operator.email
        )
    except evidence_vault.VaultError as exc:
        _raise(exc)
    await audit.record(
        db,
        action="evidence_legal_hold.released",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=hold.client_id,
        **_request_meta(request),
        detail={
            "hold_id": hold.id,
            "tenant_id": hold.client_id,
            "record_id": hold.record_id,
            "scope": "record" if hold.record_id else "tenant",
            "reason": body.reason,
            "covered_records": outcome.covered,
            "storage_pending": outcome.storage_pending,
        },
    )
    return {
        "hold": _hold_view(hold),
        "covered_records": outcome.covered,
        "storage_synced": outcome.storage_synced,
        "storage_pending": outcome.storage_pending,
    }
