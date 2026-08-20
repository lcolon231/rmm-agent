# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped deterministic compliance evidence exports (issues #79/#80)."""
from __future__ import annotations

import hashlib
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit, evidence_bundles, evidence_packages
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.tenant_scope import assert_client_visible
from app.models.models import Client, Operator, OperatorRole

router = APIRouter(tags=["evidence"])


@router.get("/evidence/bundles/export")
async def export_evidence_bundle(
    request: Request,
    organization_id: str = Query(min_length=1, max_length=36),
    format: Literal["json", "csv", "pdf", "zip"] = "json",
    from_seq: int = Query(default=1, ge=1),
    through_seq: int | None = Query(default=None, ge=0),
    record_limit: int = Query(
        default=evidence_bundles.DEFAULT_RECORD_LIMIT,
        ge=1,
        le=evidence_bundles.MAX_RECORD_LIMIT,
    ),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Export one tenant's evidence as JSON, CSV, PDF, or a signed ZIP.

    ``through_seq`` pins the global append-only audit prefix. Repeating a
    request with the returned value produces byte-identical output while the
    underlying domain snapshot is unchanged; the audit event emitted for the
    download is appended only after the artifact has been constructed.
    """
    tenant = await db.get(Client, organization_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await assert_client_visible(
        operator, tenant.id, db, detail="Tenant not found"
    )
    try:
        artifact = await evidence_bundles.build_bundle(
            db,
            tenant=tenant,
            from_seq=from_seq,
            through_seq=through_seq,
            record_limit=record_limit,
        )
    except evidence_bundles.EvidenceBundleError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "state": exc.state},
        ) from exc

    package_id: str | None = None
    signing_key_id: str | None = None
    if format == "zip":
        try:
            package = evidence_packages.build_signed_package(artifact)
        except evidence_packages.EvidencePackageError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code, "state": exc.state},
            ) from exc
        content = package.content
        package_id = package.package_id
        signing_key_id = package.signing_key_id
        extension = "zip"
        media_type = evidence_packages.ZIP_MEDIA_TYPE
    elif format == "pdf":
        try:
            content = evidence_packages.build_pdf(artifact)
        except evidence_packages.EvidencePackageError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code, "state": exc.state},
            ) from exc
        extension = "pdf"
        media_type = evidence_packages.PDF_MEDIA_TYPE
    elif format == "csv":
        content = evidence_bundles.serialize_csv(artifact)
        extension = "csv"
        media_type = evidence_bundles.CSV_MEDIA_TYPE
    else:
        content = evidence_bundles.serialize_json(artifact)
        extension = "json"
        media_type = evidence_bundles.JSON_MEDIA_TYPE
    content_sha256 = hashlib.sha256(content).hexdigest()

    await audit.record(
        db,
        action="evidence_bundle.exported",
        actor=operator.email,
        actor_user_id=operator.id,
        organization_id=tenant.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "bundle_id": artifact.bundle_id,
            "package_id": package_id,
            "signing_key_id": signing_key_id,
            "tenant_id": tenant.id,
            "format": format,
            "from_seq": from_seq,
            "through_seq": artifact.through_seq,
            "record_count": artifact.total_records,
            "content_sha256": content_sha256,
        },
    )
    identity = package_id or artifact.bundle_id
    filename = f"nodelink-evidence-{tenant.id}-{identity[:12]}.{extension}"
    response_headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
        "ETag": f'"sha256:{content_sha256}"',
        "X-NodeLink-Evidence-Bundle-ID": artifact.bundle_id,
        "X-NodeLink-Audit-Through-Seq": str(artifact.through_seq),
    }
    if package_id is not None:
        response_headers["X-NodeLink-Evidence-Package-ID"] = package_id
    return Response(
        content=content,
        media_type=media_type,
        headers=response_headers,
    )
