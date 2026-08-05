# SPDX-License-Identifier: AGPL-3.0-only
"""Role-gated immutable script library endpoints (issue #47)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.models.models import (
    Operator,
    OperatorRole,
    ScriptLibraryItem,
    ScriptVersion,
    ScriptVersionReview,
)
from app.schemas.script_library import (
    ScriptCreate,
    ScriptDeprecate,
    ScriptItemDetailOut,
    ScriptItemOut,
    ScriptListOut,
    ScriptReviewCreate,
    ScriptReviewOut,
    ScriptVersionDetailOut,
    ScriptVersionInput,
    ScriptVersionOut,
)


router = APIRouter(
    prefix="/script-library",
    tags=["script-library"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> tuple[str, int]:
    encoded = value.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _request_evidence(request: Request, operator: Operator) -> dict:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def _review_out(review: ScriptVersionReview | None) -> ScriptReviewOut | None:
    if review is None:
        return None
    return ScriptReviewOut(
        state=review.state,
        reviewed_by=review.reviewed_by,
        reason_sha256=review.reason_sha256,
        reason_bytes=review.reason_bytes,
        created_at=review.created_at,
    )


def _version_out(
    version: ScriptVersion,
    review: ScriptVersionReview | None,
) -> ScriptVersionOut:
    return ScriptVersionOut(
        id=version.id,
        version=version.version,
        language=version.language,
        content_sha256=version.content_sha256,
        content_bytes=version.content_bytes,
        description=version.description,
        tags=version.tags,
        supported_platforms=version.supported_platforms,
        created_by=version.created_by,
        created_at=version.created_at,
        review=_review_out(review),
    )


def _item_out(
    item: ScriptLibraryItem,
    version: ScriptVersion,
    review: ScriptVersionReview | None,
) -> ScriptItemOut:
    return ScriptItemOut(
        id=item.id,
        name=item.name,
        latest_version=item.latest_version,
        record_version=item.record_version,
        deprecated_at=item.deprecated_at,
        deprecated_by=item.deprecated_by,
        created_by=item.created_by,
        created_at=item.created_at,
        updated_at=item.updated_at,
        latest=_version_out(version, review),
    )


async def _detail(db: AsyncSession, script_id: str) -> ScriptItemDetailOut:
    item = await db.get(ScriptLibraryItem, script_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Script not found")
    rows = (
        await db.execute(
            select(ScriptVersion, ScriptVersionReview)
            .outerjoin(
                ScriptVersionReview,
                ScriptVersionReview.script_version_id == ScriptVersion.id,
            )
            .where(ScriptVersion.script_id == item.id)
            .order_by(ScriptVersion.version.desc())
        )
    ).all()
    versions = [_version_out(version, review) for version, review in rows]
    latest_version, latest_review = rows[0]
    return ScriptItemDetailOut(
        **_item_out(item, latest_version, latest_review).model_dump(),
        versions=versions,
    )


def _new_version(
    item: ScriptLibraryItem,
    body: ScriptVersionInput,
    operator: Operator,
    version_number: int,
) -> ScriptVersion:
    content_sha256, content_bytes = _digest(body.content)
    if content_bytes > settings.script_library_max_content_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"code": "script_content_too_large"},
        )
    return ScriptVersion(
        script_id=item.id,
        version=version_number,
        language=body.language,
        content=body.content,
        content_sha256=content_sha256,
        content_bytes=content_bytes,
        description=body.description,
        tags=body.tags,
        supported_platforms=body.supported_platforms,
        created_by=operator.email,
    )


@router.get("", response_model=ScriptListOut)
async def list_scripts(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count()).select_from(ScriptLibraryItem)) or 0
    rows = (
        await db.execute(
            select(ScriptLibraryItem, ScriptVersion, ScriptVersionReview)
            .join(
                ScriptVersion,
                (ScriptVersion.script_id == ScriptLibraryItem.id)
                & (ScriptVersion.version == ScriptLibraryItem.latest_version),
            )
            .outerjoin(
                ScriptVersionReview,
                ScriptVersionReview.script_version_id == ScriptVersion.id,
            )
            .order_by(
                ScriptLibraryItem.deprecated_at.asc().nullsfirst(),
                ScriptLibraryItem.name,
                ScriptLibraryItem.id,
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    items = [_item_out(item, version, review) for item, version, review in rows]
    await audit.record(
        db,
        action="script_library.list_viewed",
        **_request_evidence(request, operator),
        detail={
            "page": page,
            "page_size": page_size,
            "result_count": len(items),
            "total": total,
        },
    )
    return ScriptListOut(items=items, page=page, page_size=page_size, total=total)


@router.post("", response_model=ScriptItemDetailOut, status_code=status.HTTP_201_CREATED)
async def create_script(
    body: ScriptCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    count = await db.scalar(select(func.count()).select_from(ScriptLibraryItem)) or 0
    if count >= settings.script_library_max_items:
        raise HTTPException(status_code=409, detail={"code": "script_library_limit_reached"})
    normalized_name = body.name.casefold()
    if await db.scalar(
        select(ScriptLibraryItem.id).where(
            ScriptLibraryItem.normalized_name == normalized_name
        )
    ):
        raise HTTPException(status_code=409, detail={"code": "script_name_exists"})
    item = ScriptLibraryItem(
        name=body.name,
        normalized_name=normalized_name,
        created_by=operator.email,
    )
    db.add(item)
    try:
        await db.flush()
        version = _new_version(item, body, operator, 1)
        db.add(version)
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail={"code": "script_name_exists"}) from exc
    await audit.record(
        db,
        action="script_library.created",
        **_request_evidence(request, operator),
        detail={
            "script_id": item.id,
            "version": 1,
            "language": version.language.value,
            "content_sha256": version.content_sha256,
            "content_bytes": version.content_bytes,
            "tags": version.tags,
            "supported_platforms": version.supported_platforms,
            "name": item.name,
        },
    )
    return await _detail(db, item.id)


@router.get("/{script_id}", response_model=ScriptItemDetailOut)
async def get_script(
    script_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    detail = await _detail(db, script_id)
    await audit.record(
        db,
        action="script_library.item_viewed",
        **_request_evidence(request, operator),
        detail={"script_id": script_id, "version_count": len(detail.versions)},
    )
    return detail


@router.get(
    "/{script_id}/versions/{version_number}", response_model=ScriptVersionDetailOut
)
async def get_script_version(
    script_id: str,
    version_number: int,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            select(ScriptVersion, ScriptVersionReview)
            .outerjoin(
                ScriptVersionReview,
                ScriptVersionReview.script_version_id == ScriptVersion.id,
            )
            .where(
                ScriptVersion.script_id == script_id,
                ScriptVersion.version == version_number,
            )
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Script version not found")
    version, review = row
    await audit.record(
        db,
        action="script_library.version_viewed",
        **_request_evidence(request, operator),
        detail={
            "script_id": script_id,
            "version": version_number,
            "content_sha256": version.content_sha256,
            "content_bytes": version.content_bytes,
        },
    )
    return ScriptVersionDetailOut(
        **_version_out(version, review).model_dump(), content=version.content
    )


@router.post(
    "/{script_id}/versions",
    response_model=ScriptItemDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_script_version(
    script_id: str,
    body: ScriptVersionInput,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    item = (
        await db.execute(
            select(ScriptLibraryItem)
            .where(ScriptLibraryItem.id == script_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Script not found")
    if item.deprecated_at is not None:
        raise HTTPException(status_code=409, detail={"code": "script_deprecated"})
    if item.latest_version >= settings.script_library_max_versions_per_script:
        raise HTTPException(status_code=409, detail={"code": "script_version_limit_reached"})
    version_number = item.latest_version + 1
    version = _new_version(item, body, operator, version_number)
    item.latest_version = version_number
    item.record_version += 1
    item.updated_at = _now()
    db.add(version)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail={"code": "script_version_conflict"}) from exc
    await audit.record(
        db,
        action="script_library.version_created",
        **_request_evidence(request, operator),
        detail={
            "script_id": item.id,
            "version": version.version,
            "language": version.language.value,
            "content_sha256": version.content_sha256,
            "content_bytes": version.content_bytes,
            "tags": version.tags,
            "supported_platforms": version.supported_platforms,
        },
    )
    return await _detail(db, item.id)


@router.post(
    "/{script_id}/versions/{version_number}/review",
    response_model=ScriptItemDetailOut,
)
async def review_script_version(
    script_id: str,
    version_number: int,
    body: ScriptReviewCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    version = await db.scalar(
        select(ScriptVersion).where(
            ScriptVersion.script_id == script_id,
            ScriptVersion.version == version_number,
        )
    )
    if version is None:
        raise HTTPException(status_code=404, detail="Script version not found")
    reason_sha256, reason_bytes = _digest(body.reason)
    db.add(
        ScriptVersionReview(
            script_version_id=version.id,
            state=body.state,
            reviewed_by=operator.email,
            reason_sha256=reason_sha256,
            reason_bytes=reason_bytes,
        )
    )
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail={"code": "review_already_final"}) from exc
    await audit.record(
        db,
        action="script_library.reviewed",
        **_request_evidence(request, operator),
        detail={
            "script_id": script_id,
            "version": version_number,
            "state": body.state.value,
            "reason": body.reason,
        },
    )
    return await _detail(db, script_id)


@router.post("/{script_id}/deprecate", response_model=ScriptItemDetailOut)
async def deprecate_script(
    script_id: str,
    body: ScriptDeprecate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    item = (
        await db.execute(
            select(ScriptLibraryItem)
            .where(ScriptLibraryItem.id == script_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Script not found")
    if item.deprecated_at is not None:
        if item.last_deprecation_request_id == body.request_id:
            return await _detail(db, item.id)
        raise HTTPException(status_code=409, detail={"code": "script_already_deprecated"})
    if item.record_version != body.expected_record_version:
        raise HTTPException(status_code=409, detail={"code": "script_version_conflict"})
    previous_record_version = item.record_version
    reason_sha256, reason_bytes = _digest(body.reason)
    item.deprecated_at = _now()
    item.deprecated_by = operator.email
    item.last_deprecation_request_id = body.request_id
    item.deprecation_reason_sha256 = reason_sha256
    item.deprecation_reason_bytes = reason_bytes
    item.record_version += 1
    item.updated_at = item.deprecated_at
    await db.flush()
    await audit.record(
        db,
        action="script_library.deprecated",
        **_request_evidence(request, operator),
        detail={
            "script_id": script_id,
            "request_id": body.request_id,
            "previous_record_version": previous_record_version,
            "record_version": item.record_version,
            "reason": body.reason,
        },
    )
    return await _detail(db, item.id)
