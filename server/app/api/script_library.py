# SPDX-License-Identifier: AGPL-3.0-only
"""Role-gated immutable script library endpoints (issue #47)."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit, script_parameters
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.models.models import (
    Operator,
    OperatorRole,
    ScriptLibraryItem,
    ScriptParameterDefinition,
    ScriptParameterValueSet,
    ScriptVersion,
    ScriptVersionReview,
)
from app.schemas.script_library import (
    ScriptCreate,
    ScriptDeprecate,
    ScriptItemDetailOut,
    ScriptItemOut,
    ScriptListOut,
    ScriptParameterInput,
    ScriptParameterOut,
    ScriptParameterValueSetOut,
    ScriptParameterValuesCreate,
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


def _parameter_out(definition: ScriptParameterDefinition) -> ScriptParameterOut:
    return ScriptParameterOut(
        key=definition.key,
        label=definition.label,
        description=definition.description,
        kind=definition.kind,
        required=definition.required,
        has_default=definition.has_default,
        default_value=definition.default_value if definition.has_default else None,
        min_length=definition.min_length,
        max_length=definition.max_length,
        minimum=definition.minimum,
        maximum=definition.maximum,
        choices=definition.choices,
    )


def _version_out(
    version: ScriptVersion,
    review: ScriptVersionReview | None,
    definitions: list[ScriptParameterDefinition] | None = None,
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
        parameters=[_parameter_out(item) for item in (definitions or [])],
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
    version_ids = [version.id for version, _ in rows]
    definition_rows = list(
        (
            await db.execute(
                select(ScriptParameterDefinition)
                .where(ScriptParameterDefinition.script_version_id.in_(version_ids))
                .order_by(
                    ScriptParameterDefinition.script_version_id,
                    ScriptParameterDefinition.position,
                )
            )
        ).scalars().all()
    ) if version_ids else []
    definitions_by_version: dict[str, list[ScriptParameterDefinition]] = {}
    for definition in definition_rows:
        definitions_by_version.setdefault(definition.script_version_id, []).append(
            definition
        )
    versions = [
        _version_out(version, review, definitions_by_version.get(version.id))
        for version, review in rows
    ]
    latest_version, latest_review = rows[0]
    return ScriptItemDetailOut(
        **ScriptItemOut(
            **_item_out(item, latest_version, latest_review).model_dump(exclude={"latest"}),
            latest=_version_out(
                latest_version,
                latest_review,
                definitions_by_version.get(latest_version.id),
            ),
        ).model_dump(),
        versions=versions,
    )


def _parameter_rows(
    version: ScriptVersion, definitions: list[ScriptParameterInput]
) -> list[ScriptParameterDefinition]:
    rows: list[ScriptParameterDefinition] = []
    for position, definition in enumerate(definitions):
        rows.append(
            ScriptParameterDefinition(
                script_version_id=version.id,
                position=position,
                key=definition.key,
                label=definition.label,
                description=definition.description,
                kind=definition.kind,
                required=definition.required,
                has_default="default_value" in definition.model_fields_set,
                default_value=(
                    definition.default_value
                    if "default_value" in definition.model_fields_set
                    else None
                ),
                min_length=definition.min_length,
                max_length=definition.max_length,
                minimum=definition.minimum,
                maximum=definition.maximum,
                choices=definition.choices,
            )
        )
    return rows


def _parameter_set_out(
    item: ScriptParameterValueSet,
    version: ScriptVersion,
    script_id: str,
) -> ScriptParameterValueSetOut:
    expires_at = item.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return ScriptParameterValueSetOut(
        id=item.id,
        script_id=script_id,
        script_version_id=version.id,
        version=version.version,
        request_id=item.request_id,
        state="expired" if expires_at <= _now() else "available",
        provided_keys=item.provided_keys,
        defaulted_keys=item.defaulted_keys,
        secret_keys=item.secret_keys,
        values_fingerprint=item.values_fingerprint,
        created_by=item.created_by,
        created_at=item.created_at,
        expires_at=item.expires_at,
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
    version_ids = [version.id for _, version, _ in rows]
    definition_rows = list(
        (
            await db.execute(
                select(ScriptParameterDefinition)
                .where(ScriptParameterDefinition.script_version_id.in_(version_ids))
                .order_by(ScriptParameterDefinition.position)
            )
        ).scalars().all()
    ) if version_ids else []
    definitions_by_version: dict[str, list[ScriptParameterDefinition]] = {}
    for definition in definition_rows:
        definitions_by_version.setdefault(definition.script_version_id, []).append(
            definition
        )
    items = []
    for item, version, review in rows:
        base = _item_out(item, version, review)
        items.append(
            ScriptItemOut(
                **base.model_dump(exclude={"latest"}),
                latest=_version_out(
                    version, review, definitions_by_version.get(version.id)
                ),
            )
        )
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
        db.add_all(_parameter_rows(version, body.parameters))
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
            "parameter_count": len(body.parameters),
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
    definitions = list(
        (
            await db.execute(
                select(ScriptParameterDefinition)
                .where(ScriptParameterDefinition.script_version_id == version.id)
                .order_by(ScriptParameterDefinition.position)
            )
        ).scalars().all()
    )
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
        **_version_out(version, review, definitions).model_dump(), content=version.content
    )


@router.post(
    "/{script_id}/versions/{version_number}/parameter-value-sets",
    response_model=ScriptParameterValueSetOut,
    status_code=status.HTTP_201_CREATED,
)
async def prepare_script_parameter_values(
    script_id: str,
    version_number: int,
    body: ScriptParameterValuesCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            select(ScriptLibraryItem, ScriptVersion, ScriptVersionReview)
            .join(
                ScriptVersion,
                ScriptVersion.script_id == ScriptLibraryItem.id,
            )
            .outerjoin(
                ScriptVersionReview,
                ScriptVersionReview.script_version_id == ScriptVersion.id,
            )
            .where(
                ScriptLibraryItem.id == script_id,
                ScriptVersion.version == version_number,
            )
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Script version not found")
    item, version, review = row
    if item.deprecated_at is not None:
        raise HTTPException(status_code=409, detail={"code": "script_deprecated"})
    if review is None or review.state.value != "approved":
        raise HTTPException(
            status_code=409, detail={"code": "script_version_not_approved"}
        )
    definitions = list(
        (
            await db.execute(
                select(ScriptParameterDefinition)
                .where(ScriptParameterDefinition.script_version_id == version.id)
                .order_by(ScriptParameterDefinition.position)
            )
        ).scalars().all()
    )
    try:
        prepared = script_parameters.prepare_values(definitions, body.values)
        value_set_id = str(uuid.uuid4())
        encrypted, fingerprint = script_parameters.encrypt_values(
            prepared.values,
            script_version_id=version.id,
            value_set_id=value_set_id,
        )
    except script_parameters.ScriptParameterError as exc:
        http_status = 503 if exc.state == "unavailable" else 422
        raise HTTPException(
            status_code=http_status,
            detail={"code": exc.code, "state": exc.state},
        ) from exc

    existing = await db.scalar(
        select(ScriptParameterValueSet).where(
            ScriptParameterValueSet.script_version_id == version.id,
            ScriptParameterValueSet.request_id == body.request_id,
        )
    )
    if existing is not None:
        if existing.values_fingerprint != fingerprint:
            raise HTTPException(
                status_code=409,
                detail={"code": "parameter_request_conflict"},
            )
        return _parameter_set_out(existing, version, script_id)

    active_count = await db.scalar(
        select(func.count()).select_from(ScriptParameterValueSet).where(
            ScriptParameterValueSet.script_version_id == version.id,
            ScriptParameterValueSet.expires_at > _now(),
        )
    ) or 0
    if active_count >= settings.script_parameter_max_sets_per_version:
        raise HTTPException(
            status_code=409, detail={"code": "parameter_value_set_limit_reached"}
        )

    created_at = _now()
    value_set = ScriptParameterValueSet(
        id=value_set_id,
        script_version_id=version.id,
        request_id=body.request_id,
        encrypted_values=encrypted,
        values_fingerprint=fingerprint,
        provided_keys=list(prepared.provided_keys),
        defaulted_keys=list(prepared.defaulted_keys),
        secret_keys=list(prepared.secret_keys),
        created_by=operator.email,
        created_at=created_at,
        expires_at=created_at
        + timedelta(seconds=settings.script_parameter_value_ttl_seconds),
    )
    db.add(value_set)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "parameter_request_conflict"}
        ) from exc
    await audit.record(
        db,
        action="script_library.parameter_values_prepared",
        **_request_evidence(request, operator),
        detail={
            "script_id": script_id,
            "version": version_number,
            "parameter_value_set_id": value_set.id,
            "request_id": body.request_id,
            "provided_keys": value_set.provided_keys,
            "defaulted_keys": value_set.defaulted_keys,
            "secret_keys": value_set.secret_keys,
            "values_fingerprint": value_set.values_fingerprint,
            "expires_at": value_set.expires_at.isoformat(),
        },
    )
    return _parameter_set_out(value_set, version, script_id)


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
        db.add_all(_parameter_rows(version, body.parameters))
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
            "parameter_count": len(body.parameters),
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
