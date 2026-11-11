# SPDX-License-Identifier: AGPL-3.0-only
"""Moderated community script repository endpoints (issue #74).

Trust chain: an admin registers a publisher namespace and its Ed25519 public
keys; anyone with the operator role may submit a package version signed
offline by one of those keys; a *different* admin moderates it; an admin
installs an approved version into the local script library. Signature, digest,
key, publisher, moderation, and revocation state are re-verified at
submission, moderation, install, update, rollback, and every dispatch.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.api.script_library import _new_version, _parameter_rows
from app.core import audit
from app.core import community_packages as trust
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.models.models import (
    CommunityInstall,
    CommunityPackage,
    CommunityPackageModeration,
    CommunityPackageVersion,
    CommunityPublisher,
    CommunityPublisherKey,
    Operator,
    OperatorRole,
    ScriptLibraryItem,
    ScriptReviewState,
    ScriptVersion,
    ScriptVersionReview,
)
from app.schemas.community_packages import (
    InstallCreate,
    InstallListOut,
    InstallOut,
    InstallTransition,
    ModerationCreate,
    ModerationOut,
    PackageListOut,
    PackageOut,
    PackageVersionDetailOut,
    PackageVersionOut,
    PublisherCreate,
    PublisherKeyCreate,
    PublisherKeyOut,
    PublisherListOut,
    PublisherOut,
    RevokeRequest,
    SubmissionCreate,
)


router = APIRouter(
    prefix="/community",
    tags=["community-packages"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> tuple[str, int]:
    encoded = value.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _evidence(request: Request, operator: Operator) -> dict:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


def _refuse(code: str, status_code: int = 409) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code})


# --- read models -------------------------------------------------------------


async def _publisher_out(db: AsyncSession, publisher: CommunityPublisher) -> PublisherOut:
    keys = (
        await db.execute(
            select(CommunityPublisherKey)
            .where(CommunityPublisherKey.publisher_id == publisher.id)
            .order_by(CommunityPublisherKey.created_at, CommunityPublisherKey.key_id)
        )
    ).scalars().all()
    return PublisherOut(
        id=publisher.id,
        slug=publisher.slug,
        display_name=publisher.display_name,
        status=publisher.status,
        created_by=publisher.created_by,
        created_at=publisher.created_at,
        revoked_at=publisher.revoked_at,
        revoked_by=publisher.revoked_by,
        keys=[
            PublisherKeyOut(
                key_id=key.key_id,
                fingerprint=key.fingerprint,
                status=key.status,
                created_by=key.created_by,
                created_at=key.created_at,
                revoked_at=key.revoked_at,
            )
            for key in keys
        ],
    )


async def _moderation(
    db: AsyncSession, version_id: str
) -> CommunityPackageModeration | None:
    return await db.scalar(
        select(CommunityPackageModeration).where(
            CommunityPackageModeration.package_version_id == version_id
        )
    )


async def _previous_approved_capabilities(
    db: AsyncSession, version: CommunityPackageVersion
) -> list[str] | None:
    """Capabilities of the newest approved, unrevoked, *older* version."""
    rows = (
        await db.execute(
            select(CommunityPackageVersion)
            .join(
                CommunityPackageModeration,
                CommunityPackageModeration.package_version_id
                == CommunityPackageVersion.id,
            )
            .where(
                CommunityPackageVersion.package_id == version.package_id,
                CommunityPackageModeration.state == "approved",
                CommunityPackageVersion.revoked_at.is_(None),
            )
            .order_by(
                CommunityPackageVersion.major.desc(),
                CommunityPackageVersion.minor.desc(),
                CommunityPackageVersion.patch.desc(),
            )
        )
    ).scalars().all()
    current = (version.major, version.minor, version.patch)
    for row in rows:
        if (row.major, row.minor, row.patch) < current:
            return list(row.capabilities)
    return None


async def _escalation(db: AsyncSession, version: CommunityPackageVersion) -> list[str]:
    previous = await _previous_approved_capabilities(db, version)
    if previous is None:
        # A first approval is measured against the bare interpreter/platform
        # baseline, so every declared side-effect capability needs explicit
        # moderator acknowledgement.
        return sorted(set(version.capabilities) & trust.EFFECT_CAPABILITIES)
    return trust.capability_escalation(previous, version.capabilities)


async def _version_out(
    db: AsyncSession, version: CommunityPackageVersion, *, detail: bool = False
):
    key = await db.get(CommunityPublisherKey, version.signing_key_id)
    moderation = await _moderation(db, version.id)
    values = dict(
        id=version.id,
        version=version.version,
        state=await trust.version_state(db, version),
        language=version.manifest.get("language", ""),
        content_sha256=version.content_sha256,
        content_bytes=version.content_bytes,
        manifest_sha256=version.manifest_sha256,
        signing_key_id=key.key_id if key else "",
        signing_key_fingerprint=key.fingerprint if key else "",
        capabilities=list(version.capabilities),
        supported_platforms=list(version.manifest.get("supported_platforms", [])),
        description=version.manifest.get("description"),
        submitted_by=version.submitted_by,
        submitted_at=version.submitted_at,
        revoked_at=version.revoked_at,
        moderation=ModerationOut(
            state=moderation.state,
            moderated_by=moderation.moderated_by,
            reason_sha256=moderation.reason_sha256,
            reason_bytes=moderation.reason_bytes,
            acknowledged_capability_escalation=moderation.acknowledged_capability_escalation,
            created_at=moderation.created_at,
        )
        if moderation
        else None,
        capability_escalation=await _escalation(db, version),
    )
    if detail:
        return PackageVersionDetailOut(
            **values,
            manifest=version.manifest,
            signature=version.signature,
            content=version.content,
        )
    return PackageVersionOut(**values)


async def _package_out(db: AsyncSession, package: CommunityPackage) -> PackageOut:
    publisher = await db.get(CommunityPublisher, package.publisher_id)
    versions = (
        await db.execute(
            select(CommunityPackageVersion)
            .where(CommunityPackageVersion.package_id == package.id)
            .order_by(
                CommunityPackageVersion.major.desc(),
                CommunityPackageVersion.minor.desc(),
                CommunityPackageVersion.patch.desc(),
            )
        )
    ).scalars().all()
    return PackageOut(
        id=package.id,
        publisher=publisher.slug,
        name=package.name,
        qualified_name=f"{publisher.slug}/{package.name}",
        publisher_status=publisher.status,
        created_at=package.created_at,
        updated_at=package.updated_at,
        versions=[await _version_out(db, item) for item in versions],
    )


async def _load_version(
    db: AsyncSession, package_id: str, version: str
) -> tuple[CommunityPackage, CommunityPackageVersion]:
    package = await db.get(CommunityPackage, package_id)
    row = None
    if package is not None:
        row = await db.scalar(
            select(CommunityPackageVersion).where(
                CommunityPackageVersion.package_id == package_id,
                CommunityPackageVersion.version == version,
            )
        )
    if package is None or row is None:
        raise HTTPException(status_code=404, detail="Package version not found")
    return package, row


async def _qualified(db: AsyncSession, package: CommunityPackage) -> str:
    publisher = await db.get(CommunityPublisher, package.publisher_id)
    return f"{publisher.slug}/{package.name}"


# --- publishers --------------------------------------------------------------


@router.get("/publishers", response_model=PublisherListOut)
async def list_publishers(db: AsyncSession = Depends(get_db)):
    publishers = (
        await db.execute(select(CommunityPublisher).order_by(CommunityPublisher.slug))
    ).scalars().all()
    return PublisherListOut(items=[await _publisher_out(db, item) for item in publishers])


@router.post("/publishers", response_model=PublisherOut, status_code=status.HTTP_201_CREATED)
async def create_publisher(
    body: PublisherCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    count = await db.scalar(select(func.count()).select_from(CommunityPublisher)) or 0
    if count >= settings.community_max_publishers:
        raise _refuse("community_publisher_limit_reached")
    if await db.scalar(
        select(CommunityPublisher.id).where(CommunityPublisher.slug == body.slug)
    ):
        raise _refuse("publisher_slug_exists")
    publisher = CommunityPublisher(
        slug=body.slug, display_name=body.display_name, created_by=operator.email
    )
    db.add(publisher)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise _refuse("publisher_slug_exists") from exc
    await audit.record(
        db,
        action="community.publisher_created",
        **_evidence(request, operator),
        detail={"publisher_id": publisher.id, "slug": publisher.slug},
    )
    return await _publisher_out(db, publisher)


async def _locked_publisher(db: AsyncSession, publisher_id: str) -> CommunityPublisher:
    publisher = (
        await db.execute(
            select(CommunityPublisher)
            .where(CommunityPublisher.id == publisher_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if publisher is None:
        raise HTTPException(status_code=404, detail="Publisher not found")
    return publisher


@router.post(
    "/publishers/{publisher_id}/keys",
    response_model=PublisherOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_publisher_key(
    publisher_id: str,
    body: PublisherKeyCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    publisher = await _locked_publisher(db, publisher_id)
    if publisher.status != "active":
        raise _refuse("publisher_revoked")
    try:
        fingerprint = trust.key_fingerprint(body.public_key_pem)
    except ValueError as exc:
        raise _refuse("publisher_key_invalid", 422) from exc
    key_count = await db.scalar(
        select(func.count()).select_from(CommunityPublisherKey).where(
            CommunityPublisherKey.publisher_id == publisher.id
        )
    ) or 0
    if key_count >= settings.community_max_keys_per_publisher:
        raise _refuse("publisher_key_limit_reached")
    if await db.scalar(
        select(CommunityPublisherKey.id).where(
            (CommunityPublisherKey.fingerprint == fingerprint)
            | (
                (CommunityPublisherKey.publisher_id == publisher.id)
                & (CommunityPublisherKey.key_id == body.key_id)
            )
        )
    ):
        # A key is bound to exactly one namespace forever, and a revoked key ID
        # is never reused, so old signatures can never be re-attributed.
        raise _refuse("publisher_key_exists")
    key = CommunityPublisherKey(
        publisher_id=publisher.id,
        key_id=body.key_id,
        public_key_pem=body.public_key_pem.strip() + "\n",
        fingerprint=fingerprint,
        created_by=operator.email,
    )
    db.add(key)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise _refuse("publisher_key_exists") from exc
    await audit.record(
        db,
        action="community.publisher_key_added",
        **_evidence(request, operator),
        detail={
            "publisher_id": publisher.id,
            "key_id": key.key_id,
            "fingerprint": fingerprint,
        },
    )
    return await _publisher_out(db, publisher)


@router.post("/publishers/{publisher_id}/keys/{key_id}/revoke", response_model=PublisherOut)
async def revoke_publisher_key(
    publisher_id: str,
    key_id: str,
    body: RevokeRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    publisher = await _locked_publisher(db, publisher_id)
    key = await db.scalar(
        select(CommunityPublisherKey).where(
            CommunityPublisherKey.publisher_id == publisher.id,
            CommunityPublisherKey.key_id == key_id,
        )
    )
    if key is None:
        raise HTTPException(status_code=404, detail="Publisher key not found")
    if key.status == "revoked":
        return await _publisher_out(db, publisher)
    key.status = "revoked"
    key.revoked_at = _now()
    key.revoked_by = operator.email
    key.revocation_reason_sha256, key.revocation_reason_bytes = _digest(body.reason)
    await db.flush()
    await audit.record(
        db,
        action="community.publisher_key_revoked",
        **_evidence(request, operator),
        detail={
            "publisher_id": publisher.id,
            "key_id": key.key_id,
            "fingerprint": key.fingerprint,
            "request_id": body.request_id,
            "reason": body.reason,
        },
    )
    return await _publisher_out(db, publisher)


@router.post("/publishers/{publisher_id}/revoke", response_model=PublisherOut)
async def revoke_publisher(
    publisher_id: str,
    body: RevokeRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    publisher = await _locked_publisher(db, publisher_id)
    if publisher.status == "revoked":
        if publisher.revocation_request_id == body.request_id:
            return await _publisher_out(db, publisher)
        raise _refuse("publisher_revoked")
    publisher.status = "revoked"
    publisher.revoked_at = _now()
    publisher.revoked_by = operator.email
    publisher.revocation_request_id = body.request_id
    publisher.revocation_reason_sha256, publisher.revocation_reason_bytes = _digest(
        body.reason
    )
    await db.flush()
    await audit.record(
        db,
        action="community.publisher_revoked",
        **_evidence(request, operator),
        detail={
            "publisher_id": publisher.id,
            "slug": publisher.slug,
            "request_id": body.request_id,
            "reason": body.reason,
        },
    )
    return await _publisher_out(db, publisher)


# --- packages ----------------------------------------------------------------


@router.get("/packages", response_model=PackageListOut)
async def list_packages(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count()).select_from(CommunityPackage)) or 0
    packages = (
        await db.execute(
            select(CommunityPackage)
            .join(CommunityPublisher, CommunityPublisher.id == CommunityPackage.publisher_id)
            .order_by(CommunityPublisher.slug, CommunityPackage.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()
    items = [await _package_out(db, item) for item in packages]
    await audit.record(
        db,
        action="community.catalog_viewed",
        **_evidence(request, operator),
        detail={"page": page, "page_size": page_size, "result_count": len(items), "total": total},
    )
    return PackageListOut(items=items, total=total)


@router.get("/packages/{package_id}", response_model=PackageOut)
async def get_package(package_id: str, db: AsyncSession = Depends(get_db)):
    package = await db.get(CommunityPackage, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return await _package_out(db, package)


@router.get(
    "/packages/{package_id}/versions/{version}", response_model=PackageVersionDetailOut
)
async def get_package_version(
    package_id: str,
    version: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    package, row = await _load_version(db, package_id, version)
    await audit.record(
        db,
        action="community.version_viewed",
        **_evidence(request, operator),
        detail={
            "package_id": package.id,
            "package_version_id": row.id,
            "version": row.version,
            "content_sha256": row.content_sha256,
        },
    )
    return await _version_out(db, row, detail=True)


async def _record_submission_refusal(
    db: AsyncSession,
    request: Request,
    operator: Operator,
    code: str,
    body: SubmissionCreate,
) -> None:
    """Tamper/abuse evidence survives the refused request's rollback."""
    def claim(field: str) -> str:
        value = body.manifest.get(field)
        return value[:200] if isinstance(value, str) else ""

    await audit.record(
        db,
        action="community.submission_refused",
        **_evidence(request, operator),
        detail={
            "code": code,
            "publisher": claim("publisher"),
            "name": claim("name"),
            "version": claim("version"),
            "key_id": body.key_id,
            "content_sha256": hashlib.sha256(body.content.encode("utf-8")).hexdigest(),
        },
    )
    await db.commit()


@router.post(
    "/submissions", response_model=PackageOut, status_code=status.HTTP_201_CREATED
)
async def submit_package_version(
    body: SubmissionCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    try:
        verified = trust.validate_manifest(body.manifest, body.content)
        publisher = await db.scalar(
            select(CommunityPublisher).where(
                CommunityPublisher.slug == verified.manifest["publisher"]
            )
        )
        if publisher is None:
            raise trust.CommunityRefusal("publisher_unknown", 422)
        key = await db.scalar(
            select(CommunityPublisherKey).where(
                CommunityPublisherKey.publisher_id == publisher.id,
                CommunityPublisherKey.key_id == body.key_id,
            )
        )
        if key is None:
            # Either an unknown key or one registered to another namespace:
            # a manifest can only claim the namespace that owns its key.
            other = await db.scalar(
                select(CommunityPublisherKey.id).where(
                    CommunityPublisherKey.key_id == body.key_id
                )
            )
            raise trust.CommunityRefusal(
                "manifest_publisher_mismatch" if other else "publisher_key_unknown", 422
            )
        if publisher.status != "active":
            raise trust.CommunityRefusal("publisher_revoked")
        if key.status != "active":
            raise trust.CommunityRefusal("publisher_key_revoked")
        if not trust.verify_signature(key.public_key_pem, body.signature, verified.manifest):
            raise trust.CommunityRefusal("signature_invalid", 422)
    except trust.CommunityRefusal as refusal:
        await _record_submission_refusal(db, request, operator, refusal.code, body)
        raise _refuse(refusal.code, refusal.status_code) from refusal

    package = await db.scalar(
        select(CommunityPackage)
        .where(
            CommunityPackage.publisher_id == publisher.id,
            CommunityPackage.name == verified.manifest["name"],
        )
        .with_for_update()
    )
    if package is None:
        count = await db.scalar(select(func.count()).select_from(CommunityPackage)) or 0
        if count >= settings.community_max_packages:
            raise _refuse("community_package_limit_reached")
        package = CommunityPackage(publisher_id=publisher.id, name=verified.manifest["name"])
        db.add(package)
        try:
            await db.flush()
        except IntegrityError as exc:
            raise _refuse("package_version_conflict") from exc
    existing = await db.scalar(
        select(CommunityPackageVersion).where(
            CommunityPackageVersion.package_id == package.id,
            CommunityPackageVersion.version == verified.manifest["version"],
        )
    )
    if existing is not None:
        # Versions are immutable: an exact replay is idempotent, anything else
        # that reuses the number is refused rather than overwritten.
        if (
            existing.manifest_sha256 == verified.manifest_sha256
            and existing.signature == body.signature
        ):
            return await _package_out(db, package)
        raise _refuse("package_version_exists")
    versions = (
        await db.execute(
            select(CommunityPackageVersion).where(
                CommunityPackageVersion.package_id == package.id
            )
        )
    ).scalars().all()
    if len(versions) >= settings.community_max_versions_per_package:
        raise _refuse("package_version_limit_reached")
    if any((row.major, row.minor, row.patch) >= verified.version for row in versions):
        raise _refuse("package_version_not_monotonic")
    major, minor, patch = verified.version
    version = CommunityPackageVersion(
        package_id=package.id,
        version=verified.manifest["version"],
        major=major,
        minor=minor,
        patch=patch,
        manifest=verified.manifest,
        manifest_sha256=verified.manifest_sha256,
        signature=body.signature,
        signing_key_id=key.id,
        content=verified.content,
        content_sha256=verified.content_sha256,
        content_bytes=verified.content_bytes,
        capabilities=list(verified.manifest["capabilities"]),
        submitted_by=operator.email,
    )
    package.updated_at = _now()
    db.add(version)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise _refuse("package_version_exists") from exc
    await audit.record(
        db,
        action="community.submitted",
        **_evidence(request, operator),
        detail={
            "package_id": package.id,
            "package_version_id": version.id,
            "qualified_name": f"{publisher.slug}/{package.name}",
            "version": version.version,
            "manifest_sha256": version.manifest_sha256,
            "content_sha256": version.content_sha256,
            "content_bytes": version.content_bytes,
            "key_id": key.key_id,
            "capabilities": version.capabilities,
        },
    )
    return await _package_out(db, package)


@router.post(
    "/packages/{package_id}/versions/{version}/moderation", response_model=PackageOut
)
async def moderate_package_version(
    package_id: str,
    version: str,
    body: ModerationCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    package, row = await _load_version(db, package_id, version)
    if row.submitted_by.casefold() == operator.email.casefold():
        raise _refuse("moderation_self_review_forbidden", 403)
    if await _moderation(db, row.id) is not None:
        raise _refuse("moderation_already_final")
    escalation = await _escalation(db, row)
    if body.state == "approved":
        state = await trust.version_state(db, row)
        if state == "blocked":
            raise _refuse("community_package_blocked")
        if state == "revoked":
            raise _refuse("package_version_revoked")
        key = await db.get(CommunityPublisherKey, row.signing_key_id)
        if not trust.verify_signature(key.public_key_pem, row.signature, row.manifest):
            raise _refuse("signature_invalid")
        if escalation and not body.acknowledge_capability_escalation:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "capability_escalation_unacknowledged",
                    "capabilities": escalation,
                },
            )
    reason_sha256, reason_bytes = _digest(body.reason)
    db.add(
        CommunityPackageModeration(
            package_version_id=row.id,
            state=body.state,
            moderated_by=operator.email,
            reason_sha256=reason_sha256,
            reason_bytes=reason_bytes,
            acknowledged_capability_escalation=bool(
                body.state == "approved" and escalation
            ),
        )
    )
    try:
        await db.flush()
    except IntegrityError as exc:
        raise _refuse("moderation_already_final") from exc
    await audit.record(
        db,
        action="community.moderated",
        **_evidence(request, operator),
        detail={
            "package_id": package.id,
            "package_version_id": row.id,
            "qualified_name": await _qualified(db, package),
            "version": row.version,
            "state": body.state,
            "capability_escalation": escalation,
            "reason": body.reason,
        },
    )
    return await _package_out(db, package)


@router.post("/packages/{package_id}/versions/{version}/revoke", response_model=PackageOut)
async def revoke_package_version(
    package_id: str,
    version: str,
    body: RevokeRequest,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    package, row = await _load_version(db, package_id, version)
    if row.revoked_at is not None:
        return await _package_out(db, package)
    row.revoked_at = _now()
    row.revoked_by = operator.email
    row.revocation_reason_sha256, row.revocation_reason_bytes = _digest(body.reason)
    await db.flush()
    await audit.record(
        db,
        action="community.version_revoked",
        **_evidence(request, operator),
        detail={
            "package_id": package.id,
            "package_version_id": row.id,
            "qualified_name": await _qualified(db, package),
            "version": row.version,
            "request_id": body.request_id,
            "reason": body.reason,
        },
    )
    return await _package_out(db, package)


# --- installs ----------------------------------------------------------------


async def _install_out(db: AsyncSession, install: CommunityInstall) -> InstallOut:
    package = await db.get(CommunityPackage, install.package_id)
    version = await db.get(CommunityPackageVersion, install.package_version_id)
    item = await db.get(ScriptLibraryItem, install.script_id)
    library_version = await db.scalar(
        select(ScriptVersion).where(
            ScriptVersion.script_id == item.id,
            ScriptVersion.version == item.latest_version,
        )
    )
    return InstallOut(
        id=install.id,
        package_id=install.package_id,
        qualified_name=await _qualified(db, package),
        script_id=item.id,
        script_version_id=library_version.id,
        library_version=item.latest_version,
        installed_version=version.version,
        installed_by=install.installed_by,
        created_at=install.created_at,
        updated_at=install.updated_at,
    )


async def _runnable_version(
    db: AsyncSession, package_id: str, version: str, accepted: list[str]
) -> tuple[CommunityPackage, CommunityPackageVersion]:
    package, row = await _load_version(db, package_id, version)
    try:
        await trust.require_runnable(db, row)
    except trust.CommunityRefusal as refusal:
        state = await trust.version_state(db, row)
        code = {
            "submitted": "package_version_not_approved",
            "rejected": "package_version_not_approved",
            "revoked": "package_version_revoked",
        }.get(state, refusal.code)
        raise _refuse(code) from refusal
    if sorted(set(accepted)) != sorted(row.capabilities) or len(accepted) != len(
        row.capabilities
    ):
        # The installer must accept the exact declared set; a stale screen can
        # never silently accept an escalated capability list.
        raise HTTPException(
            status_code=409,
            detail={
                "code": "install_capabilities_mismatch",
                "capabilities": list(row.capabilities),
            },
        )
    return package, row


def _review(version: ScriptVersion, operator: Operator, moderation_id: str) -> ScriptVersionReview:
    reason_sha256, reason_bytes = _digest(f"community moderation {moderation_id}")
    return ScriptVersionReview(
        script_version_id=version.id,
        state=ScriptReviewState.approved,
        reviewed_by=operator.email,
        reason_sha256=reason_sha256,
        reason_bytes=reason_bytes,
    )


async def _append_library_version(
    db: AsyncSession,
    item: ScriptLibraryItem,
    row: CommunityPackageVersion,
    operator: Operator,
    version_number: int,
) -> ScriptVersion:
    verified = trust.validate_manifest(row.manifest, row.content)
    library_version = _new_version(item, verified.script, operator, version_number)
    library_version.community_package_version_id = row.id
    db.add(library_version)
    await db.flush()
    db.add_all(_parameter_rows(library_version, verified.script.parameters))
    moderation = await _moderation(db, row.id)
    db.add(_review(library_version, operator, moderation.id))
    await db.flush()
    return library_version


@router.get("/installs", response_model=InstallListOut)
async def list_installs(db: AsyncSession = Depends(get_db)):
    installs = (
        await db.execute(select(CommunityInstall).order_by(CommunityInstall.created_at))
    ).scalars().all()
    return InstallListOut(items=[await _install_out(db, item) for item in installs])


@router.post("/installs", response_model=InstallOut, status_code=status.HTTP_201_CREATED)
async def install_package(
    body: InstallCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    replay = await db.scalar(
        select(CommunityInstall).where(CommunityInstall.request_id == body.request_id)
    )
    if replay is not None:
        current = await db.get(CommunityPackageVersion, replay.package_version_id)
        if replay.package_id == body.package_id and current.version == body.version:
            return await _install_out(db, replay)
        raise _refuse("install_request_conflict")
    package, row = await _runnable_version(
        db, body.package_id, body.version, body.accepted_capabilities
    )
    qualified = await _qualified(db, package)
    name = body.library_name or qualified
    normalized = name.casefold()
    existing_item = await db.scalar(
        select(ScriptLibraryItem).where(ScriptLibraryItem.normalized_name == normalized)
    )
    if existing_item is not None:
        linked = await db.scalar(
            select(CommunityInstall).where(CommunityInstall.script_id == existing_item.id)
        )
        # Dependency confusion: a community package must never take over (or
        # be mistaken for) a local script that merely shares its name.
        raise _refuse(
            "package_already_installed"
            if linked is not None and linked.package_id == package.id
            else "library_name_shadowed"
        )
    if await db.scalar(
        select(CommunityInstall.id).where(CommunityInstall.package_id == package.id)
    ):
        raise _refuse("package_already_installed")
    count = await db.scalar(select(func.count()).select_from(ScriptLibraryItem)) or 0
    if count >= settings.script_library_max_items:
        raise _refuse("script_library_limit_reached")
    item = ScriptLibraryItem(name=name, normalized_name=normalized, created_by=operator.email)
    db.add(item)
    try:
        await db.flush()
        library_version = await _append_library_version(db, item, row, operator, 1)
        install = CommunityInstall(
            package_id=package.id,
            script_id=item.id,
            package_version_id=row.id,
            request_id=body.request_id,
            last_request_id=body.request_id,
            installed_by=operator.email,
        )
        db.add(install)
        await db.flush()
    except IntegrityError as exc:
        raise _refuse("install_request_conflict") from exc
    await audit.record(
        db,
        action="community.installed",
        **_evidence(request, operator),
        detail={
            "install_id": install.id,
            "package_version_id": row.id,
            "qualified_name": qualified,
            "version": row.version,
            "script_id": item.id,
            "script_version_id": library_version.id,
            "capabilities": list(row.capabilities),
            "request_id": body.request_id,
        },
    )
    return await _install_out(db, install)


async def _transition(
    install_id: str,
    body: InstallTransition,
    request: Request,
    operator: Operator,
    db: AsyncSession,
    *,
    direction: str,
) -> InstallOut:
    install = (
        await db.execute(
            select(CommunityInstall)
            .where(CommunityInstall.id == install_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if install is None:
        raise HTTPException(status_code=404, detail="Install not found")
    current = await db.get(CommunityPackageVersion, install.package_version_id)
    if install.last_request_id == body.request_id:
        if current.version == body.version:
            return await _install_out(db, install)
        raise _refuse("install_request_conflict")
    package, row = await _runnable_version(
        db, install.package_id, body.version, body.accepted_capabilities
    )
    target = (row.major, row.minor, row.patch)
    installed = (current.major, current.minor, current.patch)
    if direction == "update" and target <= installed:
        raise _refuse("install_downgrade_requires_rollback")
    if direction == "rollback" and target >= installed:
        raise _refuse("install_rollback_requires_older_version")
    item = (
        await db.execute(
            select(ScriptLibraryItem)
            .where(ScriptLibraryItem.id == install.script_id)
            .with_for_update()
        )
    ).scalar_one()
    if item.deprecated_at is not None:
        raise _refuse("script_deprecated")
    if item.latest_version >= settings.script_library_max_versions_per_script:
        raise _refuse("script_version_limit_reached")
    version_number = item.latest_version + 1
    try:
        library_version = await _append_library_version(
            db, item, row, operator, version_number
        )
    except IntegrityError as exc:
        raise _refuse("script_version_conflict") from exc
    item.latest_version = version_number
    item.record_version += 1
    item.updated_at = _now()
    install.package_version_id = row.id
    install.last_request_id = body.request_id
    install.updated_at = item.updated_at
    await db.flush()
    detail = {
        "install_id": install.id,
        "package_version_id": row.id,
        "qualified_name": await _qualified(db, package),
        "version": row.version,
        "previous_version": current.version,
        "script_id": item.id,
        "script_version_id": library_version.id,
        "capabilities": list(row.capabilities),
        "request_id": body.request_id,
    }
    if direction == "update":
        await audit.record(
            db, action="community.updated", **_evidence(request, operator), detail=detail
        )
    else:
        await audit.record(
            db, action="community.rolled_back", **_evidence(request, operator), detail=detail
        )
    return await _install_out(db, install)


@router.post("/installs/{install_id}/update", response_model=InstallOut)
async def update_install(
    install_id: str,
    body: InstallTransition,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    return await _transition(install_id, body, request, operator, db, direction="update")


@router.post("/installs/{install_id}/rollback", response_model=InstallOut)
async def rollback_install(
    install_id: str,
    body: InstallTransition,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    return await _transition(install_id, body, request, operator, db, direction="rollback")
