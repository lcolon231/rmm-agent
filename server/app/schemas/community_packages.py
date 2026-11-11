# SPDX-License-Identifier: AGPL-3.0-only
"""Contracts for the moderated community script repository (issue #74)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator

RequestId = Annotated[
    str, StringConstraints(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
]
Reason = Annotated[
    str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
]
Slug = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
    ),
]
KeyId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
]
VersionState = Literal["submitted", "approved", "rejected", "revoked", "blocked"]


class PublisherCreate(BaseModel):
    slug: Slug
    display_name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ]


class PublisherKeyCreate(BaseModel):
    key_id: KeyId
    public_key_pem: str = Field(min_length=1, max_length=1_024)


class RevokeRequest(BaseModel):
    request_id: RequestId
    reason: Reason


class PublisherKeyOut(BaseModel):
    key_id: str
    fingerprint: str
    status: Literal["active", "revoked"]
    created_by: str
    created_at: datetime
    revoked_at: datetime | None


class PublisherOut(BaseModel):
    id: str
    slug: str
    display_name: str
    status: Literal["active", "revoked"]
    created_by: str
    created_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None
    keys: list[PublisherKeyOut]


class PublisherListOut(BaseModel):
    items: list[PublisherOut]


MAX_MANIFEST_BYTES = 65_536


class SubmissionCreate(BaseModel):
    manifest: dict[str, Any]
    content: str = Field(min_length=1, max_length=57_344)
    key_id: KeyId
    signature: str = Field(min_length=1, max_length=128)

    @field_validator("manifest")
    @classmethod
    def bounded_manifest(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("manifest must be finite JSON") from exc
        if len(encoded.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise ValueError(f"manifest may contain at most {MAX_MANIFEST_BYTES} bytes")
        return value


class ModerationCreate(BaseModel):
    state: Literal["approved", "rejected"]
    reason: Reason
    acknowledge_capability_escalation: bool = False


class ModerationOut(BaseModel):
    state: Literal["approved", "rejected"]
    moderated_by: str
    reason_sha256: str
    reason_bytes: int
    acknowledged_capability_escalation: bool
    created_at: datetime


class PackageVersionOut(BaseModel):
    id: str
    version: str
    state: VersionState
    language: str
    content_sha256: str
    content_bytes: int
    manifest_sha256: str
    signing_key_id: str
    signing_key_fingerprint: str
    capabilities: list[str]
    supported_platforms: list[str]
    description: str | None
    submitted_by: str
    submitted_at: datetime
    revoked_at: datetime | None
    moderation: ModerationOut | None
    # Capabilities this version adds over the latest approved earlier version.
    capability_escalation: list[str]


class PackageVersionDetailOut(PackageVersionOut):
    manifest: dict[str, Any]
    signature: str
    content: str


class PackageOut(BaseModel):
    id: str
    publisher: str
    name: str
    qualified_name: str
    publisher_status: Literal["active", "revoked"]
    created_at: datetime
    updated_at: datetime
    versions: list[PackageVersionOut]


class PackageListOut(BaseModel):
    items: list[PackageOut]
    total: int


class InstallCreate(BaseModel):
    package_id: str = Field(min_length=1, max_length=36)
    version: str = Field(min_length=5, max_length=32)
    accepted_capabilities: list[str] = Field(max_length=32)
    request_id: RequestId
    library_name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ] | None = None


class InstallTransition(BaseModel):
    version: str = Field(min_length=5, max_length=32)
    accepted_capabilities: list[str] = Field(max_length=32)
    request_id: RequestId


class InstallOut(BaseModel):
    id: str
    package_id: str
    qualified_name: str
    script_id: str
    script_version_id: str
    library_version: int
    installed_version: str
    installed_by: str
    created_at: datetime
    updated_at: datetime


class InstallListOut(BaseModel):
    items: list[InstallOut]
