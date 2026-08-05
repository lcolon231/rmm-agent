# SPDX-License-Identifier: AGPL-3.0-only
"""Contracts for the immutable, reviewed script library (issue #47)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator

from app.models.models import ScriptLanguage, ScriptReviewState


MAX_SCRIPT_BYTES = 57_344
MAX_SCRIPT_LINES = 5_000
_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_DISALLOWED_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")

ScriptName = Annotated[
    str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
]
Description = Annotated[
    str, StringConstraints(max_length=2_000, strip_whitespace=True)
]
ReviewReason = Annotated[
    str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
]
Platform = Literal["windows", "linux", "macos"]


def canonical_script_content(value: str) -> str:
    """Normalize line endings and outer whitespace before hashing/storage."""
    value = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not value:
        raise ValueError("script content must not be empty")
    if _DISALLOWED_CONTROLS.search(value) or _BIDI_CONTROLS.search(value):
        raise ValueError("script content contains unsupported control characters")
    if value.count("\n") + 1 > MAX_SCRIPT_LINES:
        raise ValueError(f"script content may contain at most {MAX_SCRIPT_LINES} lines")
    if len(value.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise ValueError(f"script content may contain at most {MAX_SCRIPT_BYTES} bytes")
    return value


class ScriptVersionInput(BaseModel):
    language: ScriptLanguage
    content: str
    description: Description | None = None
    tags: list[str] = Field(default_factory=list, max_length=20)
    supported_platforms: list[Platform] = Field(min_length=1, max_length=3)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        return canonical_script_content(value)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in value]
        if any(not 1 <= len(item) <= 50 or not _TAG.fullmatch(item) for item in normalized):
            raise ValueError("tags must use 1-50 lowercase letters, digits, '.', '_' or '-'")
        if len(set(normalized)) != len(normalized):
            raise ValueError("tags must be unique")
        return normalized

    @field_validator("supported_platforms")
    @classmethod
    def validate_platforms(cls, value: list[Platform]) -> list[Platform]:
        if len(set(value)) != len(value):
            raise ValueError("supported platforms must be unique")
        return sorted(value)


class ScriptCreate(ScriptVersionInput):
    name: ScriptName


class ScriptReviewCreate(BaseModel):
    state: ScriptReviewState
    reason: ReviewReason


class ScriptDeprecate(BaseModel):
    expected_record_version: int = Field(ge=1)
    request_id: Annotated[
        str, StringConstraints(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    reason: ReviewReason


class ScriptReviewOut(BaseModel):
    state: ScriptReviewState
    reviewed_by: str
    reason_sha256: str
    reason_bytes: int
    created_at: datetime


class ScriptVersionOut(BaseModel):
    id: str
    version: int
    language: ScriptLanguage
    content_sha256: str
    content_bytes: int
    description: str | None
    tags: list[str]
    supported_platforms: list[Platform]
    created_by: str
    created_at: datetime
    review: ScriptReviewOut | None = None


class ScriptVersionDetailOut(ScriptVersionOut):
    content: str


class ScriptItemOut(BaseModel):
    id: str
    name: str
    latest_version: int
    record_version: int
    deprecated_at: datetime | None
    deprecated_by: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    latest: ScriptVersionOut


class ScriptItemDetailOut(ScriptItemOut):
    versions: list[ScriptVersionOut]


class ScriptListOut(BaseModel):
    items: list[ScriptItemOut]
    page: int
    page_size: int
    total: int
