# SPDX-License-Identifier: AGPL-3.0-only
"""Contracts for the immutable, reviewed script library (issue #47)."""
from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

from app.models.models import (
    ScriptLanguage,
    ScriptParameterKind,
    ScriptReviewState,
)


MAX_SCRIPT_BYTES = 57_344
MAX_SCRIPT_LINES = 5_000
_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_DISALLOWED_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_PARAMETER_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

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


class ScriptParameterInput(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    kind: ScriptParameterKind
    required: bool = False
    default_value: Any = None
    min_length: int | None = Field(default=None, ge=0, le=16_384)
    max_length: int | None = Field(default=None, ge=1, le=16_384)
    minimum: float | None = None
    maximum: float | None = None
    choices: list[str] | None = Field(default=None, min_length=1, max_length=50)

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        if not _PARAMETER_KEY.fullmatch(value):
            raise ValueError("parameter keys must start with a letter and use letters, digits, or '_'")
        return value

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("parameter label must not be blank")
        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("minimum", "maximum")
    @classmethod
    def finite_bound(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("numeric bounds must be finite")
        return value

    @model_validator(mode="after")
    def validate_kind_contract(self):
        has_default = "default_value" in self.model_fields_set
        if self.min_length is not None and self.max_length is not None:
            if self.min_length > self.max_length:
                raise ValueError("min_length must not exceed max_length")
        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError("minimum must not exceed maximum")

        if self.kind in (ScriptParameterKind.string, ScriptParameterKind.secret):
            if self.minimum is not None or self.maximum is not None or self.choices is not None:
                raise ValueError("string and secret parameters support only length constraints")
            if self.kind is ScriptParameterKind.secret and has_default:
                raise ValueError("secret parameters may not define defaults")
            if has_default and not isinstance(self.default_value, str):
                raise ValueError("string defaults must be strings")
            # A default that violates its own bounds would make every prepared
            # run fail later, so reject the unusable definition here instead.
            if has_default and (
                self.min_length is not None and len(self.default_value) < self.min_length
                or self.max_length is not None
                and len(self.default_value) > self.max_length
            ):
                raise ValueError("string defaults must satisfy the length constraints")
        elif self.kind is ScriptParameterKind.number:
            if self.min_length is not None or self.max_length is not None or self.choices is not None:
                raise ValueError("number parameters support only minimum and maximum")
            if has_default and (
                isinstance(self.default_value, bool)
                or not isinstance(self.default_value, (int, float))
                or not math.isfinite(float(self.default_value))
            ):
                raise ValueError("number defaults must be finite numbers")
            if has_default and (
                self.minimum is not None and float(self.default_value) < self.minimum
                or self.maximum is not None and float(self.default_value) > self.maximum
            ):
                raise ValueError("number defaults must satisfy the numeric bounds")
        elif self.kind is ScriptParameterKind.boolean:
            if any(value is not None for value in (
                self.min_length, self.max_length, self.minimum, self.maximum, self.choices
            )):
                raise ValueError("boolean parameters do not support constraints")
            if has_default and not isinstance(self.default_value, bool):
                raise ValueError("boolean defaults must be booleans")
        elif self.kind is ScriptParameterKind.choice:
            if any(value is not None for value in (
                self.min_length, self.max_length, self.minimum, self.maximum
            )):
                raise ValueError("choice parameters support only choices")
            if not self.choices:
                raise ValueError("choice parameters require choices")
            normalized = [item.strip() for item in self.choices]
            if any(not item or len(item) > 200 for item in normalized):
                raise ValueError("choices must contain 1-200 characters")
            if len(set(normalized)) != len(normalized):
                raise ValueError("choices must be unique")
            if sum(len(item.encode("utf-8")) for item in normalized) > 4_096:
                raise ValueError("choice values exceed the 4096-byte limit")
            self.choices = normalized
            if has_default and (
                not isinstance(self.default_value, str)
                or self.default_value not in normalized
            ):
                raise ValueError("choice defaults must be one of the configured choices")

        if has_default and self.required:
            raise ValueError("a parameter with a default must not be marked required")
        return self


class ScriptParameterOut(BaseModel):
    key: str
    label: str
    description: str | None
    kind: ScriptParameterKind
    required: bool
    has_default: bool
    default_value: Any = None
    min_length: int | None
    max_length: int | None
    minimum: float | None
    maximum: float | None
    choices: list[str] | None


class ScriptParameterValuesCreate(BaseModel):
    request_id: Annotated[
        str, StringConstraints(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    values: dict[str, Any] = Field(default_factory=dict, max_length=32)


class ScriptParameterValueSetOut(BaseModel):
    id: str
    script_id: str
    script_version_id: str
    version: int
    request_id: str
    state: Literal["available", "expired"]
    provided_keys: list[str]
    defaulted_keys: list[str]
    secret_keys: list[str]
    values_fingerprint: str
    created_by: str
    created_at: datetime
    expires_at: datetime


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
    parameters: list[ScriptParameterInput] = Field(default_factory=list, max_length=32)

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

    @field_validator("parameters")
    @classmethod
    def validate_parameters(
        cls, value: list[ScriptParameterInput]
    ) -> list[ScriptParameterInput]:
        keys = [item.key.casefold() for item in value]
        if len(set(keys)) != len(keys):
            raise ValueError("parameter keys must be unique ignoring case")
        return value


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
    parameters: list[ScriptParameterOut]
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
