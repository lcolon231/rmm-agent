# SPDX-License-Identifier: AGPL-3.0-only
"""Request/response shapes for API tokens and the public API version (#72)."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.models import ClientRole, OperatorRole


class ApiTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, strip_whitespace=True)]
    client_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    role_ceiling: OperatorRole = OperatorRole.readonly
    client_role_ceiling: ClientRole = ClientRole.client_readonly
    # Bounded by API_TOKEN_MAX_TTL_DAYS at request time; None = the default.
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class ApiTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    prefix: str
    operator_id: str
    client_id: str
    role_ceiling: OperatorRole
    client_role_ceiling: ClientRole
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    active: bool


class ApiTokenCreatedOut(ApiTokenOut):
    # Shown exactly once. NodeLink stores only its SHA-256.
    token: str


class ApiTokenListOut(BaseModel):
    items: list[ApiTokenOut]


class ApiDeprecationOut(BaseModel):
    method: str
    path: str
    deprecated_on: str | None
    sunset_on: str | None


class ApiVersionOut(BaseModel):
    api_version: str
    api_revision: str
    webhook_api_versions: list[str]
    deprecations: list[ApiDeprecationOut]
