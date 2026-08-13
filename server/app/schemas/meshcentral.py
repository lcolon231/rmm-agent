# SPDX-License-Identifier: AGPL-3.0-only
"""Validated MeshCentral remote-desktop launch and mapping contracts (issue #62)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.models import MeshLaunchStatus, MeshMappingOrigin, MeshMappingState


class MeshLaunchRequest(BaseModel):
    """Optional operator note recorded digest-only in the launch audit event."""

    reason: str | None = Field(None, max_length=200)


class MeshLaunchOut(BaseModel):
    """A launch record. ``login_url``/``login_expires_at`` are populated only in
    the immediate creation response and are never stored or returned on GET."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    status: MeshLaunchStatus
    meshcentral_node_id: str | None
    denied_reason: str | None
    expires_at: datetime | None
    created_at: datetime
    closed_at: datetime | None
    # Secret, single-use, returned once on 201 only.
    login_url: str | None = None
    login_expires_at: datetime | None = None


class MeshMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    meshcentral_node_id: str
    meshcentral_mesh_id: str | None
    state: MeshMappingState
    origin: MeshMappingOrigin
    created_by: str | None
    last_synced_at: datetime | None
    last_seen_in_mesh_at: datetime | None
    created_at: datetime


class MeshMappingCreate(BaseModel):
    agent_id: str = Field(min_length=1, max_length=36)
    meshcentral_node_id: str = Field(min_length=1, max_length=128)
    meshcentral_mesh_id: str | None = Field(None, max_length=128)


class MeshAvailabilityOut(BaseModel):
    available: bool
    reason: str
    provider_enabled: bool


class MeshProviderStatusOut(BaseModel):
    provider: str
    configured: bool
    base_url_configured: bool
    credential_configured: bool
    encryption_key_configured: bool
    mapping_count: int
    stale_mapping_count: int
