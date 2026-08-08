# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic schemas for interactive shell sessions (issue #61).

Phase 1 exposes the session lifecycle only. No streamed input/output bytes are
carried by these schemas; the live frame relay is a later phase.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.models import ShellSessionStatus


class ShellSessionOpen(BaseModel):
    """Optional close reason is not part of open; open takes no client-authored
    fields today, but the model reserves a place for a human-readable label."""

    label: str | None = Field(None, max_length=200)


class ShellSessionClose(BaseModel):
    reason: str | None = Field(None, max_length=64)


class ShellSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    status: ShellSessionStatus
    capability_version: str | None
    close_reason: str | None
    created_at: datetime
    activated_at: datetime | None
    last_activity_at: datetime | None
    closed_at: datetime | None
    absolute_deadline: datetime | None
    idle_deadline: datetime | None
    output_bytes_limit: int | None
    output_bytes_total: int
    frames_in: int
    frames_out: int
