# SPDX-License-Identifier: AGPL-3.0-only
"""Validated interactive-shell lifecycle and frame contracts (issue #61)."""
from __future__ import annotations

from datetime import datetime

from typing import Literal

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
    client_last_seq: int
    agent_last_seq: int


class ShellFrameIn(BaseModel):
    seq: int = Field(ge=1)
    stream: Literal["input", "stdout", "stderr", "control"]
    data_b64: str = Field(default="", max_length=24_000)
    eof: bool = False


class ShellFrameOut(ShellFrameIn):
    byte_length: int = Field(ge=0)


class ShellFrameBatch(BaseModel):
    session: ShellSessionOut
    frames: list[ShellFrameOut] = Field(default_factory=list, max_length=64)


class ShellAgentAttachOut(BaseModel):
    session: ShellSessionOut | None


class ShellAgentComplete(BaseModel):
    status: Literal["closed", "failed"] = "closed"
    reason: str | None = Field(None, max_length=64)
