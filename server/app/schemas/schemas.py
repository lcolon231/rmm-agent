# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic v2 request/response schemas."""
from __future__ import annotations

from datetime import datetime

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
)

from app.models.models import (
    AgentStatus,
    CommandKind,
    CommandStatus,
    OperatorRole,
)
from app.core.command_envelope import format_command_time, validate_command_payload


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class OperatorCreate(BaseModel):
    email: str
    password: str
    role: OperatorRole = OperatorRole.readonly


class OperatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: OperatorRole
    disabled: bool
    created_at: datetime


# --------------------------------------------------------------------------- #
# Clients / Sites
# --------------------------------------------------------------------------- #
class ClientCreate(BaseModel):
    name: str


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    created_at: datetime


class SiteCreate(BaseModel):
    client_id: str
    name: str


class SiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    name: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Enrollment
# --------------------------------------------------------------------------- #
EnvelopeVersion = Annotated[
    str, StringConstraints(min_length=1, max_length=32, pattern=r"^[a-z0-9-]+$")
]


class CommandEnvelopeCapabilities(BaseModel):
    supported_command_envelope_versions: list[EnvelopeVersion] = Field(
        default_factory=list, max_length=8
    )

    @field_validator("supported_command_envelope_versions")
    @classmethod
    def versions_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("command envelope versions must be unique")
        return value


class EnrollmentTokenCreate(BaseModel):
    site_id: str
    label: str | None = None
    max_uses: int = 1
    expires_at: datetime | None = None


class EnrollmentTokenOut(BaseModel):
    """Returned once at creation — includes the plaintext token."""
    id: str
    site_id: str
    token: str  # plaintext, shown only here
    label: str | None
    max_uses: int
    expires_at: datetime | None


class EnrollRequest(CommandEnvelopeCapabilities):
    """Sent by the agent installer to claim an identity."""
    enrollment_token: str
    hostname: str
    os: str
    os_version: str = ""
    agent_version: str = ""


class EnrollResponse(BaseModel):
    agent_id: str
    agent_token: str  # long-lived bearer token, shown only here
    heartbeat_interval_seconds: int
    command_public_key: str  # PEM Ed25519 public key for verifying commands
    command_envelope_version: EnvelopeVersion


# --------------------------------------------------------------------------- #
# Heartbeat
# --------------------------------------------------------------------------- #
class HeartbeatIn(CommandEnvelopeCapabilities):
    cpu_percent: float = 0.0
    mem_percent: float = 0.0
    disk_percent: float = 0.0
    uptime_seconds: int = 0
    logged_in_user: str | None = None
    inventory: dict | None = None  # optional full snapshot piggybacked on a beat


class HeartbeatAck(BaseModel):
    ok: bool = True
    # Commands the agent should pick up now (thin-poll model without WS).
    pending_commands: list["CommandOut"] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
class CommandCreate(BaseModel):
    kind: CommandKind
    payload: dict = Field(default_factory=dict)
    ttl_seconds: int = Field(default=300, ge=1, le=86_400)

    @field_validator("payload")
    @classmethod
    def payload_must_be_canonicalizable(cls, value: dict) -> dict:
        return validate_command_payload(value)


class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    kind: CommandKind
    payload: dict
    envelope_version: EnvelopeVersion
    schema_version: int | None
    issued_at: datetime | None
    nonce: str | None
    signature: str
    status: CommandStatus
    created_at: datetime
    expires_at: datetime | None

    @field_serializer("issued_at", "expires_at", when_used="unless-none")
    def serialize_command_time(self, value: datetime) -> str:
        """Keep signed command timestamps canonical on every API response."""
        return format_command_time(value)


class CommandResult(BaseModel):
    """Posted by the agent after execution."""
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    site_id: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    command_envelope_versions: list[EnvelopeVersion]
    status: AgentStatus
    last_seen_at: datetime | None
    enrolled_at: datetime


# --------------------------------------------------------------------------- #
# Audit anchors
# --------------------------------------------------------------------------- #
class AnchorOut(BaseModel):
    """A Merkle commitment over the audit chain. `merkle_root` is the value to
    publish externally — everything else is bookkeeping for verification."""
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    event_count: int
    last_event_id: str
    merkle_root: str


class AnchorVerifyOut(BaseModel):
    anchor_id: str
    intact: bool
    reason: str | None = None


HeartbeatAck.model_rebuild()
