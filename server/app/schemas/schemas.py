# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic v2 request/response schemas."""
from __future__ import annotations

import json
from datetime import datetime

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

from app.models.models import (
    AgentStatus,
    AgentTrustState,
    CommandKind,
    CommandStatus,
    EnrollmentTokenStatus,
    OperatorRole,
    ScriptExecutionScope,
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
    email: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=320,
            strip_whitespace=True,
            pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
        ),
    ]
    password: str
    role: OperatorRole = OperatorRole.readonly

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()


class OperatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: OperatorRole
    script_execution_scope: ScriptExecutionScope | None
    script_execution_scope_id: str | None
    disabled: bool
    created_at: datetime


class ScriptExecutionPermissionChange(BaseModel):
    scope: ScriptExecutionScope
    scope_id: Annotated[
        str | None, StringConstraints(min_length=1, max_length=36)
    ] = None
    reason: Annotated[
        str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
    ]

    @model_validator(mode="after")
    def scope_and_id_must_match(self):
        if self.scope == ScriptExecutionScope.global_ and self.scope_id is not None:
            raise ValueError("global script permission must not include scope_id")
        if self.scope != ScriptExecutionScope.global_ and self.scope_id is None:
            raise ValueError("site and agent script permissions require scope_id")
        return self


class ScriptExecutionPermissionRevoke(BaseModel):
    reason: Annotated[
        str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
    ]


class OperatorRoleChange(BaseModel):
    role: OperatorRole
    reason: Annotated[
        str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
    ]


class OperatorStatusChange(BaseModel):
    disabled: bool
    reason: Annotated[
        str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
    ]


# --------------------------------------------------------------------------- #
# Clients / Sites
# --------------------------------------------------------------------------- #
class ClientCreate(BaseModel):
    name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ]


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    created_at: datetime


class SiteCreate(BaseModel):
    client_id: str
    name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ]


class SiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    name: str
    created_at: datetime


class NavigationSiteOut(BaseModel):
    id: str
    client_id: str
    name: str
    endpoint_count: int = Field(ge=0)


class NavigationClientOut(BaseModel):
    id: str
    name: str
    sites: list[NavigationSiteOut] = Field(default_factory=list)


class NavigationClientListOut(BaseModel):
    items: list[NavigationClientOut] = Field(default_factory=list)
    truncated: bool = False


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
    name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ] = "Enrollment token"
    description: Annotated[
        str, StringConstraints(max_length=2_000, strip_whitespace=True)
    ] | None = None
    assigned_user_id: str | None = None
    environment: Annotated[
        str, StringConstraints(max_length=100, strip_whitespace=True)
    ] | None = None
    hostname_restriction: Annotated[
        str, StringConstraints(max_length=255, strip_whitespace=True)
    ] | None = None
    agent_name_restriction: Annotated[
        str, StringConstraints(max_length=255, strip_whitespace=True)
    ] | None = None
    labels: list[
        Annotated[str, StringConstraints(min_length=1, max_length=50, strip_whitespace=True)]
    ] = Field(default_factory=list, max_length=20)
    notes: Annotated[
        str, StringConstraints(max_length=4_000, strip_whitespace=True)
    ] | None = None
    label: str | None = None
    max_uses: int = Field(default=1, ge=1, le=100)
    expires_at: datetime | None = None

    @field_validator("labels")
    @classmethod
    def labels_must_be_unique(cls, value: list[str]) -> list[str]:
        if len({item.casefold() for item in value}) != len(value):
            raise ValueError("labels must be unique")
        return value


class EnrollmentTokenMetadataOut(BaseModel):
    """Safe token metadata used after the creation response."""
    id: str
    site_id: str
    organization_id: str
    organization_name: str
    site_name: str
    masked_token: str
    name: str
    description: str | None
    label: str | None
    assigned_user_id: str | None
    assigned_user_email: str | None
    environment: str | None
    hostname_restriction: str | None
    agent_name_restriction: str | None
    labels: list[str]
    max_uses: int
    use_count: int
    expires_at: datetime | None
    created_at: datetime
    created_by_id: str | None
    created_by_email: str | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by_id: str | None
    revoked_by_email: str | None
    status: EnrollmentTokenStatus
    notes: str | None


class EnrollmentTokenOut(EnrollmentTokenMetadataOut):
    """Creation-only response. No other response schema contains plaintext."""
    token: str


class EnrollmentTokenListOut(BaseModel):
    items: list[EnrollmentTokenMetadataOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class EnrollRequest(CommandEnvelopeCapabilities):
    """Sent by the agent installer to claim an identity."""
    enrollment_token: str
    hostname: str
    agent_name: str | None = None
    os: str = ""
    operating_system: str | None = None
    os_version: str = ""
    agent_version: str = ""
    architecture: str = ""
    environment: str | None = None
    site: str | None = None
    public_key: str | None = Field(default=None, max_length=16_384)


class EnrollResponse(BaseModel):
    agent_id: str
    agent_token: str  # long-lived bearer token, shown only here
    heartbeat_interval_seconds: int
    command_public_key: str  # PEM Ed25519 public key for verifying commands
    command_envelope_version: EnvelopeVersion
    command_public_keys: dict[str, str] = Field(default_factory=dict)
    command_signing_key_id: str = "default"
    credential_expires_at: datetime | None = None
    api_base_url: str | None = None
    configuration_metadata: dict = Field(default_factory=dict)


class AgentCredentialRenewResponse(BaseModel):
    agent_id: str
    agent_token: str
    credential_expires_at: datetime | None = None


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
    pending_results: list["PendingResultNotice"] = Field(
        default_factory=list, max_length=256
    )

    @field_validator("pending_results")
    @classmethod
    def pending_result_ids_must_be_unique(
        cls, value: list["PendingResultNotice"]
    ) -> list["PendingResultNotice"]:
        ids = [notice.command_id for notice in value]
        if len(ids) != len(set(ids)):
            raise ValueError("pending result command IDs must be unique")
        return value


class PendingResultNotice(BaseModel):
    command_id: Annotated[
        str, StringConstraints(min_length=1, max_length=64)
    ]
    agent_completed_at: datetime | None = None

    @field_validator("agent_completed_at")
    @classmethod
    def completion_time_must_include_timezone(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("agent_completed_at must include a timezone")
        return value


class HeartbeatAck(BaseModel):
    ok: bool = True
    # Commands the agent should pick up now (thin-poll model without WS).
    pending_commands: list["CommandOut"] = Field(default_factory=list)
    command_public_keys: dict[str, str] = Field(default_factory=dict)
    # Additive: lets a quarantined agent see its own state so it can stop
    # executing locally. Older agents ignore the field.
    trust_state: AgentTrustState = AgentTrustState.active


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
# Dispatch-side cap on the canonical payload (scripts included). Bounds what
# an operator can push toward an agent in one command.
MAX_COMMAND_PAYLOAD_BYTES = 64 * 1024


class CommandCreate(BaseModel):
    kind: CommandKind
    payload: dict = Field(default_factory=dict)
    ttl_seconds: int = Field(default=300, ge=1, le=86_400)

    @field_validator("payload")
    @classmethod
    def payload_must_be_canonicalizable(cls, value: dict) -> dict:
        value = validate_command_payload(value)
        size = len(json.dumps(value, separators=(",", ":")).encode("utf-8"))
        if size > MAX_COMMAND_PAYLOAD_BYTES:
            raise ValueError(
                f"command payload exceeds {MAX_COMMAND_PAYLOAD_BYTES} bytes"
            )
        return value


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
    signing_key_id: str | None
    signature: str
    status: CommandStatus
    created_at: datetime
    expires_at: datetime | None
    stdout_truncated: bool | None = None
    stderr_truncated: bool | None = None
    stdout_total_bytes: int | None = None
    stderr_total_bytes: int | None = None

    @field_serializer("issued_at", "expires_at", when_used="unless-none")
    def serialize_command_time(self, value: datetime) -> str:
        """Keep signed command timestamps canonical on every API response."""
        return format_command_time(value)


# Operator-facing command views. These are separate from CommandOut, which is
# part of the signed agent delivery contract inside HeartbeatAck and must not
# grow dashboard-only fields.
class CommandHistoryItemOut(BaseModel):
    """One row of an endpoint's command history.

    `status` is the effective status: a stored queued/dispatched command whose
    expires_at has passed is reported as expired even before the next agent
    heartbeat persists that transition, so operators never see an expired
    command still presented as pending work.
    """

    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    kind: CommandKind
    status: CommandStatus
    envelope_version: EnvelopeVersion
    schema_version: int | None
    signing_key_id: str | None
    exit_code: int | None
    stdout_truncated: bool | None
    stderr_truncated: bool | None
    created_at: datetime
    issued_at: datetime | None
    dispatched_at: datetime | None
    agent_completed_at: datetime | None
    completed_at: datetime | None
    expires_at: datetime | None

    @field_serializer("issued_at", "expires_at", when_used="unless-none")
    def serialize_command_time(self, value: datetime) -> str:
        """Keep signed command timestamps canonical on every API response."""
        return format_command_time(value)


class CommandHistoryOut(BaseModel):
    items: list[CommandHistoryItemOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    # Queue admission state so the dispatch UI can explain a 429 before it
    # happens instead of surprising the operator.
    outstanding: int = Field(ge=0)
    outstanding_limit: int = Field(ge=1)


class CommandDetailOut(CommandHistoryItemOut):
    """Full command record: signed envelope evidence plus the bounded result."""

    payload: dict
    nonce: str | None
    signature: str
    stdout: str | None
    stderr: str | None
    stdout_total_bytes: int | None
    stderr_total_bytes: int | None


# Server-side acceptance caps for reported command output. They mirror the
# agent's capture limits (256 KiB per stream, 384 KiB combined) plus a small
# allowance for agent-appended markers like "[command timed out]". A result
# beyond these bounds cannot have come from a compliant agent, so it is
# rejected outright rather than stored or re-truncated.
MAX_RESULT_STREAM_BYTES = 256 * 1024 + 256
MAX_RESULT_COMBINED_BYTES = 384 * 1024 + 256


class CommandResult(BaseModel):
    """Posted by the agent after execution.

    The truncation fields are the agent's own report of its bounded capture;
    None means an older agent that predates output limits (unknown, not
    "complete"). Sizes are validated in bytes, not characters, because the
    limits exist to bound storage and memory.
    """
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    agent_completed_at: datetime | None = None
    stdout_truncated: bool | None = None
    stderr_truncated: bool | None = None
    stdout_total_bytes: int | None = Field(default=None, ge=0)
    stderr_total_bytes: int | None = Field(default=None, ge=0)

    @field_validator("agent_completed_at")
    @classmethod
    def result_completion_time_must_include_timezone(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("agent_completed_at must include a timezone")
        return value

    @field_validator("stdout", "stderr")
    @classmethod
    def stream_within_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_RESULT_STREAM_BYTES:
            raise ValueError(
                f"output stream exceeds {MAX_RESULT_STREAM_BYTES} bytes"
            )
        return value

    @model_validator(mode="after")
    def combined_within_byte_limit(self) -> "CommandResult":
        combined = len(self.stdout.encode("utf-8")) + len(self.stderr.encode("utf-8"))
        if combined > MAX_RESULT_COMBINED_BYTES:
            raise ValueError(
                f"combined output exceeds {MAX_RESULT_COMBINED_BYTES} bytes"
            )
        return self


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    site_id: str
    name: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    architecture: str
    environment: str | None
    labels: list[str]
    owner_user_id: str | None
    enrolled_by_token_id: str | None
    credential_fingerprint: str | None
    credential_issued_at: datetime | None
    credential_expires_at: datetime | None
    command_envelope_versions: list[EnvelopeVersion]
    status: AgentStatus
    trust_state: AgentTrustState
    trust_state_reason: str | None
    trust_state_changed_at: datetime | None
    trust_state_changed_by: str | None
    last_seen_at: datetime | None
    enrolled_at: datetime
    revoked_at: datetime | None


class EnrollmentDashboardOut(BaseModel):
    total_agents: int = Field(ge=0)
    active_agents: int = Field(ge=0)
    offline_agents: int = Field(ge=0)
    revoked_agents: int = Field(ge=0)
    active_enrollment_tokens: int = Field(ge=0)
    expired_tokens: int = Field(ge=0)
    recently_enrolled_agents: list[AgentOut] = Field(default_factory=list)
    recent_enrollment_failures: int = Field(ge=0)


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    seq: int | None
    ts: datetime
    actor: str
    actor_user_id: str | None
    action: str
    agent_id: str | None
    enrollment_token_id: str | None
    organization_id: str | None
    source_ip: str | None
    detail: dict


class AuditEventListOut(BaseModel):
    items: list[AuditEventOut] = Field(default_factory=list)
    #: Sequence ceiling this page was taken against. Pass it back as the
    #: ``before_seq`` query parameter so later pages read the same snapshot of
    #: an append-only chain. Null only when no sequenced event exists yet.
    before_seq: int | None = None
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class EndpointListItemOut(BaseModel):
    id: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    status: AgentStatus
    last_seen_at: datetime | None
    client_id: str
    client_name: str
    site_id: str
    site_name: str
    cpu_percent: float | None
    mem_percent: float | None
    disk_percent: float | None
    logged_in_user: str | None


class EndpointListOut(BaseModel):
    items: list[EndpointListItemOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class EndpointTelemetrySampleOut(BaseModel):
    ts: datetime
    cpu_percent: float | None
    mem_percent: float | None
    disk_percent: float | None
    uptime_seconds: int | None
    logged_in_user: str | None


class EndpointDetailOut(BaseModel):
    id: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    command_envelope_versions: list[EnvelopeVersion]
    status: AgentStatus
    trust_state: AgentTrustState
    last_seen_at: datetime | None
    enrolled_at: datetime
    client_id: str
    client_name: str
    site_id: str
    site_name: str
    script_execution_allowed: bool
    current_telemetry: EndpointTelemetrySampleOut | None
    telemetry: list[EndpointTelemetrySampleOut] = Field(default_factory=list)
    telemetry_freshness: Literal["current", "stale", "unavailable"]
    stale_after_seconds: int = Field(ge=1)
    history_hours: int = Field(ge=1, le=168)
    history_limit: int = Field(ge=10, le=500)
    history_truncated: bool = False


class TrustStateChange(BaseModel):
    """Operator-supplied justification for a quarantine/restore/revoke action.
    The reason is mandatory: every trust transition must be explainable in the
    audit log."""
    reason: Annotated[str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)]


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


HeartbeatIn.model_rebuild()
HeartbeatAck.model_rebuild()
