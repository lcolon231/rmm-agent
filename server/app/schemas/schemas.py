# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic v2 request/response schemas."""
from __future__ import annotations

import json
import base64
import binascii
import hashlib
import re
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
from app.schemas.monitoring import AgentCheckAssignment


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


CapabilityName = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
]


class CommandEnvelopeCapabilities(BaseModel):
    supported_command_envelope_versions: list[EnvelopeVersion] = Field(
        default_factory=list, max_length=8
    )
    # Optional feature capabilities the agent advertises (issue #61), e.g.
    # "shell-session-v2". Absent means the agent supports none, so features that
    # require one fail closed as "unsupported".
    supported_capabilities: list[CapabilityName] = Field(
        default_factory=list, max_length=16
    )
    # Release channel this endpoint follows (issue #63). Absent means the agent
    # predates self-update or follows the default, so it is only ever targeted
    # by a stable-channel release.
    update_channel: Literal["stable", "beta", "canary"] | None = None

    @field_validator("supported_command_envelope_versions")
    @classmethod
    def versions_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("command envelope versions must be unique")
        return value

    @field_validator("supported_capabilities")
    @classmethod
    def capabilities_must_be_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("capabilities must be unique")
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


class AgentCredentialRenewRequest(BaseModel):
    """Versioned renewal request (issue #125).

    ``rotation_nonce`` is a fresh, agent-chosen value per attempt. The server
    records the last accepted nonce and rejects a verbatim replay (same nonce),
    while a genuine retry after a lost response uses a new nonce and rotates
    normally against the still-valid overlap credential.
    """

    rotation_nonce: str = Field(min_length=16, max_length=64)


class AgentCredentialRenewResponse(BaseModel):
    agent_id: str
    agent_token: str
    credential_expires_at: datetime | None = None
    # Overlap end for the just-superseded credential, so the agent knows how
    # long its previous token keeps working while it adopts the new one.
    overlap_expires_at: datetime | None = None
    credential_generation: int = 1


# --------------------------------------------------------------------------- #
# Heartbeat
# --------------------------------------------------------------------------- #
# Bounded shape for a reported agent build version (issue #179). The width
# matches the stored ``Agent.agent_version`` column so a value that validates
# always persists, and the character class keeps a version to the printable
# semver-ish alphabet an agent build stamps — never free-form prose that could
# turn the field into an unbounded log sink.
MAX_AGENT_VERSION_LENGTH = 50
AGENT_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$"
AgentVersionStr = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=MAX_AGENT_VERSION_LENGTH,
        pattern=AGENT_VERSION_PATTERN,
    ),
]


class HeartbeatIn(CommandEnvelopeCapabilities):
    # The running build, reported on every beat so an in-place upgrade refreshes
    # the stored value on the next successful check-in — no re-enrollment and no
    # inventory upload required (issue #179). Compatibility policy: absent is
    # accepted and leaves the stored value untouched, because agents released
    # before this field existed still beat normally. Anything present must be a
    # well-formed, bounded version; empty, oversized, or malformed values are
    # rejected with 422 rather than silently ignored, so a broken build is
    # visible instead of quietly reporting nothing.
    agent_version: AgentVersionStr | None = None
    cpu_percent: float = 0.0
    mem_percent: float = 0.0
    disk_percent: float = 0.0
    uptime_seconds: int = 0
    logged_in_user: str | None = None
    # Per-section SHA-256 of the agent's current inventory, e.g.
    # {"system": "<hex>", "cpu": "<hex>"}. Tiny by construction, so the beat
    # stays small; the server compares it against what it has stored and asks
    # for a resend through `inventory_requested` only when it differs or is
    # stale. Full snapshots go to POST /agents/me/inventory, never through a
    # heartbeat — that path was previously an unbounded, unvalidated sink.
    inventory_hashes: dict[
        Annotated[str, StringConstraints(max_length=32)],
        Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")],
    ] = Field(default_factory=dict, max_length=16)
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


class InventoryAck(BaseModel):
    """What the server did with a submission, per section.

    Distinguishing stored from unchanged lets the agent confirm the server
    holds its current state without a follow-up read, and makes a resend loop
    (agent keeps sending, server keeps deduping) visible in one response.
    """

    ok: bool = True
    stored_sections: list[str] = Field(default_factory=list)
    unchanged_sections: list[str] = Field(default_factory=list)


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
    # Sections the server wants resent, because their hash differs from what is
    # stored, they were never reported, or the stored copy is older than the
    # refresh interval. Empty means "nothing to send" — the common case, so a
    # steady-state endpoint transfers no inventory bytes at all.
    inventory_requested: list[str] = Field(default_factory=list)
    monitoring_checks: list["AgentCheckAssignment"] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
# Dispatch-side cap on the canonical payload (scripts included). Bounds what
# an operator can push toward an agent in one command.
MAX_COMMAND_PAYLOAD_BYTES = 64 * 1024
MAX_FILE_UPLOAD_BYTES = 32 * 1024
MAX_REGISTRY_BINARY_BYTES = 16 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_REGISTRY_TYPES = {
    "string", "expand_string", "dword", "qword", "multi_string", "binary"
}

# Bounded Windows event log access (issue #58). Metadata-only v1: the agent
# returns structured <System> fields only, never message text or EventData, so
# no PHI-bearing free text crosses the wire or is stored. Channels are a fixed
# server-side allowlist split into a standard tier and an elevated tier that a
# query must explicitly acknowledge (tier_ack) and which is separately audited.
_EVENT_LOG_STANDARD_CHANNELS = {"System", "Application", "Setup"}
_EVENT_LOG_ELEVATED_CHANNELS = {
    "Security",
    "Microsoft-Windows-Windows Defender/Operational",
}
_EVENT_LOG_MIN_WINDOW_SECONDS = 60
_EVENT_LOG_MAX_WINDOW_SECONDS = 7 * 24 * 3600
_EVENT_LOG_MAX_EVENTS = 500
_EVENT_LOG_MAX_PROVIDERS = 16
_EVENT_LOG_MAX_EVENT_IDS = 32
_EVENT_LOG_MAX_CURSOR = 2**63 - 1
_EVENT_LOG_PROVIDER_RE = re.compile(r"^[A-Za-z0-9 ._/\-]{1,255}$")


def event_log_channel_tier(channel: object) -> str | None:
    """Return the allowlist tier ("standard"/"elevated") for a channel, or None.

    None means the channel is not on the allowlist and the query must be
    rejected. Shared with the dispatch handler so the audit event can record the
    tier alongside the channel.
    """
    if channel in _EVENT_LOG_STANDARD_CHANNELS:
        return "standard"
    if channel in _EVENT_LOG_ELEVATED_CHANNELS:
        return "elevated"
    return None


def _validate_managed_windows_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("path must be a string")
    path = value.strip().replace("/", "\\")
    if len(path) > 260 or not re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f]+", path):
        raise ValueError("path must be an absolute Windows drive path")
    if path.startswith(("\\\\", "\\?\\", "\\.\\")) or ".." in path.split("\\"):
        raise ValueError("device, UNC, and traversal paths are not supported")
    if ":" in path[2:]:
        raise ValueError("alternate data streams are not supported")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    for segment in path[3:].split("\\"):
        if not segment or segment != segment.rstrip(" .") or segment.split(".", 1)[0].upper() in reserved:
            raise ValueError("path contains an empty, ambiguous, or reserved device segment")
    folded = path.casefold().rstrip("\\")
    roots = (r"c:\programdata\nodelink\managed", r"c:\windows\temp\nodelink")
    if not any(folded == root or folded.startswith(root + "\\") for root in roots):
        raise ValueError("path is outside the managed transfer roots")
    return path


def _validate_registry_location(payload: dict) -> tuple[str, str, str, int]:
    allowed = {"hive", "key", "value_name", "view"}
    if set(payload) - allowed:
        raise ValueError("registry payload contains unsupported fields")
    hive = payload.get("hive")
    key = payload.get("key")
    value_name = payload.get("value_name")
    view = payload.get("view", 64)
    if hive not in {"HKLM", "HKCU"}:
        raise ValueError("registry hive must be HKLM or HKCU")
    if not isinstance(key, str):
        raise ValueError("registry key must be a string")
    key = key.strip().replace("/", "\\").strip("\\")
    folded_key = key.casefold()
    registry_root = "software\\nodelink\\managed"
    if (
        len(key) > 240
        or ".." in key.split("\\")
        or (folded_key != registry_root and not folded_key.startswith(registry_root + "\\"))
    ):
        raise ValueError("registry key is outside the managed subtree")
    if not isinstance(value_name, str) or len(value_name) > 163 or "\\" in value_name or "\x00" in value_name:
        raise ValueError("registry value_name is invalid")
    if view not in {32, 64}:
        raise ValueError("registry view must be 32 or 64")
    return hive, key, value_name, view


def _validate_event_log_query(payload: dict) -> dict:
    allowed = {
        "channel", "tier_ack", "time_window_seconds",
        "providers", "levels", "event_ids", "max_events", "cursor",
    }
    if set(payload) - allowed:
        raise ValueError("event log query payload contains unsupported fields")
    channel = payload.get("channel")
    tier = event_log_channel_tier(channel)
    if tier is None:
        raise ValueError("event log channel is not on the allowlist")
    tier_ack = payload.get("tier_ack", False)
    if not isinstance(tier_ack, bool):
        raise ValueError("tier_ack must be a boolean")
    if tier == "elevated" and tier_ack is not True:
        raise ValueError("elevated event log channels require tier_ack=true")
    if tier == "standard" and tier_ack:
        raise ValueError("tier_ack is only valid for elevated channels")
    window = payload.get("time_window_seconds")
    if (
        not isinstance(window, int) or isinstance(window, bool)
        or not _EVENT_LOG_MIN_WINDOW_SECONDS <= window <= _EVENT_LOG_MAX_WINDOW_SECONDS
    ):
        raise ValueError("time_window_seconds is out of range")
    max_events = payload.get("max_events")
    if (
        not isinstance(max_events, int) or isinstance(max_events, bool)
        or not 1 <= max_events <= _EVENT_LOG_MAX_EVENTS
    ):
        raise ValueError("max_events is out of range")
    normalized: dict = {
        "channel": channel,
        "tier_ack": tier_ack,
        "time_window_seconds": window,
        "max_events": max_events,
    }
    providers = payload.get("providers")
    if providers is not None:
        if not isinstance(providers, list) or not 1 <= len(providers) <= _EVENT_LOG_MAX_PROVIDERS:
            raise ValueError("providers must be a bounded non-empty list")
        cleaned: list[str] = []
        for item in providers:
            if not isinstance(item, str) or not _EVENT_LOG_PROVIDER_RE.fullmatch(item):
                raise ValueError("provider name is invalid")
            cleaned.append(item)
        normalized["providers"] = cleaned
    levels = payload.get("levels")
    if levels is not None:
        if not isinstance(levels, list) or not 1 <= len(levels) <= 5:
            raise ValueError("levels must be a bounded non-empty list")
        seen: list[int] = []
        for item in levels:
            if not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 5 or item in seen:
                raise ValueError("levels must be unique integers between 1 and 5")
            seen.append(item)
        normalized["levels"] = seen
    event_ids = payload.get("event_ids")
    if event_ids is not None:
        if not isinstance(event_ids, list) or not 1 <= len(event_ids) <= _EVENT_LOG_MAX_EVENT_IDS:
            raise ValueError("event_ids must be a bounded non-empty list")
        cleaned_ids: list[int] = []
        for item in event_ids:
            if not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 65535:
                raise ValueError("event_id is out of range")
            cleaned_ids.append(item)
        normalized["event_ids"] = cleaned_ids
    cursor = payload.get("cursor")
    if cursor is not None:
        if not isinstance(cursor, int) or isinstance(cursor, bool) or not 0 <= cursor <= _EVENT_LOG_MAX_CURSOR:
            raise ValueError("cursor must be a non-negative integer watermark")
        normalized["cursor"] = cursor
    return normalized


# Package-provider validation (issue #55). Identifiers cover winget, msstore, and
# chocolatey ids; the bound matches the agent's normalizePackageIDs.
_PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_PACKAGE_PROVIDERS = {"winget", "chocolatey"}
_PACKAGE_OPERATIONS = {"install", "upgrade"}
_MAX_PACKAGE_TARGETS = 100


def _normalize_package_ids(raw: object) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("package_ids must be a non-empty array")
    if len(raw) > _MAX_PACKAGE_TARGETS:
        raise ValueError(f"at most {_MAX_PACKAGE_TARGETS} package targets are allowed")
    normalized: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError("every package_id must be a string")
        package_id = value.strip()
        if not _PACKAGE_ID_RE.fullmatch(package_id):
            raise ValueError(f"invalid package_id: {value!r}")
        if package_id not in normalized:
            normalized.append(package_id)
    return normalized


def _validate_package_scan(payload: dict) -> dict:
    """scan_packages accepts an optional provider filter and nothing else."""
    if set(payload) - {"provider"}:
        raise ValueError("scan_packages payload contains unsupported fields")
    provider = payload.get("provider")
    if provider is None:
        return {}
    if provider not in _PACKAGE_PROVIDERS:
        raise ValueError("scan_packages provider is unsupported")
    return {"provider": provider}


def _validate_package_install(payload: dict) -> dict:
    """install_packages: bounded targets via winget or opt-in chocolatey.

    Chocolatey additionally requires signed source, source_digest, and signer
    evidence; winget must not carry any of it. The server validates the shape and
    records the evidence; endpoint opt-in is enforced by the capability gate and
    re-checked on the agent.
    """
    allowed = {"provider", "operation", "package_ids", "source", "source_digest", "signer"}
    if set(payload) - allowed:
        raise ValueError("install_packages payload contains unsupported fields")
    provider = payload.get("provider")
    if provider not in _PACKAGE_PROVIDERS:
        raise ValueError("install_packages provider is unsupported")
    operation = payload.get("operation")
    if operation not in _PACKAGE_OPERATIONS:
        raise ValueError("install_packages operation must be install or upgrade")
    package_ids = _normalize_package_ids(payload.get("package_ids"))

    if provider == "winget":
        if any(key in payload for key in ("source", "source_digest", "signer")):
            raise ValueError("winget install must not include source evidence")
        return {"provider": provider, "operation": operation, "package_ids": package_ids}

    # Chocolatey: require and normalize the signed source trust evidence.
    source = payload.get("source")
    if not isinstance(source, str):
        raise ValueError("chocolatey install requires a source string")
    source = source.strip()
    if not 1 <= len(source.encode("utf-8")) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in source):
        raise ValueError("chocolatey source must be 1-512 printable bytes")
    digest = payload.get("source_digest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ValueError("chocolatey source_digest must be a lowercase SHA-256 digest")
    signer = payload.get("signer")
    if not isinstance(signer, str):
        raise ValueError("chocolatey install requires a signer string")
    signer = signer.strip()
    if not 1 <= len(signer.encode("utf-8")) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in signer):
        raise ValueError("chocolatey signer must be 1-255 printable bytes")
    return {
        "provider": provider,
        "operation": operation,
        "package_ids": package_ids,
        "source": source,
        "source_digest": digest,
        "signer": signer,
    }


# Software-deployment validation (issue #56).
_THUMBPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_DEPLOY_MAX_ARGS = 32
_DEPLOY_MAX_ARG_LEN = 256
_DEPLOY_MAX_URL_LEN = 2048
_DEPLOY_MAX_SUCCESS_CODES = 32


def _validate_software_deploy(payload: dict) -> dict:
    """deploy_software: authenticated MSI/EXE deployment with integrity checks.

    Source trust is https + a mandatory SHA-256 digest, with an optional
    Authenticode signer thumbprint. Arguments are bounded printable argv tokens
    (installers run as argv, never through a shell). Reboot reuses the #53
    post-install reboot shape.
    """
    allowed = {
        "url", "sha256", "installer_type", "arguments",
        "signer_thumbprint", "timeout_seconds", "success_exit_codes", "reboot",
    }
    if set(payload) - allowed:
        raise ValueError("deploy_software payload contains unsupported fields")

    url = payload.get("url")
    if not isinstance(url, str) or not 1 <= len(url) <= _DEPLOY_MAX_URL_LEN:
        raise ValueError("deploy_software url is required")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("deploy_software url contains control characters")
    if not re.match(r"^https://", url, re.IGNORECASE):
        raise ValueError("deploy_software url must be https")

    sha = payload.get("sha256")
    if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
        raise ValueError("deploy_software sha256 must be a lowercase SHA-256 digest")

    installer_type = payload.get("installer_type")
    if installer_type not in {"msi", "exe"}:
        raise ValueError("deploy_software installer_type must be msi or exe")

    arguments = payload.get("arguments", [])
    if not isinstance(arguments, list) or len(arguments) > _DEPLOY_MAX_ARGS:
        raise ValueError(f"deploy_software allows at most {_DEPLOY_MAX_ARGS} arguments")
    for arg in arguments:
        if not isinstance(arg, str) or len(arg) > _DEPLOY_MAX_ARG_LEN:
            raise ValueError("deploy_software arguments must be short strings")
        if any(ord(c) < 32 or ord(c) == 127 for c in arg):
            raise ValueError("deploy_software arguments must be printable")

    timeout = payload.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 30 <= timeout <= 3600:
        raise ValueError("deploy_software timeout_seconds must be between 30 and 3600")

    result: dict = {
        "url": url,
        "sha256": sha,
        "installer_type": installer_type,
        "arguments": list(arguments),
        "timeout_seconds": timeout,
    }

    thumbprint = payload.get("signer_thumbprint")
    if thumbprint is not None:
        if not isinstance(thumbprint, str) or not _THUMBPRINT_RE.fullmatch(thumbprint):
            raise ValueError("deploy_software signer_thumbprint must be a 40-char hex thumbprint")
        result["signer_thumbprint"] = thumbprint

    success_codes = payload.get("success_exit_codes")
    if success_codes is not None:
        if not isinstance(success_codes, list) or len(success_codes) > _DEPLOY_MAX_SUCCESS_CODES:
            raise ValueError("deploy_software success_exit_codes is invalid")
        for code in success_codes:
            if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 65535:
                raise ValueError("deploy_software success_exit_codes must be 0-65535 integers")
        result["success_exit_codes"] = list(success_codes)

    reboot = payload.get("reboot")
    if reboot is not None:
        if not isinstance(reboot, dict) or set(reboot) - {"policy", "delay_seconds", "requires_no_user"}:
            raise ValueError("deploy_software reboot is invalid")
        policy = reboot.get("policy")
        if policy not in {"never", "if_required", "forced"}:
            raise ValueError("deploy_software reboot.policy is invalid")
        normalized_reboot: dict = {"policy": policy}
        if policy != "never":
            delay = reboot.get("delay_seconds")
            if not isinstance(delay, int) or isinstance(delay, bool) or not 60 <= delay <= 3600:
                raise ValueError("deploy_software reboot.delay_seconds must be between 60 and 3600")
            requires_no_user = reboot.get("requires_no_user", True)
            if not isinstance(requires_no_user, bool):
                raise ValueError("deploy_software reboot.requires_no_user must be a boolean")
            normalized_reboot["delay_seconds"] = delay
            normalized_reboot["requires_no_user"] = requires_no_user
        result["reboot"] = normalized_reboot

    return result


# ProtectedServices is the case-insensitive denylist of services that may never be controlled.
# MUST stay in sync with agent/internal/svcproc/svcproc.go ProtectedServices.
PROTECTED_SERVICES: frozenset[str] = frozenset(
    {
        "nodelinkagent", "windefend", "mpssvc", "eventlog",
        "rpcss", "dcomlaunch", "rpceptmapper", "winmgmt",
        "lsm", "dnscache", "dhcp", "bfe", "gpsvc",
        "netlogon", "samss", "cryptsvc", "schedule",
        "profsvc", "plugplay", "power", "nsi",
    }
)

# ProtectedProcesses is the case-insensitive image-name denylist for termination.
# MUST stay in sync with agent/internal/svcproc/svcproc.go ProtectedProcesses.
PROTECTED_PROCESSES: frozenset[str] = frozenset(
    {
        "system", "idle", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsm.exe", "svchost.exe",
        "nodelinkagent.exe",
    }
)

_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,256}$")
_SERVICE_ACTIONS = frozenset({"start", "stop", "restart"})


def _validate_service_control(payload: dict) -> dict:
    allowed = {"name", "action", "confirm", "reason"}
    if set(payload) != allowed:
        raise ValueError("control_service requires name, action, confirm, and reason")
    name = payload.get("name")
    if not isinstance(name, str) or not _SERVICE_NAME_RE.fullmatch(name):
        raise ValueError("service name is invalid")
    name_clean = name.strip()
    if name_clean.lower() in PROTECTED_SERVICES:
        raise ValueError("service is protected and cannot be controlled")
    action = payload.get("action")
    if action not in _SERVICE_ACTIONS:
        raise ValueError("service action must be start, stop, or restart")
    if payload.get("confirm") is not True:
        raise ValueError("control_service requires confirm=true")
    reason = payload.get("reason")
    if not isinstance(reason, str):
        raise ValueError("reason must be a string")
    reason = reason.strip()
    reason_bytes = len(reason.encode("utf-8"))
    if not 10 <= reason_bytes <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in reason):
        raise ValueError("reason must contain 10-512 printable UTF-8 bytes")
    return {
        "name": name_clean,
        "action": action,
        "confirm": True,
        "reason": reason,
    }


def _validate_process_terminate(payload: dict) -> dict:
    allowed = {"pid", "confirm", "reason", "expected_name"}
    if set(payload) - allowed or not {"pid", "confirm", "reason"}.issubset(payload):
        raise ValueError("terminate_process payload contains unsupported or missing fields")
    pid = payload.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
        raise ValueError("process pid must be a positive integer")
    if pid in (0, 4):
        raise ValueError("process is protected and cannot be terminated")
    if payload.get("confirm") is not True:
        raise ValueError("terminate_process requires confirm=true")
    reason = payload.get("reason")
    if not isinstance(reason, str):
        raise ValueError("reason must be a string")
    reason = reason.strip()
    reason_bytes = len(reason.encode("utf-8"))
    if not 10 <= reason_bytes <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in reason):
        raise ValueError("reason must contain 10-512 printable UTF-8 bytes")
    expected_name = payload.get("expected_name")
    if expected_name is not None:
        if not isinstance(expected_name, str):
            raise ValueError("expected_name must be a string")
        expected_name = expected_name.strip()
        if len(expected_name) > 260 or any(ord(c) < 32 or ord(c) == 127 for c in expected_name):
            raise ValueError("expected_name is invalid")
        if expected_name.lower() in PROTECTED_PROCESSES:
            raise ValueError("process is protected and cannot be terminated")
    return {
        "pid": pid,
        "confirm": True,
        "reason": reason,
        **({"expected_name": expected_name} if expected_name else {}),
    }


# Agent self-update validation (issue #63).
_SELF_UPDATE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_SELF_UPDATE_PLATFORM_RE = re.compile(r"^[a-z0-9]{1,16}/[a-z0-9]{1,16}$")
_SELF_UPDATE_VERSION_RE = re.compile(
    r"^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,64})?$"
)
_SELF_UPDATE_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_SELF_UPDATE_CHANNELS = frozenset({"stable", "beta", "canary"})


def _validate_agent_self_update(payload: dict) -> dict:
    """agent_self_update: the signed release metadata the endpoint acts on.

    The rollout path builds this from a published, signed manifest, so this
    validator is the fail-closed structural gate that keeps anything else from
    reaching an endpoint. It is deliberately identical in shape to the agent's
    own re-check (agent/internal/selfupdate).
    """
    allowed = {
        "release_id", "version", "channel", "platform", "artifact",
        "min_supported_version", "signer_thumbprint", "health_check",
    }
    required = {
        "release_id", "version", "channel", "platform", "artifact",
        "min_supported_version",
    }
    if set(payload) - allowed or not required.issubset(payload):
        raise ValueError("agent_self_update payload contains unsupported or missing fields")

    release_id = payload["release_id"]
    if not isinstance(release_id, str) or not _SELF_UPDATE_ID_RE.fullmatch(release_id):
        raise ValueError("agent_self_update release_id is invalid")
    for field in ("version", "min_supported_version"):
        value = payload[field]
        if not isinstance(value, str) or not _SELF_UPDATE_VERSION_RE.fullmatch(value):
            raise ValueError(f"agent_self_update {field} must be MAJOR.MINOR.PATCH[-prerelease]")
    channel = payload["channel"]
    if channel not in _SELF_UPDATE_CHANNELS:
        raise ValueError("agent_self_update channel is invalid")
    platform = payload["platform"]
    if not isinstance(platform, str) or not _SELF_UPDATE_PLATFORM_RE.fullmatch(platform):
        raise ValueError("agent_self_update platform is invalid")

    artifact = payload["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"url", "sha256", "size_bytes"}:
        raise ValueError("agent_self_update artifact is invalid")
    url = artifact["url"]
    if not isinstance(url, str) or len(url) > _DEPLOY_MAX_URL_LEN:
        raise ValueError("agent_self_update artifact url is invalid")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("agent_self_update artifact url contains control characters")
    if not re.match(r"^https://", url, re.IGNORECASE):
        raise ValueError("agent_self_update artifact url must be https")
    if not isinstance(artifact["sha256"], str) or not _SHA256_RE.fullmatch(artifact["sha256"]):
        raise ValueError("agent_self_update artifact sha256 must be a lowercase SHA-256 digest")
    size = artifact["size_bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= _SELF_UPDATE_MAX_ARTIFACT_BYTES:
        raise ValueError("agent_self_update artifact size_bytes is out of range")

    normalized = {
        "release_id": release_id,
        "version": payload["version"],
        "channel": channel,
        "platform": platform,
        "artifact": {"url": url, "sha256": artifact["sha256"], "size_bytes": size},
        "min_supported_version": payload["min_supported_version"],
    }
    thumbprint = payload.get("signer_thumbprint")
    if thumbprint is not None:
        if not isinstance(thumbprint, str) or not _THUMBPRINT_RE.fullmatch(thumbprint):
            raise ValueError("agent_self_update signer_thumbprint must be a 40-char hex thumbprint")
        normalized["signer_thumbprint"] = thumbprint
    health = payload.get("health_check")
    if health is not None:
        if not isinstance(health, dict) or set(health) != {"timeout_seconds"}:
            raise ValueError("agent_self_update health_check is invalid")
        timeout = health["timeout_seconds"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 60 <= timeout <= 3600:
            raise ValueError("agent_self_update health_check.timeout_seconds must be 60-3600")
        normalized["health_check"] = {"timeout_seconds": timeout}
    return normalized


def _validate_agent_update_rollback(payload: dict) -> dict:
    """agent_update_rollback: restore the endpoint's retained previous build."""
    allowed = {"reason", "confirm", "expected_current_version"}
    if set(payload) - allowed or not {"reason", "confirm"}.issubset(payload):
        raise ValueError("agent_update_rollback payload contains unsupported or missing fields")
    if payload.get("confirm") is not True:
        raise ValueError("agent_update_rollback requires confirm=true")
    reason = payload.get("reason")
    if not isinstance(reason, str):
        raise ValueError("reason must be a string")
    reason = reason.strip()
    reason_bytes = len(reason.encode("utf-8"))
    if not 10 <= reason_bytes <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in reason):
        raise ValueError("reason must contain 10-256 printable UTF-8 bytes")
    normalized = {"reason": reason, "confirm": True}
    expected = payload.get("expected_current_version")
    if expected is not None:
        if not isinstance(expected, str) or not _SELF_UPDATE_VERSION_RE.fullmatch(expected):
            raise ValueError("expected_current_version must be MAJOR.MINOR.PATCH[-prerelease]")
        normalized["expected_current_version"] = expected
    return normalized


class CommandCreate(BaseModel):
    kind: CommandKind
    payload: dict = Field(default_factory=dict)
    ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    # Optional script-library provenance (issue #50). When a run originates from
    # a reviewed script version — and optionally a captured parameter value set —
    # the caller passes the ids so the run row records where it came from. The
    # dispatch handler validates existence and that the value set belongs to the
    # version, failing closed on any mismatch.
    script_version_id: str | None = Field(default=None, max_length=36)
    script_parameter_value_set_id: str | None = Field(default=None, max_length=36)

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

    @model_validator(mode="after")
    def typed_operation_payload(self) -> "CommandCreate":
        if self.kind in {CommandKind.reboot, CommandKind.shutdown}:
            allowed = {"confirm", "reason", "delay_seconds", "user_consent"}
            if set(self.payload) != allowed:
                raise ValueError(
                    "reboot and shutdown require confirm, reason, delay_seconds, and user_consent"
                )
            if self.payload.get("confirm") is not True:
                raise ValueError("power operation requires confirm=true")
            reason = self.payload.get("reason")
            if not isinstance(reason, str):
                raise ValueError("power operation reason must be a string")
            reason = reason.strip()
            reason_bytes = len(reason.encode("utf-8"))
            if not 10 <= reason_bytes <= 512 or any(ord(char) < 32 or ord(char) == 127 for char in reason):
                raise ValueError("power operation reason must contain 10-512 printable UTF-8 bytes")
            delay = self.payload.get("delay_seconds")
            if not isinstance(delay, int) or isinstance(delay, bool) or not 30 <= delay <= 3600:
                raise ValueError("power operation delay_seconds must be between 30 and 3600")
            consent = self.payload.get("user_consent")
            if consent not in {"confirmed", "no_user_session"}:
                raise ValueError("user_consent must be confirmed or no_user_session")
            self.payload = {
                "confirm": True,
                "reason": reason,
                "delay_seconds": delay,
                "user_consent": consent,
            }
            return self

        if self.kind == CommandKind.cancel_power_action:
            if set(self.payload) != {"confirm", "reason"}:
                raise ValueError("cancel_power_action requires confirm and reason")
            if self.payload.get("confirm") is not True:
                raise ValueError("cancel_power_action requires confirm=true")
            reason = self.payload.get("reason")
            if not isinstance(reason, str):
                raise ValueError("cancellation reason must be a string")
            reason = reason.strip()
            reason_bytes = len(reason.encode("utf-8"))
            if not 10 <= reason_bytes <= 512 or any(ord(char) < 32 or ord(char) == 127 for char in reason):
                raise ValueError("cancellation reason must contain 10-512 printable UTF-8 bytes")
            self.payload = {"confirm": True, "reason": reason}
            return self

        if self.kind == CommandKind.file_upload:
            allowed = {"path", "content_base64", "sha256", "overwrite"}
            if set(self.payload) - allowed or set(self.payload) != allowed:
                raise ValueError("file_upload requires path, content_base64, sha256, and overwrite")
            path = _validate_managed_windows_path(self.payload["path"])
            digest = self.payload["sha256"]
            overwrite = self.payload["overwrite"]
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise ValueError("sha256 must be a lowercase SHA-256 digest")
            if not isinstance(overwrite, bool):
                raise ValueError("overwrite must be a boolean")
            encoded = self.payload["content_base64"]
            if not isinstance(encoded, str):
                raise ValueError("content_base64 must be a string")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("content_base64 is not canonical base64") from exc
            if len(decoded) > MAX_FILE_UPLOAD_BYTES:
                raise ValueError(f"file upload exceeds {MAX_FILE_UPLOAD_BYTES} bytes")
            if hashlib.sha256(decoded).hexdigest() != digest:
                raise ValueError("file upload digest does not match content")
            self.payload = {"path": path, "content_base64": encoded, "sha256": digest, "overwrite": overwrite}
            return self

        if self.kind == CommandKind.file_download:
            if set(self.payload) - {"path", "expected_sha256"} or "path" not in self.payload:
                raise ValueError("file_download payload contains unsupported fields")
            path = _validate_managed_windows_path(self.payload["path"])
            expected = self.payload.get("expected_sha256")
            if expected is not None and (not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected)):
                raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
            self.payload = {"path": path, **({"expected_sha256": expected} if expected else {})}
            return self

        if self.kind in {CommandKind.registry_read, CommandKind.registry_write, CommandKind.registry_delete}:
            base_keys = {"hive", "key", "value_name", "view"}
            extra = {
                CommandKind.registry_read: set(),
                CommandKind.registry_write: {"type", "data", "expected_current_sha256"},
                CommandKind.registry_delete: {"confirm", "expected_current_sha256"},
            }[self.kind]
            if set(self.payload) - (base_keys | extra) or not {"hive", "key", "value_name"}.issubset(self.payload):
                raise ValueError("registry payload contains unsupported or missing fields")
            location = {name: self.payload[name] for name in base_keys if name in self.payload}
            hive, key, value_name, view = _validate_registry_location(location)
            normalized = {"hive": hive, "key": key, "value_name": value_name, "view": view}
            if self.kind == CommandKind.registry_write:
                value_type = self.payload.get("type")
                if value_type not in _REGISTRY_TYPES:
                    raise ValueError("registry type is unsupported")
                data = self.payload.get("data")
                if value_type in {"string", "expand_string"} and (not isinstance(data, str) or len(data.encode("utf-8")) > 16 * 1024):
                    raise ValueError("registry string data is invalid or oversized")
                if value_type == "multi_string" and (not isinstance(data, list) or len(data) > 256 or any(not isinstance(item, str) or "\x00" in item for item in data)):
                    raise ValueError("registry multi_string data is invalid")
                if value_type == "dword" and (not isinstance(data, int) or isinstance(data, bool) or not 0 <= data <= 0xFFFFFFFF):
                    raise ValueError("registry dword data is invalid")
                if value_type == "qword" and (not isinstance(data, int) or isinstance(data, bool) or not 0 <= data <= 0x7FFFFFFFFFFFFFFF):
                    raise ValueError("registry qword data is invalid")
                if value_type == "binary":
                    if not isinstance(data, str):
                        raise ValueError("registry binary data must be base64")
                    try:
                        binary = base64.b64decode(data, validate=True)
                    except (binascii.Error, ValueError) as exc:
                        raise ValueError("registry binary data is not canonical base64") from exc
                    if len(binary) > MAX_REGISTRY_BINARY_BYTES:
                        raise ValueError("registry binary data is oversized")
                normalized.update({"type": value_type, "data": data})
            else:
                if self.kind == CommandKind.registry_delete and self.payload.get("confirm") is not True:
                    raise ValueError("registry_delete requires confirm=true")
                if self.kind == CommandKind.registry_delete:
                    normalized["confirm"] = True
            expected = self.payload.get("expected_current_sha256")
            if expected is not None:
                if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
                    raise ValueError("expected_current_sha256 must be a lowercase SHA-256 digest")
                normalized["expected_current_sha256"] = expected
            self.payload = normalized
            return self

        if self.kind == CommandKind.remediation_rollback:
            if set(self.payload) != {"backup_id"} or not isinstance(self.payload["backup_id"], str) or not _BACKUP_ID_RE.fullmatch(self.payload["backup_id"]):
                raise ValueError("remediation_rollback requires a valid backup_id")
            return self

        if self.kind == CommandKind.query_event_log:
            self.payload = _validate_event_log_query(self.payload)
            return self

        if self.kind == CommandKind.scan_packages:
            self.payload = _validate_package_scan(self.payload)
            return self

        if self.kind == CommandKind.install_packages:
            self.payload = _validate_package_install(self.payload)
            return self

        if self.kind == CommandKind.deploy_software:
            self.payload = _validate_software_deploy(self.payload)
            return self

        if self.kind == CommandKind.list_services:
            if set(self.payload):
                raise ValueError("list_services payload must be empty")
            self.payload = {}
            return self

        if self.kind == CommandKind.list_processes:
            if set(self.payload):
                raise ValueError("list_processes payload must be empty")
            self.payload = {}
            return self

        if self.kind == CommandKind.control_service:
            self.payload = _validate_service_control(self.payload)
            return self

        if self.kind == CommandKind.terminate_process:
            self.payload = _validate_process_terminate(self.payload)
            return self

        if self.kind == CommandKind.agent_self_update:
            self.payload = _validate_agent_self_update(self.payload)
            return self

        if self.kind == CommandKind.agent_update_rollback:
            self.payload = _validate_agent_update_rollback(self.payload)
            return self

        if self.kind != CommandKind.install_updates:
            return self

        # target_kbs is accepted as the pre-typed-payload compatibility alias;
        # stored/signed commands are normalized to kb_ids.
        allowed = {"install_all", "kb_ids", "target_kbs", "update_ids"}
        if set(self.payload) - allowed:
            raise ValueError("install_updates payload contains unsupported fields")

        install_all = self.payload.get("install_all", False)
        if not isinstance(install_all, bool):
            raise ValueError("install_all must be a boolean")
        kb_values = self.payload.get("kb_ids", [])
        legacy_kb_values = self.payload.get("target_kbs", [])
        update_values = self.payload.get("update_ids", [])
        if (
            not isinstance(kb_values, list)
            or not isinstance(legacy_kb_values, list)
            or not isinstance(update_values, list)
        ):
            raise ValueError("kb_ids and update_ids must be arrays")
        kb_values = [*kb_values, *legacy_kb_values]
        if len(kb_values) + len(update_values) > 100:
            raise ValueError("at most 100 update targets are allowed")
        if install_all and (kb_values or update_values):
            raise ValueError("install_all cannot be combined with update identifiers")
        if not install_all and not kb_values and not update_values:
            raise ValueError("choose update identifiers or explicitly set install_all")

        normalized_kbs: list[str] = []
        for value in kb_values:
            if not isinstance(value, str):
                raise ValueError("every KB target must be a string")
            kb = value.strip().upper()
            if kb and not kb.startswith("KB"):
                kb = f"KB{kb}"
            if not re.fullmatch(r"KB[0-9]{4,10}", kb):
                raise ValueError(f"invalid KB target: {value!r}")
            if kb not in normalized_kbs:
                normalized_kbs.append(kb)

        normalized_update_ids: list[str] = []
        for value in update_values:
            if not isinstance(value, str):
                raise ValueError("every Windows Update ID must be a string")
            update_id = value.strip().lower()
            if not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                update_id,
            ):
                raise ValueError(f"invalid Windows Update ID: {value!r}")
            if update_id not in normalized_update_ids:
                normalized_update_ids.append(update_id)

        self.payload = (
            {"install_all": True}
            if install_all
            else {"kb_ids": normalized_kbs, "update_ids": normalized_update_ids}
        )
        return self


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


class TaskRunItemOut(CommandHistoryItemOut):
    """One row of the complete, cross-endpoint task-run history (issue #50).

    Adds the run provenance stored on the command row — who dispatched it, the
    script-library origin, its link into the audit chain, and forward-compat
    scheduling/retry lineage — plus the endpoint hostname for display. Like the
    per-endpoint history, this metadata view never carries captured output; the
    sensitive stdout/stderr stay behind the audited command-detail read.
    """

    hostname: str | None = None
    actor_email: str | None = None
    actor_operator_id: str | None = None
    script_version_id: str | None = None
    script_parameter_value_set_id: str | None = None
    dispatch_audit_event_id: str | None = None
    planned_at: datetime | None = None
    attempt: int = 1
    parent_command_id: str | None = None


class TaskRunHistoryOut(BaseModel):
    items: list[TaskRunItemOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


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
    supported_capabilities: list[CapabilityName] = Field(default_factory=list)
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
