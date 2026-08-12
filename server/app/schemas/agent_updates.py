# SPDX-License-Identifier: AGPL-3.0-only
"""Request/response contracts for signed, staged agent self-update (issue #63)."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator

from app.core.agent_updates import CHANNELS, PLATFORM_RE, parse_version


VersionStr = Annotated[str, StringConstraints(min_length=1, max_length=64)]
Sha256Str = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ThumbprintStr = Annotated[str, StringConstraints(pattern=r"^[0-9A-Fa-f]{40}$")]
PlatformStr = Annotated[str, StringConstraints(min_length=3, max_length=33)]
ReasonStr = Annotated[
    str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
]


class AgentUpdateReleaseCreate(BaseModel):
    """Publish one signed release artifact for one platform and channel."""

    version: VersionStr
    channel: Literal["stable", "beta", "canary"]
    platform: PlatformStr
    artifact_url: Annotated[str, StringConstraints(min_length=8, max_length=2_048)]
    artifact_sha256: Sha256Str
    artifact_size_bytes: int = Field(ge=1, le=256 * 1024 * 1024)
    # Optional pinned Authenticode signer, checked at the endpoint in addition
    # to the mandatory digest.
    signer_thumbprint: ThumbprintStr | None = None
    # Anti-rollback floor. An endpoint refuses a target below it, which is how a
    # withdrawn build is kept from returning through a replayed release.
    min_supported_version: VersionStr
    # Canary halt policy for this release's staged rollout.
    failure_threshold_percent: int = Field(default=20, ge=1, le=100)
    min_attempts_before_halt: int = Field(default=5, ge=1, le=10_000)
    # Seconds an endpoint gives the new build to report healthy before it rolls
    # itself back.
    health_timeout_seconds: int = Field(default=600, ge=60, le=3_600)

    @field_validator("version", "min_supported_version")
    @classmethod
    def versions_must_be_comparable(cls, value: str) -> str:
        parse_version(value)  # raises AgentUpdateError (a ValueError) if not
        return value

    @field_validator("platform")
    @classmethod
    def platform_must_be_a_selector(cls, value: str) -> str:
        if not PLATFORM_RE.fullmatch(value):
            raise ValueError("platform must look like windows/amd64")
        return value

    @field_validator("artifact_url")
    @classmethod
    def artifact_url_must_be_https(cls, value: str) -> str:
        if not value.startswith("https://") or len(value) < len("https://a"):
            raise ValueError("artifact_url must be an https URL")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("artifact_url contains control characters")
        return value


class AgentUpdateRolloutAdvance(BaseModel):
    """Raise the staged rollout to a percentage and dispatch to what it admits.

    The percentage may only increase: buckets are stable, so lowering it could
    not recall an endpoint that already updated and would only make the recorded
    stage disagree with what actually happened.
    """

    rollout_percent: int = Field(ge=1, le=100)
    # Bounds how many endpoints one call may target, so a jump to 100% on a large
    # fleet is paged rather than issued as one unbounded burst.
    max_dispatch: int = Field(default=200, ge=1, le=1_000)


class AgentUpdateHalt(BaseModel):
    reason: ReasonStr


class AgentUpdateAttemptOut(BaseModel):
    id: str
    agent_id: str
    command_id: str | None
    status: str
    from_version: str | None
    to_version: str | None
    observed_version: str | None
    reason: str | None
    health_attempts: int | None
    rollout_bucket: int
    dispatched_at: datetime
    reported_at: datetime | None

    model_config = {"from_attributes": True}


class AgentUpdateReleaseStatsOut(BaseModel):
    """Resolved-attempt counters that the halt rule reads."""

    dispatched: int = 0
    staged: int = 0
    succeeded: int = 0
    rolled_back: int = 0
    failed: int = 0
    resolved: int = 0
    failure_percent: int = 0


class AgentUpdateReleaseOut(BaseModel):
    id: str
    version: str
    channel: str
    platform: str
    artifact_sha256: str
    artifact_size_bytes: int
    signer_thumbprint: str | None
    min_supported_version: str
    state: str
    rollout_percent: int
    failure_threshold_percent: int
    min_attempts_before_halt: int
    health_timeout_seconds: int
    signing_key_id: str
    manifest_sha256: str
    created_by_email: str | None
    created_at: datetime
    updated_at: datetime
    halted_at: datetime | None
    halted_reason: str | None
    stats: AgentUpdateReleaseStatsOut


class AgentUpdateReleaseDetailOut(AgentUpdateReleaseOut):
    """Adds the publication record itself so it can be re-verified offline."""

    artifact_url: str
    manifest: dict[str, Any]
    signature: str
    # Re-verified on read against the keyring, so a key that can no longer
    # confirm the stored manifest is visible rather than assumed good.
    signature_valid: bool


class AgentUpdateReleaseListOut(BaseModel):
    releases: list[AgentUpdateReleaseOut]


class AgentUpdateAttemptListOut(BaseModel):
    attempts: list[AgentUpdateAttemptOut]


class AgentUpdateDispatchOut(BaseModel):
    """What one rollout advance actually did, and why endpoints were skipped."""

    release_id: str
    state: str
    rollout_percent: int
    dispatched: int
    # Coded reason -> count, e.g. {"outside_rollout_stage": 42,
    # "capability_unsupported": 3}. Never a hostname or any endpoint identifier.
    skipped: dict[str, int]
    truncated: bool


class SelfUpdateReportIn(BaseModel):
    """The endpoint's post-restart resolution of a staged update.

    Reported separately from the command result because the deciding evidence —
    whether the new build came up healthy — only exists after the restart, by
    which time the command that staged it has already completed.
    """

    release_id: Annotated[str, StringConstraints(max_length=64)] | None = None
    command_id: Annotated[str, StringConstraints(max_length=64)] | None = None
    from_version: Annotated[str, StringConstraints(max_length=64)] | None = None
    to_version: Annotated[str, StringConstraints(max_length=64)] | None = None
    observed_version: Annotated[str, StringConstraints(max_length=64)] | None = None
    status: Literal["succeeded", "rolled_back", "failed"]
    # Coded, non-secret outcome reason produced by the agent, e.g.
    # health_check_failed. Free prose is not accepted.
    reason: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_+]{1,100}$")] | None = (
        None
    )
    attempts: int = Field(default=0, ge=0, le=100)


class SelfUpdateReportAck(BaseModel):
    ok: bool
    recorded: bool
    release_state: str | None = None


__all__ = [
    "CHANNELS",
    "AgentUpdateAttemptListOut",
    "AgentUpdateAttemptOut",
    "AgentUpdateDispatchOut",
    "AgentUpdateHalt",
    "AgentUpdateReleaseCreate",
    "AgentUpdateReleaseDetailOut",
    "AgentUpdateReleaseListOut",
    "AgentUpdateReleaseOut",
    "AgentUpdateReleaseStatsOut",
    "AgentUpdateRolloutAdvance",
    "SelfUpdateReportAck",
    "SelfUpdateReportIn",
]
