# SPDX-License-Identifier: AGPL-3.0-only
"""Signed, staged agent self-update policy (issue #63).

Three responsibilities live here, deliberately free of FastAPI and session
plumbing so they can be tested directly:

* **Publication.** A release is described by an immutable manifest — version,
  channel, platform, artifact URL/digest/size, and the anti-rollback floor —
  canonicalized and signed with the server's Ed25519 signing key. The signature
  is the durable, re-verifiable record of what was published. On the wire the
  same metadata additionally rides inside the ordinary signed command envelope,
  so an endpoint never acts on unsigned update metadata either way.

* **Targeting.** Which endpoints a release may reach: capability, trust, channel,
  platform, anti-rollback, and the staged rollout bucket. Every rule fails
  closed — an endpoint the server cannot positively confirm is eligible is not
  targeted.

* **Halt.** The canary rule that stops a bad release automatically once enough
  endpoints have resolved their attempt and too many of them failed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.keyring import active_signing_key


# --------------------------------------------------------------------------- #
# Version ordering
# --------------------------------------------------------------------------- #
# The one accepted release-version shape, mirroring the agent's parser exactly
# (agent/internal/selfupdate/version.go). Build metadata is deliberately not
# accepted: two artifacts differing only in build metadata would compare equal,
# which is not a safe basis for an anti-rollback decision.
_VERSION_RE = re.compile(
    r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]{1,64}))?$"
)

MANIFEST_VERSION = 1
#: Domain separator so an update manifest signature can never be replayed as a
#: command signature (or vice versa) even if both use the same key.
MANIFEST_SIGNING_CONTEXT = b"nodelink-agent-update-manifest:v1:"

#: Capability an agent must advertise before any self-update kind is dispatched.
SELF_UPDATE_CAPABILITY = "agent-self-update-v1"

#: Platform selector shape, e.g. "windows/amd64".
PLATFORM_RE = re.compile(r"^[a-z0-9]{1,16}/[a-z0-9]{1,16}$")

#: Channels a release may be published on and an endpoint may follow.
CHANNELS = ("stable", "beta", "canary")
DEFAULT_CHANNEL = "stable"

#: Endpoint outcome statuses that count as a resolved failure for the halt rule.
FAILURE_STATUSES = frozenset({"rolled_back", "failed"})
#: Endpoint outcome statuses that count as a resolved success.
SUCCESS_STATUSES = frozenset({"succeeded"})


class AgentUpdateError(ValueError):
    """A stable, fail-closed self-update policy failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def parse_version(raw: str) -> tuple[int, int, int, str]:
    """Return the comparable parts of a release version, failing closed."""
    match = _VERSION_RE.fullmatch(raw or "")
    if not match:
        raise AgentUpdateError(
            "version_uncomparable",
            "version must be MAJOR.MINOR.PATCH with an optional -prerelease",
        )
    return int(match[1]), int(match[2]), int(match[3]), match[4] or ""


def _prerelease_key(prerelease: str) -> list[tuple[int, int | str]]:
    """Order dot-separated prerelease identifiers by semver precedence.

    Numeric identifiers sort below alphanumeric ones, so the leading tuple
    element carries that class and keeps int/str comparisons apart.
    """
    parts: list[tuple[int, int | str]] = []
    for item in prerelease.split("."):
        if item.isdigit():
            parts.append((0, int(item)))
        else:
            parts.append((1, item))
    return parts


def version_sort_key(raw: str) -> tuple:
    """Total order over versions: a prerelease precedes its release."""
    major, minor, patch, prerelease = parse_version(raw)
    # 0 marks "has a prerelease" so 1.0.0-rc.1 < 1.0.0.
    return (major, minor, patch, 0 if prerelease else 1, _prerelease_key(prerelease))


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0, or 1 for left < right, left == right, left > right."""
    a, b = version_sort_key(left), version_sort_key(right)
    return (a > b) - (a < b)


# --------------------------------------------------------------------------- #
# Signed manifest
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SignedManifest:
    manifest: dict[str, Any]
    manifest_sha256: str
    signature: str
    signing_key_id: str


def build_manifest(
    *,
    release_id: str,
    version: str,
    channel: str,
    platform: str,
    artifact_url: str,
    artifact_sha256: str,
    artifact_size_bytes: int,
    min_supported_version: str,
    signer_thumbprint: str | None,
    health_timeout_seconds: int,
    published_at: datetime,
) -> dict[str, Any]:
    """Assemble the exact document that gets signed and stored.

    Everything an endpoint uses to decide whether to install, and to prove what
    it installed, is inside. Rollout controls (percentage, thresholds) are
    deliberately outside: they change over a release's life, and a signature
    that changed with them would not be an immutable publication record.
    """
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "release_id": release_id,
        "version": version,
        "channel": channel,
        "platform": platform,
        "artifact": {
            "url": artifact_url,
            "sha256": artifact_sha256,
            "size_bytes": artifact_size_bytes,
        },
        "min_supported_version": min_supported_version,
        "health_timeout_seconds": health_timeout_seconds,
        "published_at": _format_time(published_at),
    }
    if signer_thumbprint:
        manifest["signer_thumbprint"] = signer_thumbprint
    return manifest


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Deterministic encoding: sorted keys, no whitespace, domain-separated."""
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return MANIFEST_SIGNING_CONTEXT + encoded


def sign_manifest(manifest: dict[str, Any]) -> SignedManifest:
    """Sign a manifest with the active Ed25519 signing key."""
    key_record = active_signing_key()
    payload = canonical_manifest_bytes(manifest)
    signature = key_record.private_key.sign(payload)
    return SignedManifest(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        signature=base64.b64encode(signature).decode("ascii"),
        signing_key_id=key_record.key_id,
    )


def verify_manifest(
    manifest: dict[str, Any], signature_b64: str, signing_key_id: str
) -> bool:
    """Re-verify a stored manifest against the keyring.

    Used by the release read API so an operator can confirm at any time that the
    stored publication record still verifies under the key that produced it.
    """
    from cryptography.exceptions import InvalidSignature

    from app.core.keyring import load_keyring

    _, keys = load_keyring()
    key = keys.get(signing_key_id)
    if key is None:
        return False
    try:
        public_key = key.private_key.public_key()
    except ValueError:
        # Overlap keys may hold only public material; load it from the PEM.
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(
            key.public_key_pem.encode("ascii")
        )
    try:
        public_key.verify(
            base64.b64decode(signature_b64), canonical_manifest_bytes(manifest)
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def command_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """Project a manifest onto the signed agent_self_update command payload.

    The payload is a strict subset of the manifest, so what the endpoint acts on
    is exactly what was published — and the command envelope's own Ed25519
    signature is what authenticates it on the wire.
    """
    payload: dict[str, Any] = {
        "release_id": manifest["release_id"],
        "version": manifest["version"],
        "channel": manifest["channel"],
        "platform": manifest["platform"],
        "artifact": dict(manifest["artifact"]),
        "min_supported_version": manifest["min_supported_version"],
        "health_check": {"timeout_seconds": manifest["health_timeout_seconds"]},
    }
    if manifest.get("signer_thumbprint"):
        payload["signer_thumbprint"] = manifest["signer_thumbprint"]
    return payload


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Staged rollout targeting
# --------------------------------------------------------------------------- #
def rollout_bucket(release_id: str, agent_id: str) -> int:
    """Return the stable 0-99 bucket an endpoint occupies for a release.

    Derived from the pair, so raising the rollout percentage only ever *adds*
    endpoints: the ones already updated keep the bucket that admitted them, and
    no endpoint can be shuffled out of a completed update.
    """
    digest = hashlib.sha256(f"{release_id}:{agent_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 100


def agent_platform(agent) -> str | None:
    """Return the artifact selector for an endpoint, or None if unknown.

    Unknown platform means not targetable: the server will not guess which
    binary an endpoint can run.
    """
    os_name = (agent.os or "").strip().lower()
    architecture = (agent.architecture or "").strip().lower()
    if not os_name or not architecture:
        return None
    candidate = f"{os_name}/{architecture}"
    return candidate if PLATFORM_RE.fullmatch(candidate) else None


def agent_channel(agent) -> str:
    """Return the channel an endpoint follows; unset means stable."""
    channel = (agent.update_channel or "").strip().lower()
    return channel if channel in CHANNELS else DEFAULT_CHANNEL


@dataclass(frozen=True)
class EligibilityDecision:
    eligible: bool
    reason: str


def evaluate_eligibility(
    agent,
    *,
    release_version: str,
    release_channel: str,
    release_platform: str,
    min_supported_version: str,
    rollout_percent: int,
    release_id: str,
    trust_active: bool,
) -> EligibilityDecision:
    """Decide whether one endpoint may be targeted by one release.

    Ordered from cheapest and most disqualifying to most specific, so the reason
    an endpoint was skipped is the most useful one an operator can act on.
    """
    if not trust_active:
        return EligibilityDecision(False, "agent_not_trusted")
    if SELF_UPDATE_CAPABILITY not in (agent.supported_capabilities or []):
        return EligibilityDecision(False, "capability_unsupported")
    platform = agent_platform(agent)
    if platform is None:
        return EligibilityDecision(False, "platform_unknown")
    if platform != release_platform:
        return EligibilityDecision(False, "platform_mismatch")
    if agent_channel(agent) != release_channel:
        return EligibilityDecision(False, "channel_mismatch")

    current = (agent.agent_version or "").strip()
    if not current:
        # An endpoint that has never reported a build cannot be checked against
        # the anti-rollback rule, so it is not targeted.
        return EligibilityDecision(False, "agent_version_unknown")
    try:
        if compare_versions(current, release_version) == 0:
            return EligibilityDecision(False, "already_current")
        if compare_versions(current, release_version) > 0:
            return EligibilityDecision(False, "downgrade_refused")
        if compare_versions(release_version, min_supported_version) < 0:
            return EligibilityDecision(False, "below_min_supported_version")
    except AgentUpdateError:
        return EligibilityDecision(False, "agent_version_uncomparable")

    if rollout_bucket(release_id, agent.id) >= rollout_percent:
        return EligibilityDecision(False, "outside_rollout_stage")
    return EligibilityDecision(True, "eligible")


# --------------------------------------------------------------------------- #
# Canary halt
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HaltDecision:
    halt: bool
    reason: str
    resolved: int
    failed: int
    succeeded: int


def evaluate_halt(
    *,
    status_counts: dict[str, int],
    failure_threshold_percent: int,
    min_attempts_before_halt: int,
) -> HaltDecision:
    """Decide whether a release's failure rate requires halting the rollout.

    Only *resolved* attempts count. A dispatched-but-unreported attempt is not
    evidence of anything yet, and counting it either way would let a slow fleet
    either mask a bad release or halt a good one.
    """
    succeeded = sum(status_counts.get(name, 0) for name in SUCCESS_STATUSES)
    failed = sum(status_counts.get(name, 0) for name in FAILURE_STATUSES)
    resolved = succeeded + failed
    if resolved < min_attempts_before_halt:
        return HaltDecision(False, "insufficient_evidence", resolved, failed, succeeded)
    if failed * 100 >= failure_threshold_percent * resolved:
        return HaltDecision(
            True, "failure_threshold_exceeded", resolved, failed, succeeded
        )
    return HaltDecision(False, "within_threshold", resolved, failed, succeeded)
