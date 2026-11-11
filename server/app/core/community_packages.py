# SPDX-License-Identifier: AGPL-3.0-only
"""Signed community package verification and trust evaluation (issue #74).

A publisher signs a canonical JSON manifest offline with an Ed25519 key that an
admin registered for that publisher's namespace. The manifest binds the exact
script bytes (SHA-256 + length), the interpreter, the supported platforms and a
declared capability set. Everything here fails closed: a value that cannot be
proven valid is refused, never coerced.

Capabilities are declarative. The agent does not sandbox script internals; the
enforced boundaries are moderation of the declared set, escalation gating on
updates, and dispatch refusal when a run falls outside the declared set.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.relays import load_public_key, public_key_fingerprint
from app.models.models import (
    CommandKind,
    CommunityPackageModeration,
    CommunityPackageVersion,
    CommunityPublisher,
    CommunityPublisherKey,
    ScriptVersion,
)
from app.schemas.script_library import ScriptVersionInput, canonical_script_content


MANIFEST_SCHEMA = "nodelink.community-package/v1"
SIGNING_CONTEXT = b"nodelink-community-package:v1\n"
MANIFEST_KEYS = frozenset(
    {
        "schema", "publisher", "name", "version", "language", "content_sha256",
        "content_bytes", "description", "tags", "supported_platforms",
        "capabilities", "parameters",
    }
)
RUN_CAPABILITIES = {"powershell": "script.run.powershell", "shell": "script.run.shell"}
PLATFORM_CAPABILITIES = {
    "windows": "platform.windows",
    "linux": "platform.linux",
    "macos": "platform.macos",
}
EFFECT_CAPABILITIES = frozenset(
    {
        "requires.elevation",
        "network.egress",
        "filesystem.write",
        "registry.write",
        "service.control",
    }
)
CAPABILITIES = frozenset(
    set(RUN_CAPABILITIES.values())
    | set(PLATFORM_CAPABILITIES.values())
    | EFFECT_CAPABILITIES
)
SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
SEMVER = re.compile(r"^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$")


class CommunityRefusal(Exception):
    """A fail-closed refusal carrying a stable, documented error code."""

    def __init__(self, code: str, status_code: int = 409) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedManifest:
    manifest: dict[str, Any]
    manifest_sha256: str
    version: tuple[int, int, int]
    content: str
    content_sha256: str
    content_bytes: int
    script: ScriptVersionInput


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Domain-separated, sorted-key, whitespace-free UTF-8 JSON."""
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return SIGNING_CONTEXT + encoded


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def key_fingerprint(public_key_pem: str) -> str:
    """SHA-256 of the raw Ed25519 key; raises ValueError for anything else."""
    try:
        return public_key_fingerprint(public_key_pem)
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise ValueError("publisher keys must be PEM Ed25519 public keys") from exc


def verify_signature(
    public_key_pem: str, signature_b64: str, manifest: dict[str, Any]
) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            return False
        load_public_key(public_key_pem).verify(
            signature, canonical_manifest_bytes(manifest)
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False
    return True


def parse_semver(value: Any) -> tuple[int, int, int]:
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        raise CommunityRefusal("manifest_invalid", 422)
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def capability_escalation(previous: list[str] | None, current: list[str]) -> list[str]:
    """Capabilities the new version declares that the prior approved one did not."""
    return sorted(set(current) - set(previous or []))


def validate_manifest(manifest: Any, content: str) -> VerifiedManifest:
    """Validate shape, capabilities, and the content binding of a manifest."""
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise CommunityRefusal("manifest_invalid", 422)
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise CommunityRefusal("manifest_invalid", 422)
    for field in ("publisher", "name"):
        if not isinstance(manifest[field], str) or not SLUG.fullmatch(manifest[field]):
            raise CommunityRefusal("manifest_invalid", 422)
    version = parse_semver(manifest["version"])
    try:
        # The library's own validators are the single source of truth for
        # language, content, tags, platforms, and parameter definitions.
        script = ScriptVersionInput.model_validate(
            {
                "language": manifest["language"],
                "content": content,
                "description": manifest["description"],
                "tags": manifest["tags"],
                "supported_platforms": manifest["supported_platforms"],
                "parameters": manifest["parameters"],
            }
        )
        canonical = canonical_script_content(content)
    except (ValidationError, ValueError, TypeError) as exc:
        raise CommunityRefusal("manifest_invalid", 422) from exc
    if canonical != content:
        # The signed digest must describe the stored bytes exactly; accepting
        # non-canonical input would make the digest refer to different bytes.
        raise CommunityRefusal("content_not_canonical", 422)
    if (
        manifest["supported_platforms"] != script.supported_platforms
        or manifest["tags"] != script.tags
    ):
        raise CommunityRefusal("manifest_invalid", 422)
    encoded = content.encode("utf-8")
    content_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        manifest["content_sha256"] != content_sha256
        or manifest["content_bytes"] != len(encoded)
    ):
        raise CommunityRefusal("content_digest_mismatch", 422)
    _validate_capabilities(manifest, script)
    return VerifiedManifest(
        manifest=manifest,
        manifest_sha256=manifest_digest(manifest),
        version=version,
        content=content,
        content_sha256=content_sha256,
        content_bytes=len(encoded),
        script=script,
    )


def _validate_capabilities(manifest: dict[str, Any], script: ScriptVersionInput) -> None:
    capabilities = manifest["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not all(isinstance(item, str) for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise CommunityRefusal("manifest_invalid", 422)
    if not set(capabilities) <= CAPABILITIES:
        raise CommunityRefusal("capability_unknown", 422)
    run = {item for item in capabilities if item.startswith("script.run.")}
    if run != {RUN_CAPABILITIES[script.language.value]}:
        raise CommunityRefusal("capability_language_mismatch", 422)
    platforms = {item for item in capabilities if item.startswith("platform.")}
    if platforms != {PLATFORM_CAPABILITIES[item] for item in script.supported_platforms}:
        raise CommunityRefusal("capability_platform_mismatch", 422)


def agent_platform(agent_os: str | None) -> str | None:
    value = (agent_os or "").strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value.startswith(("darwin", "macos", "mac os")):
        return "macos"
    return None


async def version_state(db: AsyncSession, version: CommunityPackageVersion) -> str:
    """Derived trust state: blocked > revoked > moderation outcome > submitted."""
    key = await db.get(CommunityPublisherKey, version.signing_key_id)
    publisher = await db.get(CommunityPublisher, key.publisher_id) if key else None
    if key is None or publisher is None:
        return "blocked"
    if key.status != "active" or publisher.status != "active":
        return "blocked"
    if version.revoked_at is not None:
        return "revoked"
    moderation = await db.scalar(
        select(CommunityPackageModeration).where(
            CommunityPackageModeration.package_version_id == version.id
        )
    )
    if moderation is None:
        return "submitted"
    return moderation.state


async def require_runnable(db: AsyncSession, version: CommunityPackageVersion) -> None:
    """Re-verify a stored version end to end before install or dispatch."""
    state = await version_state(db, version)
    if state != "approved":
        raise CommunityRefusal("community_package_blocked")
    key = await db.get(CommunityPublisherKey, version.signing_key_id)
    if (
        key is None
        or not verify_signature(key.public_key_pem, version.signature, version.manifest)
        or hashlib.sha256(version.content.encode("utf-8")).hexdigest()
        != version.content_sha256
        or version.manifest.get("content_sha256") != version.content_sha256
    ):
        raise CommunityRefusal("signature_invalid")


async def check_dispatch(
    db: AsyncSession,
    script_version: ScriptVersion,
    *,
    kind: CommandKind | str,
    agent_os: str | None,
    payload: dict[str, Any] | None,
) -> None:
    """Refuse a run citing a community-installed version outside its trust/scope.

    No-op for ordinary library versions. Shared by interactive dispatch and the
    scheduler so neither path can bypass the other's checks.
    """
    version = await check_run_definition(
        db, script_version, kind=kind, payload=payload
    )
    if version is None:
        return
    platform = agent_platform(agent_os)
    if platform is None or PLATFORM_CAPABILITIES[platform] not in version.capabilities:
        raise CommunityRefusal("community_capability_denied")


async def check_run_definition(
    db: AsyncSession,
    script_version: ScriptVersion,
    *,
    kind: CommandKind | str,
    payload: dict[str, Any] | None,
) -> CommunityPackageVersion | None:
    """Target-independent checks, also applied when a schedule is created."""
    if script_version.community_package_version_id is None:
        return None
    version = await db.get(
        CommunityPackageVersion, script_version.community_package_version_id
    )
    if version is None:
        raise CommunityRefusal("community_package_blocked")
    await require_runnable(db, version)
    kind_value = kind.value if hasattr(kind, "value") else str(kind)
    if RUN_CAPABILITIES.get(kind_value) not in version.capabilities:
        raise CommunityRefusal("community_capability_denied")
    script = (payload or {}).get("script")
    if not isinstance(script, str) or (
        hashlib.sha256(script.encode("utf-8")).hexdigest() != version.content_sha256
    ):
        # A run may only cite community provenance for the exact signed bytes.
        raise CommunityRefusal("community_content_mismatch")
    return version
