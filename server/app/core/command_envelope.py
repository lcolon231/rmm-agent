# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned command-envelope contract shared by signing and API code."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


COMMAND_ENVELOPE_V1 = "command-v1"
COMMAND_ENVELOPE_V2 = "command-v2"
COMMAND_ENVELOPE_V3 = "command-v3"
ACTIVE_COMMAND_ENVELOPE_VERSION = COMMAND_ENVELOPE_V3
SUPPORTED_COMMAND_ENVELOPE_VERSIONS = (COMMAND_ENVELOPE_V3, COMMAND_ENVELOPE_V2)
COMMAND_SCHEMA_VERSION = 1
SUPPORTED_COMMAND_KINDS = frozenset(
    {"powershell", "shell", "collect_inventory"}
)

MAX_COMMAND_ENVELOPE_BYTES = 64 * 1024
MAX_COMMAND_PAYLOAD_BYTES = 60 * 1024
MAX_COMMAND_PAYLOAD_DEPTH = 16
MAX_COMMAND_LIFETIME_SECONDS = 86_400
MIN_SIGNED_INTEGER = -(2**63)
MAX_SIGNED_INTEGER = 2**63 - 1

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
_COMMAND_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$"
)


class CommandEnvelopeError(ValueError):
    """A stable, fail-closed command-envelope validation failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def select_command_envelope_version(agent_versions: list[str]) -> str | None:
    """Choose the server-preferred mutually supported envelope version."""
    for version in SUPPORTED_COMMAND_ENVELOPE_VERSIONS:
        if version in agent_versions:
            return version
    return None


def format_command_time(value: datetime) -> str:
    """Return the one UTC representation accepted inside signed envelopes."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_command_time(field: str, raw: str) -> datetime:
    if not raw:
        raise CommandEnvelopeError(f"missing_{field}", f"{field} is required")
    if not isinstance(raw, str) or not _COMMAND_TIME_RE.fullmatch(raw):
        raise CommandEnvelopeError(
            "malformed_time", f"{field} must be canonical UTC RFC3339"
        )
    try:
        parsed = datetime.fromisoformat(raw.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CommandEnvelopeError(
            "malformed_time", f"{field} must be a valid UTC timestamp"
        ) from exc
    if format_command_time(parsed) != raw:
        raise CommandEnvelopeError(
            "malformed_time", f"{field} is not canonically encoded"
        )
    return parsed


def validate_command_window(issued_at: str, expires_at: str) -> tuple[datetime, datetime]:
    issued = parse_command_time("issued_at", issued_at)
    expires = parse_command_time("expires_at", expires_at)
    if expires <= issued:
        raise CommandEnvelopeError(
            "invalid_time_window", "expires_at must be later than issued_at"
        )
    if (expires - issued).total_seconds() > MAX_COMMAND_LIFETIME_SECONDS:
        raise CommandEnvelopeError(
            "invalid_time_window",
            f"command lifetime exceeds {MAX_COMMAND_LIFETIME_SECONDS} seconds",
        )
    return issued, expires


def _validate_payload_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_COMMAND_PAYLOAD_DEPTH:
        raise CommandEnvelopeError(
            "payload_too_deep",
            f"payload nesting exceeds {MAX_COMMAND_PAYLOAD_DEPTH} levels",
        )
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not MIN_SIGNED_INTEGER <= value <= MAX_SIGNED_INTEGER:
            raise CommandEnvelopeError(
                "integer_out_of_range", "payload integers must fit signed 64-bit"
            )
        return
    if isinstance(value, float):
        raise CommandEnvelopeError(
            "floating_point_not_supported",
            "floating-point payload values are not supported by command-v2",
        )
    if isinstance(value, list):
        for item in value:
            _validate_payload_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CommandEnvelopeError(
                    "invalid_payload_key", "payload object keys must be strings"
                )
            _validate_payload_value(item, depth + 1)
        return
    raise CommandEnvelopeError(
        "unsupported_payload_type", f"unsupported payload value: {type(value).__name__}"
    )


def validate_command_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the active command payload value domain and return it unchanged."""
    if not isinstance(payload, dict):
        raise CommandEnvelopeError("malformed_envelope", "payload must be a JSON object")
    _validate_payload_value(payload)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_COMMAND_PAYLOAD_BYTES:
        raise CommandEnvelopeError(
            "payload_too_large",
            f"canonical payload exceeds {MAX_COMMAND_PAYLOAD_BYTES} bytes",
        )
    return payload


def canonical_command_bytes(
    envelope_version: str,
    schema_version: int | None,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    issued_at: str,
    expires_at: str,
    nonce: str,
    signing_key_id: str | None = None,
) -> bytes:
    """Validate and encode a signed command-v2/v3 JSON representation.

    command-v2 uses UTF-8 JSON with recursively sorted object keys, no
    insignificant whitespace, no ASCII-only escaping, signed 64-bit integers,
    and no floating-point values. The bounded value domain keeps Python and Go
    canonicalization identical without relying on language-specific float
    formatting.
    """
    if envelope_version not in SUPPORTED_COMMAND_ENVELOPE_VERSIONS:
        code = "missing_version" if not envelope_version else "unsupported_version"
        raise CommandEnvelopeError(
            code, f"unsupported command envelope version: {envelope_version!r}"
        )
    if schema_version is None:
        raise CommandEnvelopeError("missing_schema_version", "schema_version is required")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise CommandEnvelopeError(
            "unsupported_schema_version",
            f"unsupported command schema version: {schema_version!r}",
        )
    if schema_version != COMMAND_SCHEMA_VERSION:
        raise CommandEnvelopeError(
            "unsupported_schema_version",
            f"unsupported command schema version: {schema_version!r}",
        )
    if not command_id or not agent_id or not kind:
        raise CommandEnvelopeError(
            "malformed_envelope", "command_id, agent_id, and kind are required"
        )
    if kind not in SUPPORTED_COMMAND_KINDS:
        raise CommandEnvelopeError(
            "unsupported_kind", f"unsupported command kind: {kind!r}"
        )
    if not nonce:
        raise CommandEnvelopeError("missing_nonce", "nonce is required")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise CommandEnvelopeError(
            "malformed_nonce", "nonce must be 22-64 URL-safe base64 characters"
        )
    validate_command_window(issued_at, expires_at)
    if envelope_version == COMMAND_ENVELOPE_V3:
        if not signing_key_id:
            raise CommandEnvelopeError(
                "missing_signing_key_id", "signing_key_id is required"
            )
        if not isinstance(signing_key_id, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", signing_key_id
        ):
            raise CommandEnvelopeError(
                "malformed_signing_key_id", "signing_key_id is invalid"
            )
    elif signing_key_id is not None:
        raise CommandEnvelopeError(
            "unexpected_signing_key_id", "command-v2 does not accept signing_key_id"
        )
    validate_command_payload(payload)

    doc = {
        "agent_id": agent_id,
        "command_id": command_id,
        "envelope_version": envelope_version,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "kind": kind,
        "nonce": nonce,
        "payload": payload,
        "schema_version": schema_version,
    }
    if envelope_version == COMMAND_ENVELOPE_V3:
        doc["signing_key_id"] = signing_key_id
    encoded_text = json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    # Go's encoding/json escapes these two line-separator code points even when
    # HTML escaping is disabled. Normalize them explicitly so signatures remain
    # byte-identical across the Python and Go implementations.
    encoded = encoded_text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")
    if len(encoded) > MAX_COMMAND_ENVELOPE_BYTES:
        raise CommandEnvelopeError(
            "envelope_too_large",
            f"canonical envelope exceeds {MAX_COMMAND_ENVELOPE_BYTES} bytes",
        )
    return encoded
