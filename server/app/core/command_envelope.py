"""Versioned command-envelope contract shared by signing and API code."""
from __future__ import annotations

import json
from typing import Any


COMMAND_ENVELOPE_V1 = "command-v1"
SUPPORTED_COMMAND_ENVELOPE_VERSIONS = (COMMAND_ENVELOPE_V1,)
SUPPORTED_COMMAND_KINDS = frozenset(
    {"powershell", "shell", "collect_inventory"}
)

MAX_COMMAND_ENVELOPE_BYTES = 64 * 1024
MAX_COMMAND_PAYLOAD_BYTES = 60 * 1024
MAX_COMMAND_PAYLOAD_DEPTH = 16
MIN_SIGNED_INTEGER = -(2**63)
MAX_SIGNED_INTEGER = 2**63 - 1


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
            "floating-point payload values are not supported by command-v1",
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
    """Validate the command-v1 payload value domain and return it unchanged."""
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
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
) -> bytes:
    """Validate and encode the signed command-v1 JSON representation.

    command-v1 uses UTF-8 JSON with recursively sorted object keys, no
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
    if not command_id or not agent_id or not kind:
        raise CommandEnvelopeError(
            "malformed_envelope", "command_id, agent_id, and kind are required"
        )
    if kind not in SUPPORTED_COMMAND_KINDS:
        raise CommandEnvelopeError(
            "unsupported_kind", f"unsupported command kind: {kind!r}"
        )
    validate_command_payload(payload)

    doc = {
        "agent_id": agent_id,
        "command_id": command_id,
        "envelope_version": envelope_version,
        "kind": kind,
        "payload": payload,
    }
    encoded = json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_COMMAND_ENVELOPE_BYTES:
        raise CommandEnvelopeError(
            "envelope_too_large",
            f"canonical envelope exceeds {MAX_COMMAND_ENVELOPE_BYTES} bytes",
        )
    return encoded
