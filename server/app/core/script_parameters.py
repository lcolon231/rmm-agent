# SPDX-License-Identifier: AGPL-3.0-only
"""Typed script parameter validation, encryption, quoting, and redaction (#48)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings, settings
from app.models.models import ScriptParameterDefinition, ScriptParameterKind


class ScriptParameterError(ValueError):
    """A safe parameter failure with an API-visible state and code."""

    def __init__(self, code: str, *, state: str = "invalid"):
        super().__init__(code)
        self.code = code
        self.state = state


@dataclass(frozen=True)
class PreparedValues:
    values: dict[str, str | float | int | bool]
    provided_keys: tuple[str, ...]
    defaulted_keys: tuple[str, ...]
    secret_keys: tuple[str, ...]


def _decode_key(config: Settings = settings) -> bytes:
    value = config.script_parameter_encryption_key or ""
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ScriptParameterError(
            "parameter_encryption_unavailable", state="unavailable"
        ) from exc
    if len(key) != 32:
        raise ScriptParameterError(
            "parameter_encryption_unavailable", state="unavailable"
        )
    return key


def encryption_key_configured(config: Settings = settings) -> bool:
    try:
        _decode_key(config)
    except ScriptParameterError:
        return False
    return True


def _validate_value(
    definition: ScriptParameterDefinition, value: Any
) -> str | float | int | bool:
    kind = definition.kind
    if kind in (ScriptParameterKind.string, ScriptParameterKind.secret):
        if not isinstance(value, str):
            raise ScriptParameterError(f"parameter_{definition.key}_type_invalid")
        if definition.min_length is not None and len(value) < definition.min_length:
            raise ScriptParameterError(f"parameter_{definition.key}_too_short")
        if definition.max_length is not None and len(value) > definition.max_length:
            raise ScriptParameterError(f"parameter_{definition.key}_too_long")
        return value
    if kind is ScriptParameterKind.number:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ScriptParameterError(f"parameter_{definition.key}_type_invalid")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ScriptParameterError(f"parameter_{definition.key}_type_invalid")
        if definition.minimum is not None and numeric < definition.minimum:
            raise ScriptParameterError(f"parameter_{definition.key}_below_minimum")
        if definition.maximum is not None and numeric > definition.maximum:
            raise ScriptParameterError(f"parameter_{definition.key}_above_maximum")
        return value
    if kind is ScriptParameterKind.boolean:
        if not isinstance(value, bool):
            raise ScriptParameterError(f"parameter_{definition.key}_type_invalid")
        return value
    if kind is ScriptParameterKind.choice:
        if not isinstance(value, str):
            raise ScriptParameterError(f"parameter_{definition.key}_type_invalid")
        if value not in (definition.choices or []):
            raise ScriptParameterError(f"parameter_{definition.key}_choice_invalid")
        return value
    raise ScriptParameterError("parameter_kind_unsupported", state="unsupported")


def prepare_values(
    definitions: Iterable[ScriptParameterDefinition], provided: dict[str, Any]
) -> PreparedValues:
    ordered = list(definitions)
    by_key = {definition.key: definition for definition in ordered}
    if len(provided) > 32:
        raise ScriptParameterError("parameter_value_limit_exceeded")
    unknown = sorted(set(provided) - set(by_key))
    if unknown:
        raise ScriptParameterError("parameter_key_unknown")

    values: dict[str, str | float | int | bool] = {}
    provided_keys: list[str] = []
    defaulted_keys: list[str] = []
    secret_keys: list[str] = []
    for definition in ordered:
        if definition.key in provided:
            value = provided[definition.key]
            provided_keys.append(definition.key)
        elif definition.has_default:
            value = definition.default_value
            defaulted_keys.append(definition.key)
        elif definition.required:
            raise ScriptParameterError(f"parameter_{definition.key}_required")
        else:
            continue
        values[definition.key] = _validate_value(definition, value)
        if definition.kind is ScriptParameterKind.secret:
            secret_keys.append(definition.key)

    encoded = canonical_values(values)
    if len(encoded) > settings.script_parameter_max_values_bytes:
        raise ScriptParameterError("parameter_values_too_large")
    return PreparedValues(
        values=values,
        provided_keys=tuple(provided_keys),
        defaulted_keys=tuple(defaulted_keys),
        secret_keys=tuple(secret_keys),
    )


def canonical_values(values: dict[str, Any]) -> bytes:
    return json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _aad(script_version_id: str, value_set_id: str) -> bytes:
    return f"nodelink-script-parameters:v1:{script_version_id}:{value_set_id}".encode(
        "ascii"
    )


def encrypt_values(
    values: dict[str, Any], *, script_version_id: str, value_set_id: str,
    config: Settings = settings,
) -> tuple[str, str]:
    key = _decode_key(config)
    plaintext = canonical_values(values)
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(
        nonce, plaintext, _aad(script_version_id, value_set_id)
    )
    fingerprint = hmac.new(key, plaintext, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii"), fingerprint


def decrypt_values(
    encrypted: str, *, script_version_id: str, value_set_id: str,
    config: Settings = settings,
) -> dict[str, Any]:
    key = _decode_key(config)
    try:
        raw = base64.b64decode(encrypted, altchars=b"-_", validate=True)
        if len(raw) < 29:
            raise ValueError("ciphertext too short")
        plaintext = AESGCM(key).decrypt(
            raw[:12], raw[12:], _aad(script_version_id, value_set_id)
        )
        value = json.loads(plaintext)
        if not isinstance(value, dict):
            raise ValueError("invalid plaintext shape")
        return value
    except ScriptParameterError:
        raise
    except Exception as exc:
        raise ScriptParameterError(
            "parameter_decryption_unavailable", state="unavailable"
        ) from exc


def _powershell_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, (int, float)):
        return json.dumps(value, allow_nan=False)
    return "'" + str(value).replace("'", "''") + "'"


def _shell_literal(value: Any) -> str:
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (int, float)):
        value = json.dumps(value, allow_nan=False)
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def render_script(language: str, script: str, values: dict[str, Any]) -> str:
    """Bind values to generated variables; script text is never token-substituted."""
    lines: list[str] = []
    if language == "powershell":
        lines = [
            f"$NL_PARAM_{key} = {_powershell_literal(value)}"
            for key, value in values.items()
        ]
    elif language == "shell":
        for key, value in values.items():
            variable = f"NL_PARAM_{key}"
            lines.extend((f"{variable}={_shell_literal(value)}", f"export {variable}"))
    else:
        raise ScriptParameterError("parameter_language_unsupported", state="unsupported")
    if not lines:
        return script
    return "\n".join((*lines, script))


def redact_secret_values(text: str, values: dict[str, Any], secret_keys: Iterable[str]) -> str:
    result = text
    secrets_to_redact = sorted(
        {str(values[key]) for key in secret_keys if key in values and str(values[key])},
        key=len,
        reverse=True,
    )
    for secret_value in secrets_to_redact:
        result = result.replace(secret_value, "[redacted]")
    return result
