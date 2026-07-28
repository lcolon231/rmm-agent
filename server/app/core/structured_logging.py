# SPDX-License-Identifier: AGPL-3.0-only
"""Structured logging helpers with defense-in-depth secret redaction."""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any


_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


def redact(value: Any, *, key: str = "") -> Any:
    """Return a JSON-safe copy with values under sensitive keys removed."""
    normalized_key = key.casefold().replace("-", "_")
    if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): redact(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def structured_event(event: str, **fields: Any) -> str:
    """Serialize a compact JSON event after recursively redacting fields."""
    payload = {"event": event, **fields}
    return json.dumps(redact(payload), separators=(",", ":"), sort_keys=True)


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    logger.info(structured_event(event, **fields))
