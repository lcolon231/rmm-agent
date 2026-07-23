# SPDX-License-Identifier: AGPL-3.0-only
"""Central, deterministic redaction boundary for audit detail and diagnostics.

Two related problems, one module:

* **Audit events (issue #115).** `audit.record` runs every event's ``detail``
  through :func:`redact_detail` before the value is hashed and persisted, so no
  event producer — present or future — can commit a secret into the
  tamper-evident chain. Redaction is deterministic (same input -> same output),
  so chain and anchor verification stay reproducible over the *stored*
  (redacted) representation, which is the only representation that is ever
  hashed.

* **Logs / diagnostics / errors (issue #112).** :func:`scrub_text` removes
  credential-shaped substrings from free text before it reaches a log line or
  an API error body.

A design constraint is specific to this codebase: audit detail legitimately
carries high-entropy *public* values — Merkle roots and event hashes (64 hex
chars), replay nonces (URL-safe base64, the same shape as our bearer tokens),
and envelope digests. Redacting those by *shape* would both destroy
accountability and break anchor verification. So the audit path redacts by
**key name** (a value is secret because of where it sits — ``password``,
``agent_token``, ...) plus only the two value shapes that never legitimately
appear in audit detail: PEM private-key blocks and JWTs. Hex and
URL-safe-base64 blobs are deliberately preserved.

:func:`scrub_text` has no verification obligation, so it is allowed to
over-redact and casts a wider net (bearer headers, ``key=value`` secrets, PEM,
JWTs).
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[redacted]"
_TOO_DEEP = "[redacted:too-deep]"

# Recursion guard. Mirrors the 16-level envelope nesting limit's intent: bound
# the work and fail closed (redact) rather than recurse without limit.
_MAX_DEPTH = 64

# Substrings that make a mapping key sensitive (matched case-insensitively).
# Curated to avoid colliding with legitimate accountable keys that this
# codebase stores in audit detail: ``signing_key_id``, ``command_public_key``,
# ``payload_keys``, ``nonce``, ``merkle_root``, ``envelope_sha256`` etc. must
# survive, so bare "key", "sig", and "hash" are deliberately NOT here.
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "bearer",
    "credential",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "session_key",
    "cookie",
)

# A PEM private-key block. Ed25519 signing keys and backup key material are the
# real risk; this catches them regardless of the key they might be filed under.
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# A JWT: three base64url segments separated by dots. Operator access tokens are
# JWTs and never belong in audit detail. Nonces (no dots) and hashes (hex, no
# dots) do not match, so this is safe on the audit path.
_JWT = re.compile(r"\b[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")


def is_sensitive_key(key: Any) -> bool:
    """True if *key* names a credential-bearing field."""
    k = str(key).lower()
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


def _redact_scalar_str(value: str) -> str:
    """Redact a string value on the audit path: only shapes that never
    legitimately appear in audit detail (PEM private keys, JWTs)."""
    if _PEM_PRIVATE_KEY.search(value):
        return REDACTED
    if _JWT.fullmatch(value):
        return REDACTED
    return value


def _redact_value(value: Any, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        return _TOO_DEEP
    if isinstance(value, Mapping):
        return _redact_mapping(value, depth)
    # Strings are a Sequence too — handle before the generic Sequence branch.
    if isinstance(value, str):
        return _redact_scalar_str(value)
    if isinstance(value, (bytes, bytearray)):
        # Bytes are not JSON and could be raw key material; never persist them.
        return REDACTED
    if isinstance(value, Sequence):
        return [_redact_value(v, depth + 1) for v in value]
    # int / float / bool / None: no secret shape, pass through unchanged.
    return value


def _redact_mapping(m: Mapping, depth: int) -> dict:
    out: dict[str, Any] = {}
    for key, value in m.items():
        # str(key) keeps output JSON-stable even if a producer used a non-str
        # key; sort is not needed here because canonical hashing sorts keys.
        skey = str(key)
        if is_sensitive_key(skey):
            out[skey] = REDACTED
        else:
            out[skey] = _redact_value(value, depth + 1)
    return out


def redact_detail(detail: Any) -> dict:
    """Return a deterministically redacted copy of an audit-event ``detail``.

    Always returns a dict so the audit schema stays a mapping. A non-mapping
    (malformed) ``detail`` is wrapped under ``_value`` and redacted, rather than
    trusted or dropped silently.
    """
    if isinstance(detail, Mapping):
        return _redact_mapping(detail, 0)
    return {"_value": _redact_value(detail, 0)}


# --- Free-text scrubbing for logs / diagnostics / API errors (issue #112) ---

_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
# key=value / key: value / "key": "value" forms where the key *contains* a
# sensitive part (so ``enrollment_token`` and ``backup_passphrase`` match, not
# just bare ``token``). The full key is captured and kept; only the value is
# replaced.
_KV_SECRET = re.compile(
    r"(?i)([\w.-]*(?:"
    + "|".join(re.escape(p) for p in _SENSITIVE_KEY_PARTS)
    + r")[\w.-]*)[\"']?\s*[:=]\s*[\"']?[^\s\"',;}&]+"
)


def scrub_text(text: str) -> str:
    """Remove credential-shaped substrings from free text (log lines, error
    messages, diagnostics). Over-redaction is acceptable here: unlike the audit
    path there is no verification that depends on the exact text."""
    if not text:
        return text
    text = _PEM_PRIVATE_KEY.sub(REDACTED, text)
    text = _BEARER.sub("Bearer " + REDACTED, text)
    text = _JWT.sub(REDACTED, text)

    # The sensitive key is captured as group 1 at the match start; keep it and
    # replace only the value that follows.
    text = _KV_SECRET.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    return text
