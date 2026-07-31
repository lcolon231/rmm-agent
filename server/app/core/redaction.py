# SPDX-License-Identifier: AGPL-3.0-only
"""Central, deterministic redaction boundary for audit detail and diagnostics.

Two related problems, one module:

* **Audit events (issue #115).** `audit.record` runs every action and ``detail``
  through :func:`sanitize_audit_detail` before sequence allocation, hashing, or
  persistence. Exact action/field schemas reject producer drift and malformed
  input; credential shapes are redacted and arbitrary prose is digest-only.
  The policy is deterministic, so chain and anchor verification stay
  reproducible over the stored safe representation.

* **Logs / diagnostics / errors (issue #112).** :func:`scrub_text` removes
  credential-shaped substrings from free text before it reaches a log line or
  an API error body.

A design constraint is specific to this codebase: audit detail legitimately
carries high-entropy *public* values—Merkle roots and event hashes (64 hex
chars), replay nonces (URL-safe base64, the same shape as bearer tokens), and
envelope digests. Exact per-action schemas distinguish those reviewed fields
from unclassified input; public evidence is preserved while unknown fields are
rejected.

:func:`scrub_text` has no verification obligation, so it is allowed to
over-redact and casts a wider net (bearer headers, ``key=value`` secrets, PEM,
JWTs).
"""
from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

REDACTED = "[redacted]"
_TOO_DEEP = "[redacted:too-deep]"

# Recursion guard. Mirrors the 16-level envelope nesting limit's intent: bound
# the work and fail closed (redact) rather than recurse without limit.
_MAX_DEPTH = 64

# Audit producers are intentionally much more constrained than the generic
# recursive redactor. No production event currently needs nested objects, and
# accepting arbitrary object graphs would create an easy place for a future
# producer to hide an unclassified credential.
_MAX_AUDIT_STRING_BYTES = 4096
_MAX_AUDIT_LIST_ITEMS = 1000


class AuditDetailError(ValueError):
    """An audit action or detail failed the fail-closed producer policy."""


@dataclass(frozen=True)
class AuditDetailSchema:
    """Exact top-level input contract for one audit action.

    ``digest_fields`` are accepted as strings but never stored verbatim. Their
    UTF-8 SHA-256 and byte count are stored instead, retaining correlation and
    accountability without committing operator/agent-controlled prose to the
    immutable audit chain.
    """

    fields: frozenset[str]
    digest_fields: frozenset[str] = frozenset()

    @property
    def stored_fields(self) -> frozenset[str]:
        stored = set(self.fields - self.digest_fields)
        for field in self.digest_fields:
            stored.update((f"{field}_sha256", f"{field}_bytes"))
        return frozenset(stored)


def _schema(
    *fields: str,
    digest_fields: tuple[str, ...] = (),
) -> AuditDetailSchema:
    schema = AuditDetailSchema(frozenset(fields), frozenset(digest_fields))
    if not schema.digest_fields <= schema.fields:
        raise ValueError("digest fields must be part of the audit schema")
    return schema


# Every production audit producer is represented here. ``sanitize_audit_detail``
# rejects unknown actions and any field drift, so adding or changing a producer
# requires an explicit, reviewable policy update.
AUDIT_DETAIL_SCHEMAS: dict[str, AuditDetailSchema] = {
    "agent.enrolled": _schema(
        "hostname",
        "agent_name",
        "os",
        "architecture",
        "site_id",
        "environment",
        "command_envelope_version",
        "supported_command_envelope_versions",
        "public_key_supplied",
        digest_fields=("hostname", "agent_name", "os"),
    ),
    "agent.enrollment_failed": _schema(
        "reason",
        "hostname",
        "agent_name",
        digest_fields=("hostname", "agent_name"),
    ),
    "agent.credential_renewed": _schema("credential_fingerprint"),
    "agent.command_envelope_capabilities_changed": _schema(
        "previous",
        "current",
    ),
    "agent.offline": _schema("last_seen_at"),
    "agent.quarantined": _schema(
        "previous_trust_state",
        "trust_state",
        "reason",
        digest_fields=("reason",),
    ),
    "agent.restored": _schema(
        "previous_trust_state",
        "trust_state",
        "reason",
        digest_fields=("reason",),
    ),
    "agent.revoked": _schema(
        "previous_trust_state",
        "trust_state",
        "reason",
        digest_fields=("reason",),
    ),
    "agent.commands_expired_on_revoke": _schema("command_ids"),
    "audit.anchored": _schema("anchor_id", "merkle_root", "event_count"),
    # Reading the evidence is itself an auditable act, so the timeline and
    # single-event views record who looked and what they scoped the view to.
    # Free-text filters are recorded as booleans, and ``event_type`` only as a
    # registered action name, so an operator cannot write arbitrary prose into
    # the tamper-evident chain through a query string.
    "audit_timeline.viewed": _schema(
        "event_type",
        "actor_filter",
        "agent_id",
        "organization_id",
        "date_from",
        "date_to",
        "before_seq",
        "page",
        "page_size",
        "result_count",
        "total",
    ),
    "audit_event.viewed": _schema("event_id", "action", "seq"),
    # Inventory payloads carry serials, adapter addresses, and volume labels.
    # Only section names, counts, and sizes reach the permanent chain.
    "inventory.received": _schema(
        "stored_sections",
        "unchanged_sections",
        "schema_version",
        "total_bytes",
    ),
    "inventory.rejected": _schema("reason", "section", "byte_size"),
    "client_navigation.list_viewed": _schema("client_count", "truncated"),
    "client_navigation.client_viewed": _schema("client_id"),
    "client_navigation.site_viewed": _schema("site_id", "client_id"),
    "client.created": _schema(
        "client_id",
        "name",
        digest_fields=("name",),
    ),
    "site.created": _schema(
        "site_id",
        "client_id",
        "name",
        digest_fields=("name",),
    ),
    "command.authorization_allowed": _schema(
        "operator_id",
        "operator_role",
        "kind",
        "site_id",
        "policy",
        "reason",
        "permission_scope",
        "permission_scope_id",
    ),
    "command.authorization_denied": _schema(
        "operator_id",
        "operator_role",
        "kind",
        "site_id",
        "policy",
        "reason",
        "permission_scope",
        "permission_scope_id",
    ),
    "command.completed": _schema(
        "command_id",
        "kind",
        "exit_code",
        "status",
        "agent_completed_at",
        "stdout_truncated",
        "stderr_truncated",
        "stdout_total_bytes",
        "stderr_total_bytes",
    ),
    "command.dispatched": _schema(
        "command_id",
        "kind",
        "payload_keys",
        "envelope_version",
        "schema_version",
        "issued_at",
        "expires_at",
        "nonce",
        "signing_key_id",
        "envelope_sha256",
    ),
    "command.result_pending": _schema(
        "command_id",
        "kind",
        "agent_completed_at",
    ),
    "command_detail.viewed": _schema("command_id", "status"),
    "endpoint_detail.viewed": _schema(
        "history_hours",
        "history_limit",
        "history_count",
        "history_truncated",
        "script_execution_allowed",
    ),
    "endpoint_list.viewed": _schema(
        "client_id",
        "site_id",
        "status",
        "search",
        "sort",
        "direction",
        "page",
        "page_size",
        "result_count",
    ),
    "enrollment_token.created": _schema(
        "site_id",
        "name",
        "expires_at",
        "max_uses",
        "has_hostname_restriction",
        "has_agent_name_restriction",
        "labels",
        digest_fields=("name",),
    ),
    "enrollment_token.revoked": _schema(
        "site_id",
        "reason",
        digest_fields=("reason",),
    ),
    "operator.script_permission_changed": _schema(
        "operator_id",
        "operator_role",
        "previous_scope",
        "previous_scope_id",
        "new_scope",
        "new_scope_id",
        "reason",
        digest_fields=("reason",),
    ),
    "operator.script_permission_revoked": _schema(
        "operator_id",
        "operator_role",
        "previous_scope",
        "previous_scope_id",
        "reason",
        digest_fields=("reason",),
    ),
    "operator.created": _schema(
        "operator_id",
        "operator_role",
        "email",
        digest_fields=("email",),
    ),
    "operator.role_changed": _schema(
        "operator_id",
        "previous_role",
        "new_role",
        "script_permission_revoked",
        "reason",
        digest_fields=("reason",),
    ),
    "operator.status_changed": _schema(
        "operator_id",
        "previous_disabled",
        "new_disabled",
        "reason",
        digest_fields=("reason",),
    ),
    "operator.tokens_revoked": _schema("operator_id", "by"),
}

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

# Sentinel tests and accidentally labelled credentials often reach the boundary
# as a bare string rather than a full JWT/PEM. This narrow marker check is safe
# for audit detail because free-form producer text is digest-only; readable
# strings are identifiers, enum-like codes, timestamps, and public evidence.
_CREDENTIAL_VALUE_MARKER = re.compile(
    r"(?i)(?:password|passphrase|secret|bearer|credential|"
    r"private[-_ ]?key|api[-_ ]?key|access[-_ ]?token|"
    r"agent[-_ ]?token|enrollment[-_ ]?token|session[-_ ]?key)"
)


def is_sensitive_key(key: Any) -> bool:
    """True if *key* names a credential-bearing field."""
    k = str(key).lower()
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


def _redact_scalar_str(value: str) -> str:
    """Redact a credential-shaped or explicitly credential-labelled value."""
    if _PEM_PRIVATE_KEY.search(value):
        return REDACTED
    if _JWT.fullmatch(value):
        return REDACTED
    if _CREDENTIAL_VALUE_MARKER.search(value):
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


def _normalize_audit_scalar(value: Any, field: str) -> Any:
    """Validate one producer value and return its deterministic safe form."""
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuditDetailError(f"audit detail field {field!r} is not finite")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_AUDIT_STRING_BYTES:
            raise AuditDetailError(f"audit detail field {field!r} is too large")
        return _redact_scalar_str(value)
    if isinstance(value, (bytes, bytearray)):
        raise AuditDetailError(f"audit detail field {field!r} may not contain bytes")
    if isinstance(value, Mapping):
        raise AuditDetailError(
            f"audit detail field {field!r} may not contain a nested object"
        )
    if isinstance(value, Sequence):
        if len(value) > _MAX_AUDIT_LIST_ITEMS:
            raise AuditDetailError(f"audit detail field {field!r} has too many items")
        normalized = []
        for item in value:
            if isinstance(item, (Mapping, Sequence)) and not isinstance(item, str):
                raise AuditDetailError(
                    f"audit detail field {field!r} may contain only scalar items"
                )
            normalized.append(_normalize_audit_scalar(item, field))
        return normalized
    raise AuditDetailError(
        f"audit detail field {field!r} has unsupported type "
        f"{type(value).__name__}"
    )


def sanitize_audit_detail(action: str, detail: Any) -> dict:
    """Enforce one action's schema, then return the only form that may be hashed.

    The boundary is intentionally fail closed. Unknown actions, field drift,
    malformed structures, and non-canonical JSON values are rejected before a
    sequence number is allocated or an ``AuditEvent`` is added to the session.
    """
    if not isinstance(action, str):
        raise AuditDetailError("audit action must be a string")
    schema = AUDIT_DETAIL_SCHEMAS.get(action)
    if schema is None:
        raise AuditDetailError(f"unregistered audit action {action!r}")
    if not isinstance(detail, Mapping):
        raise AuditDetailError("audit detail must be a mapping")
    if any(not isinstance(key, str) for key in detail):
        raise AuditDetailError("audit detail keys must be strings")

    actual = frozenset(detail)
    missing = sorted(schema.fields - actual)
    unexpected = sorted(actual - schema.fields)
    if missing or unexpected:
        parts = []
        if missing:
            parts.append(f"missing fields: {missing}")
        if unexpected:
            parts.append(f"unexpected fields: {unexpected}")
        raise AuditDetailError(
            f"audit detail does not match schema for {action!r}: "
            + "; ".join(parts)
        )

    output: dict[str, Any] = {}
    for field in sorted(schema.fields):
        value = detail[field]
        if field in schema.digest_fields:
            if not isinstance(value, str):
                raise AuditDetailError(
                    f"audit digest-only field {field!r} must be a string"
                )
            encoded = value.encode("utf-8")
            if len(encoded) > _MAX_AUDIT_STRING_BYTES:
                raise AuditDetailError(f"audit detail field {field!r} is too large")
            output[f"{field}_sha256"] = hashlib.sha256(encoded).hexdigest()
            output[f"{field}_bytes"] = len(encoded)
        else:
            output[field] = _normalize_audit_scalar(value, field)
    return output


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
