# SPDX-License-Identifier: AGPL-3.0-only
"""Redaction-boundary tests (issues #112 and #115).

Behavior under test:
  - audit detail is redacted by key name across nesting, arrays, and casing
    variants, and malformed (non-dict) detail is handled fail-closed (#115)
  - credential value shapes that never legitimately appear in audit detail
    (PEM private keys, JWTs) are redacted regardless of key (#115)
  - legitimately public high-entropy fields (Merkle roots, event hashes,
    replay nonces, envelope digests) are preserved so chain/anchor
    verification stays reproducible (#115)
  - sentinel secrets seeded into every existing producer's detail shape do not
    survive into the stored/hashed event, and the chain still verifies (#115)
  - free-text scrubbing removes bearer headers, key=value secrets, PEM blocks,
    and JWTs from logs/diagnostics/errors (#112)

Run just this file:  pytest tests/test_redaction.py -q
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_redaction.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.core import anchor, audit  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.redaction import (  # noqa: E402
    AUDIT_DETAIL_SCHEMAS,
    AuditDetailError,
    REDACTED,
    is_sensitive_key,
    redact_detail,
    sanitize_audit_detail,
    scrub_text,
)
from app.models.models import AuditEvent  # noqa: E402
from sqlalchemy import select  # noqa: E402

# A recognizable sentinel that must never survive redaction where it is secret.
SENTINEL = "nlk-SENTINEL-SECRET-do-not-log-4c8f2a"

# A real-looking Ed25519 private key PEM (structurally valid header/footer).
PEM_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIH" + "A" * 40 + "\n"
    "-----END PRIVATE KEY-----"
)

# A JWT-shaped operator token.
JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJvcCIsImV4cCI6MjAwMDAwMDAwMH0."
    "abc123DEF456ghi789_-jkl"
)


# --------------------------- pure redaction (#115) ---------------------------


def _contains(obj, needle: str) -> bool:
    return needle in json.dumps(obj)


@pytest.mark.parametrize(
    "key",
    [
        "password", "PASSWORD", "Passphrase", "backup_passphrase",
        "agent_token", "enrollment_token", "bearer", "Authorization",
        "api_key", "session_key", "operator_secret", "cookie",
        "some_credential",
    ],
)
def test_sensitive_keys_are_redacted(key):
    out = redact_detail({key: SENTINEL})
    assert out[key] == REDACTED
    assert not _contains(out, SENTINEL)


@pytest.mark.parametrize(
    "key",
    [
        "signing_key_id", "command_public_key", "command_public_keys",
        "payload_keys", "nonce", "merkle_root", "envelope_sha256",
        "command_id", "agent_id", "seq", "hostname", "kind", "actor",
    ],
)
def test_accountable_keys_are_preserved(key):
    # These are public/accountable and must be hashed as-is for verification.
    out = redact_detail({key: "keep-me-1234567890abcdef"})
    assert out[key] == "keep-me-1234567890abcdef"


def test_nested_and_array_redaction():
    detail = {
        "outer": {
            "password": SENTINEL,
            "list": [{"token": SENTINEL}, {"nonce": "n0nce-value"}],
        },
        "items": [SENTINEL, {"api_key": SENTINEL}],
    }
    out = redact_detail(detail)
    # Every value under a sensitive key is redacted, at any depth / in arrays.
    assert out["outer"]["password"] == REDACTED
    assert out["outer"]["list"][0]["token"] == REDACTED
    assert out["items"][1]["api_key"] == REDACTED
    assert out["outer"]["list"][1]["nonce"] == "n0nce-value"
    # Credential-labelled sentinel values are redacted even when a caller files
    # them under an innocuous key.
    assert out["items"][0] == REDACTED


def test_pem_private_key_redacted_regardless_of_key():
    out = redact_detail({"note": PEM_KEY, "blob": [PEM_KEY]})
    assert out["note"] == REDACTED
    assert out["blob"][0] == REDACTED


def test_jwt_value_redacted_regardless_of_key():
    out = redact_detail({"note": JWT})
    assert out["note"] == REDACTED


def test_nonce_and_hash_shapes_are_not_treated_as_secret():
    # Nonce shares the URL-safe-base64 shape of our bearer tokens; a 64-hex
    # Merkle root/hash looks high-entropy. Neither may be redacted, or anchor
    # verification would break.
    nonce = "Zx9_ab-CD012345defGHIjk"
    root = "a" * 64
    out = redact_detail({"nonce": nonce, "merkle_root": root})
    assert out["nonce"] == nonce
    assert out["merkle_root"] == root


def test_bytes_never_persisted():
    out = redact_detail({"raw": b"secret-bytes"})
    assert out["raw"] == REDACTED


def test_malformed_detail_is_wrapped_not_trusted():
    # The generic recursive helper remains total for diagnostic callers.
    assert redact_detail("just a string") == {"_value": "just a string"}
    assert redact_detail([1, 2, 3]) == {"_value": [1, 2, 3]}
    assert redact_detail(None) == {"_value": None}

    # The audit boundary is stricter: malformed producer input is rejected
    # before hashing/persistence.
    for malformed in ("just a string", [1, 2, 3], None):
        with pytest.raises(AuditDetailError, match="must be a mapping"):
            sanitize_audit_detail("agent.offline", malformed)


def test_deep_structure_is_bounded():
    node = {}
    cur = node
    for _ in range(200):
        cur["child"] = {}
        cur = cur["child"]
    cur["password"] = SENTINEL
    out = redact_detail(node)
    assert not _contains(out, SENTINEL)  # never reached, but never leaked either


def test_scalar_types_pass_through():
    out = redact_detail({"a": 1, "b": True, "c": None, "d": 1.5})
    assert out == {"a": 1, "b": True, "c": None, "d": 1.5}


def test_redaction_is_deterministic():
    detail = {"password": SENTINEL, "outer": {"token": SENTINEL, "id": "x"}}
    assert redact_detail(detail) == redact_detail(detail)


def test_is_sensitive_key():
    assert is_sensitive_key("Agent_Token")
    assert not is_sensitive_key("signing_key_id")
    assert not is_sensitive_key("payload_keys")


# ------------------------- free-text scrubbing (#112) ------------------------


def test_scrub_bearer_header():
    # Both the Bearer rule and the Authorization key=value rule fire; the point
    # is only that the raw token never survives (over-redaction is acceptable).
    out = scrub_text("Authorization: Bearer abc.def-123")
    assert "abc.def-123" not in out
    assert REDACTED in out


def test_scrub_bearer_in_sentence():
    out = scrub_text("sent Bearer " + SENTINEL + " to server")
    assert SENTINEL not in out
    assert "Bearer [redacted]" in out


def test_scrub_kv_secret_forms():
    for form in [
        f"password={SENTINEL}",
        f'"passphrase": "{SENTINEL}"',
        f"enrollment_token: {SENTINEL}",
    ]:
        assert SENTINEL not in scrub_text(form)


def test_scrub_pem_and_jwt():
    assert PEM_KEY.split("\n")[1] not in scrub_text("dump " + PEM_KEY)
    assert JWT not in scrub_text("token " + JWT)


def test_scrub_preserves_ordinary_text():
    msg = "command 7f3a completed exit_code=0 nonce=Zx9_ab-CD01"
    # 'nonce' is not sensitive; exit_code value is numeric and stays.
    assert "command 7f3a completed" in scrub_text(msg)


# ----------------------- end-to-end through audit (#115) ---------------------


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


ID1 = "11111111-1111-4111-8111-111111111111"
ID2 = "22222222-2222-4222-8222-222222222222"
ID3 = "33333333-3333-4333-8333-333333333333"

# Exact input shape for every production action. Free-form agent/operator text
# deliberately contains the sentinel and must become digest+byte-count fields.
PRODUCER_DETAILS = {
    "agent.enrolled": {
        "hostname": SENTINEL,
        "agent_name": SENTINEL,
        "os": "windows",
        "architecture": "amd64",
        "site_id": ID1,
        "environment": "production",
        "command_envelope_version": "command-v3",
        "supported_command_envelope_versions": ["command-v3"],
        "public_key_supplied": False,
    },
    "agent.enrollment_failed": {
        "reason": "invalid_token",
        "hostname": SENTINEL,
        "agent_name": SENTINEL,
    },
    "agent.credential_renewed": {
        "credential_fingerprint": "a" * 64,
        "credential_generation": 2,
    },
    "agent.credential_renewal_rejected": {"reason": "rotation_nonce_reused"},
    "agent.command_envelope_capabilities_changed": {
        "previous": ["command-v2"],
        "current": ["command-v3"],
    },
    "agent.offline": {"last_seen_at": "2026-07-23T00:00:00+00:00"},
    "agent.quarantined": {
        "previous_trust_state": "active",
        "trust_state": "quarantined",
        "reason": SENTINEL,
    },
    "agent.restored": {
        "previous_trust_state": "quarantined",
        "trust_state": "active",
        "reason": SENTINEL,
    },
    "agent.revoked": {
        "previous_trust_state": "active",
        "trust_state": "revoked",
        "reason": SENTINEL,
    },
    "agent.commands_expired_on_revoke": {"command_ids": [ID3]},
    "audit.anchored": {
        "anchor_id": ID1,
        "merkle_root": "c" * 64,
        "event_count": 21,
    },
    "audit_timeline.viewed": {
        "event_type": "agent.enrolled",
        "actor_filter": True,
        "agent_id": ID1,
        "organization_id": ID2,
        "date_from": True,
        "date_to": False,
        "before_seq": 4096,
        "page": 2,
        "page_size": 50,
        "result_count": 50,
        "total": 91,
    },
    "audit_event.viewed": {
        "event_id": ID1,
        "action": "agent.revoked",
        "seq": 42,
    },
    "inventory.received": {
        "stored_sections": ["cpu", "system"],
        "unchanged_sections": ["memory"],
        "schema_version": 1,
        "total_bytes": 4096,
    },
    "inventory.rejected": {
        "reason": "section_schema_invalid",
        "section": "storage",
        "byte_size": 512,
    },
    "inventory.viewed": {
        "sections": ["cpu", "system"],
        "missing_sections": ["security_tpm"],
    },
    "inventory.diff_viewed": {
        "section": "installed_software",
        "from_snapshot": ID1,
        "to_snapshot": ID2,
    },
    "client_navigation.list_viewed": {
        "client_count": 3,
        "truncated": False,
    },
    "client_navigation.client_viewed": {"client_id": ID1},
    "client_navigation.site_viewed": {"site_id": ID1, "client_id": ID2},
    "client.created": {
        "client_id": ID1,
        "name": SENTINEL,
    },
    "site.created": {
        "site_id": ID1,
        "client_id": ID2,
        "name": SENTINEL,
    },
    "monitoring_policy.created": {
        "policy_id": ID1,
        "scope": "site",
        "scope_id": ID2,
        "enabled": True,
        "check_count": 2,
        "name": SENTINEL,
        "change_note": SENTINEL,
    },
    "monitoring_policy.revised": {
        "policy_id": ID1,
        "version": 2,
        "enabled": True,
        "check_count": 3,
        "change_note": SENTINEL,
    },
    "monitoring_policy.deleted": {
        "policy_id": ID1,
        "scope": "site",
        "scope_id": ID2,
        "name": SENTINEL,
    },
    "monitoring_policy.viewed": {
        "policy_id": ID1,
        "version": 2,
        "check_count": 3,
        "revision_count": 2,
    },
    "monitoring_alert.acknowledged": {
        "alert_id": ID1,
        "generation": 1,
        "request_id": "request-12345678",
        "from_state": "open",
        "to_state": "acknowledged",
        "comment": SENTINEL,
        "comment_redacted": False,
    },
    "monitoring_alert.assigned": {
        "alert_id": ID1,
        "generation": 1,
        "request_id": "request-12345679",
        "assigned_to_operator_id": ID2,
        "assigned_to_email": SENTINEL,
        "comment": SENTINEL,
        "comment_redacted": False,
    },
    "monitoring_alert.commented": {
        "alert_id": ID1,
        "generation": 1,
        "request_id": "request-12345680",
        "state": "acknowledged",
        "comment": SENTINEL,
        "comment_redacted": False,
    },
    "monitoring_alert.resolved": {
        "alert_id": ID1,
        "generation": 1,
        "request_id": "request-12345681",
        "from_state": "acknowledged",
        "to_state": "resolved",
        "comment": SENTINEL,
        "comment_redacted": False,
    },
    "monitoring_alert_email.retried": {
        "delivery_id": ID3,
        "alert_id": ID1,
        "request_id": "request-12345682",
        "previous_status": "failed",
        "recipient": SENTINEL,
    },
    "webhook_endpoint.created": {
        "endpoint_id": ID1,
        "name": SENTINEL,
        "url": SENTINEL,
        "enabled": True,
        "event_types": ["opened", "automatic_recovery"],
        "secret_version": 1,
    },
    "webhook_endpoint.updated": {
        "endpoint_id": ID1,
        "request_id": "request-12345683",
        "previous_version": 1,
        "version": 2,
        "name": SENTINEL,
        "url": SENTINEL,
        "enabled": True,
        "event_types": ["opened"],
    },
    "webhook_endpoint.deleted": {
        "endpoint_id": ID1,
        "request_id": "request-12345684",
        "previous_version": 2,
        "version": 3,
        "name": SENTINEL,
        "url": SENTINEL,
    },
    "webhook_endpoint.secret_rotated": {
        "endpoint_id": ID1,
        "request_id": "request-12345685",
        "previous_version": 2,
        "version": 3,
        "previous_secret_version": 1,
        "secret_version": 2,
    },
    "monitoring_alert_webhook.retried": {
        "delivery_id": ID3,
        "alert_id": ID1,
        "endpoint_id": ID2,
        "request_id": "request-12345686",
        "previous_status": "failed",
        "destination": SENTINEL,
    },
    "script_library.list_viewed": {
        "page": 1,
        "page_size": 50,
        "result_count": 3,
        "total": 3,
    },
    "script_library.item_viewed": {
        "script_id": ID1,
        "version_count": 2,
    },
    "script_library.version_viewed": {
        "script_id": ID1,
        "version": 2,
        "content_sha256": "d" * 64,
        "content_bytes": 128,
    },
    "script_library.created": {
        "script_id": ID1,
        "version": 1,
        "language": "powershell",
        "content_sha256": "d" * 64,
        "content_bytes": 128,
        "tags": ["remediation"],
        "supported_platforms": ["windows"],
        "parameter_count": 2,
        "name": SENTINEL,
    },
    "script_library.version_created": {
        "script_id": ID1,
        "version": 2,
        "language": "powershell",
        "content_sha256": "e" * 64,
        "content_bytes": 144,
        "tags": ["remediation"],
        "supported_platforms": ["windows"],
        "parameter_count": 2,
    },
    "script_library.parameter_values_prepared": {
        "script_id": ID1,
        "version": 2,
        "parameter_value_set_id": ID2,
        "request_id": "request-12345687",
        # Only key names and a keyed fingerprint are evidence; a submitted
        # value must never be representable in this schema.
        "provided_keys": ["ServiceName", "ApiToken"],
        "defaulted_keys": ["Attempts"],
        "secret_keys": ["ApiToken"],
        "values_fingerprint": "f" * 64,
        "expires_at": "2026-08-06T10:00:00+00:00",
    },
    "script_library.reviewed": {
        "script_id": ID1,
        "version": 2,
        "state": "approved",
        "reason": SENTINEL,
    },
    "script_library.deprecated": {
        "script_id": ID1,
        "request_id": "request-12345687",
        "previous_record_version": 2,
        "record_version": 3,
        "reason": SENTINEL,
    },
    "maintenance_window.created": {
        "maintenance_window_id": ID3,
        "scope": "client",
        "scope_id": ID2,
        "starts_at": "2026-07-29T00:00:00+00:00",
        "ends_at": "2026-07-29T02:00:00+00:00",
        "name": SENTINEL,
    },
    "maintenance_window.deleted": {
        "maintenance_window_id": ID3,
        "scope": "client",
        "scope_id": ID2,
        "name": SENTINEL,
    },
    "enrollment_token.created": {
        "site_id": ID1,
        "name": SENTINEL,
        "expires_at": "2026-07-29T00:00:00+00:00",
        "max_uses": 1,
        "has_hostname_restriction": True,
        "has_agent_name_restriction": False,
        "labels": ["canary"],
    },
    "enrollment_token.revoked": {
        "site_id": ID1,
        "reason": SENTINEL,
    },
    "installer_package.created": {
        "site_id": ID1,
        "download_id": ID2,
        "enrollment_token_id": ID3,
        "artifact_version": "0.1.2",
        "artifact_sha256": "a" * 64,
        "token_expires_at": "2026-07-29T00:00:00+00:00",
    },
    "installer_package.rejected": {
        "site_id": ID1,
        "reason": "installer_artifact_integrity",
    },
    "command.authorization_allowed": {
        "operator_id": ID1,
        "operator_role": "operator",
        "kind": "powershell",
        "site_id": ID2,
        "policy": "script_permission",
        "reason": "script_permission_scope_allowed",
        "permission_scope": "site",
        "permission_scope_id": ID2,
    },
    "command.authorization_denied": {
        "operator_id": ID1,
        "operator_role": "operator",
        "kind": "powershell",
        "site_id": ID2,
        "policy": "script_permission",
        "reason": "script_permission_missing",
        "permission_scope": None,
        "permission_scope_id": None,
    },
    "command.completed": {
        "command_id": ID3,
        "kind": "powershell",
        "exit_code": 0,
        "status": "succeeded",
        "agent_completed_at": "2026-07-23T00:00:00+00:00",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_total_bytes": 12,
        "stderr_total_bytes": 0,
    },
    "command.dispatched": {
        "command_id": ID3,
        "kind": "powershell",
        "payload_keys": ["script"],
        "envelope_version": "command-v3",
        "schema_version": 3,
        "issued_at": "2026-07-23T00:00:00Z",
        "expires_at": "2026-07-23T00:05:00Z",
        "nonce": "Zx9_ab-CD012345",
        "signing_key_id": "key-1",
        "envelope_sha256": "b" * 64,
        "script_version_id": None,
        "script_parameter_value_set_id": None,
    },
    "command.result_pending": {
        "command_id": ID3,
        "kind": "powershell",
        "agent_completed_at": "2026-07-23T00:00:00+00:00",
    },
    "command_detail.viewed": {"command_id": ID3, "status": "succeeded"},
    "endpoint_detail.viewed": {
        "history_hours": 24,
        "history_limit": 144,
        "history_count": 12,
        "history_truncated": False,
        "script_execution_allowed": True,
    },
    "endpoint_list.viewed": {
        "client_id": None,
        "site_id": None,
        "status": None,
        "search": False,
        "sort": "last_seen",
        "direction": "desc",
        "page": 1,
        "page_size": 25,
        "result_count": 3,
    },
    "operator.script_permission_changed": {
        "operator_id": ID1,
        "operator_role": "operator",
        "previous_scope": None,
        "previous_scope_id": None,
        "new_scope": "site",
        "new_scope_id": ID2,
        "reason": SENTINEL,
    },
    "operator.script_permission_revoked": {
        "operator_id": ID1,
        "operator_role": "operator",
        "previous_scope": "site",
        "previous_scope_id": ID2,
        "reason": SENTINEL,
    },
    "operator.created": {
        "operator_id": ID1,
        "operator_role": "operator",
        "email": SENTINEL,
    },
    "operator.role_changed": {
        "operator_id": ID1,
        "previous_role": "operator",
        "new_role": "readonly",
        "script_permission_revoked": True,
        "reason": SENTINEL,
    },
    "operator.status_changed": {
        "operator_id": ID1,
        "previous_disabled": False,
        "new_disabled": True,
        "reason": SENTINEL,
    },
    "operator.tokens_revoked": {"operator_id": ID1, "by": "admin"},
    "scheduled_task.created": {
        "scheduled_task_id": ID1,
        "name": SENTINEL,
        "target_type": "agent",
        "target_id": ID2,
        "cron_expression": "0 * * * *",
        "timezone": "UTC",
        "next_run_at": "2026-08-08T12:00:00+00:00",
        "actor": "admin@example.com",
        "actor_user_id": ID3,
        "source_ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
    },
    "scheduled_task.updated": {
        "scheduled_task_id": ID1,
        "name": SENTINEL,
        "enabled": True,
        "next_run_at": "2026-08-08T12:00:00+00:00",
        "actor": "admin@example.com",
        "actor_user_id": ID3,
        "source_ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
    },
    "scheduled_task.deleted": {
        "scheduled_task_id": ID1,
        "name": SENTINEL,
        "target_type": "agent",
        "target_id": ID2,
        "actor": "admin@example.com",
        "actor_user_id": ID3,
        "source_ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
    },
    "scheduled_task.toggled": {
        "scheduled_task_id": ID1,
        "name": SENTINEL,
        "enabled": False,
        "actor": "admin@example.com",
        "actor_user_id": ID3,
        "source_ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
    },
    "scheduled_task.manually_triggered": {
        "scheduled_task_id": ID1,
        "name": SENTINEL,
        "dispatched_count": 1,
        "actor": "admin@example.com",
        "actor_user_id": ID3,
        "source_ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0",
    },
    "scheduled_task.dispatched": {
        "scheduled_task_id": ID1,
        "scheduled_task_name": SENTINEL,
        "command_id": ID2,
        "kind": "powershell",
        "target_type": "agent",
        "target_id": ID3,
    },
    "scheduled_task.misfire_skipped": {
        "scheduled_task_id": ID1,
        "scheduled_task_name": SENTINEL,
        "scheduled_for": "2026-08-07T00:00:00+00:00",
        "detected_at": "2026-08-08T12:00:00+00:00",
    },
}



def _source_audit_actions() -> tuple[set[str], int]:
    """Discover literal production producers and the one typed trust helper."""
    app_root = Path(__file__).resolve().parents[1] / "app"
    actions: set[str] = set()
    dynamic_record_calls = 0
    for path in app_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "record"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "audit"
            ):
                action_kw = next(
                    (kw.value for kw in node.keywords if kw.arg == "action"),
                    None,
                )
                if isinstance(action_kw, ast.Constant) and isinstance(
                    action_kw.value, str
                ):
                    actions.add(action_kw.value)
                else:
                    dynamic_record_calls += 1
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "_apply_trust_change"
            ):
                actions.update(
                    arg.value
                    for arg in node.args
                    if isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and arg.value.startswith("agent.")
                )
    return actions, dynamic_record_calls


def test_every_production_action_has_exact_schema_and_documentation():
    source_actions, dynamic_calls = _source_audit_actions()
    assert dynamic_calls == 1  # _apply_trust_change(action=...)
    assert source_actions == set(AUDIT_DETAIL_SCHEMAS)
    assert set(PRODUCER_DETAILS) == set(AUDIT_DETAIL_SCHEMAS)

    docs = (
        Path(__file__).resolve().parents[2] / "docs" / "AUDIT-EVENTS.md"
    ).read_text(encoding="utf-8")
    for action, schema in AUDIT_DETAIL_SCHEMAS.items():
        assert f"`{action}`" in docs
        for field in schema.stored_fields:
            assert f"`{field}`" in docs


@pytest.mark.asyncio
async def test_producers_cannot_persist_secrets_and_chain_anchor_verify(db):
    for action, detail in PRODUCER_DETAILS.items():
        # Every registered producer rejects field drift, including a deeply
        # nested sentinel smuggled under an innocuous top-level key.
        malformed = {
            **detail,
            "unclassified": {"nested": [{"credential": SENTINEL}]},
        }
        with pytest.raises(AuditDetailError, match="unexpected fields"):
            await audit.record(db, action=action, detail=malformed)
        await audit.record(db, action=action, detail=detail)
    await db.commit()

    rows = (
        await db.execute(select(AuditEvent).order_by(AuditEvent.seq))
    ).scalars().all()
    assert len(rows) == len(PRODUCER_DETAILS)
    assert [event.seq for event in rows] == list(
        range(1, len(PRODUCER_DETAILS) + 1)
    )
    for ev in rows:
        stored = json.dumps(ev.detail)
        assert SENTINEL not in stored, f"secret leaked in {ev.action}: {stored}"
        assert set(ev.detail) == AUDIT_DETAIL_SCHEMAS[ev.action].stored_fields

    ok, broken = await audit.verify_chain(db)
    assert ok, f"chain broke at {broken}"

    audit_anchor = await anchor.create_anchor(db)
    assert audit_anchor is not None
    await db.commit()
    intact, reason = await anchor.verify_anchor(db, audit_anchor)
    assert intact, reason


def test_accountable_fields_survive_and_free_text_is_digest_only():
    dispatched = sanitize_audit_detail(
        "command.dispatched",
        PRODUCER_DETAILS["command.dispatched"],
    )
    assert dispatched["command_id"] == ID3
    assert dispatched["nonce"] == "Zx9_ab-CD012345"
    assert dispatched["envelope_sha256"] == "b" * 64
    assert dispatched["signing_key_id"] == "key-1"

    enrolled = sanitize_audit_detail(
        "agent.enrolled",
        PRODUCER_DETAILS["agent.enrolled"],
    )
    assert "hostname" not in enrolled
    assert enrolled["hostname_bytes"] == len(SENTINEL.encode("utf-8"))
    assert len(enrolled["hostname_sha256"]) == 64
    assert SENTINEL not in json.dumps(enrolled)


@pytest.mark.parametrize(
    ("detail", "message"),
    [
        ({"last_seen_at": "now", "extra": 1}, "unexpected fields"),
        ({}, "missing fields"),
        ({1: "now"}, "keys must be strings"),
        ({"last_seen_at": {"nested": "value"}}, "nested object"),
        ({"last_seen_at": [SENTINEL, {"nested": "value"}]}, "scalar items"),
        ({"last_seen_at": b"raw"}, "may not contain bytes"),
        ({"last_seen_at": float("nan")}, "not finite"),
    ],
)
def test_audit_policy_rejects_malformed_detail(detail, message):
    with pytest.raises(AuditDetailError, match=message):
        sanitize_audit_detail("agent.offline", detail)


def test_audit_policy_rejects_unknown_action_and_oversized_value():
    with pytest.raises(AuditDetailError, match="unregistered audit action"):
        sanitize_audit_detail("future.unreviewed", {})
    with pytest.raises(AuditDetailError, match="too large"):
        sanitize_audit_detail("agent.offline", {"last_seen_at": "x" * 4097})
