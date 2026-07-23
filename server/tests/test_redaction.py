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

import json
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_redaction.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.core import audit  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.redaction import (  # noqa: E402
    REDACTED,
    is_sensitive_key,
    redact_detail,
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
    # A bare sentinel string under a non-sensitive key/list is NOT secret-shaped
    # (no PEM/JWT), so it is preserved — key context is what marks it secret.
    # This is the documented limitation of the audit path (see REDACTION-AUDIT).
    assert out["items"][0] == SENTINEL


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
    assert redact_detail("just a string") == {"_value": "just a string"}
    assert redact_detail([1, 2, 3]) == {"_value": [1, 2, 3]}
    assert redact_detail(None) == {"_value": None}


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


# Detail shapes mirroring every existing producer, each seeded with a secret
# under a sensitive key to prove the boundary catches producers uniformly.
PRODUCER_DETAILS = [
    {"last_seen_at": "2026-07-23T00:00:00Z", "password": SENTINEL},
    {"client_count": 3, "truncated": False, "token": SENTINEL},
    {"client_id": "c1", "api_key": SENTINEL},
    {"command_id": "cmd1", "kind": "powershell", "payload_keys": ["script"],
     "nonce": "Zx9_ab-CD012345", "envelope_sha256": "b" * 64,
     "signing_key_id": "k1", "authorization": SENTINEL},
    {"command_id": "cmd1", "exit_code": 0, "status": "succeeded",
     "stdout_total_bytes": 10, "operator_password": SENTINEL},
    {"anchor_id": 1, "merkle_root": "c" * 64, "backup_passphrase": SENTINEL},
    {"operator_id": "o1", "by": "admin", "session_key": SENTINEL},
    {"hostname": "h1", "agent_token": SENTINEL},
]


@pytest.mark.asyncio
async def test_producers_cannot_persist_secrets_and_chain_verifies(db):
    for i, detail in enumerate(PRODUCER_DETAILS):
        await audit.record(db, action=f"test.producer{i}", detail=detail)
    await db.commit()

    rows = (await db.execute(select(AuditEvent))).scalars().all()
    assert len(rows) == len(PRODUCER_DETAILS)
    for ev in rows:
        stored = json.dumps(ev.detail)
        assert SENTINEL not in stored, f"secret leaked in {ev.action}: {stored}"

    # Redaction happened before hashing, so the chain over the redacted form
    # still verifies deterministically.
    ok, broken = await audit.verify_chain(db)
    assert ok, f"chain broke at {broken}"


@pytest.mark.asyncio
async def test_accountable_fields_survive_the_boundary(db):
    detail = {
        "command_id": "cmd-42", "nonce": "Zx9_ab-CD012345",
        "merkle_root": "d" * 64, "signing_key_id": "key-1",
        "agent_token": SENTINEL,
    }
    ev = await audit.record(db, action="test.keep", detail=detail)
    await db.commit()
    assert ev.detail["command_id"] == "cmd-42"
    assert ev.detail["nonce"] == "Zx9_ab-CD012345"
    assert ev.detail["merkle_root"] == "d" * 64
    assert ev.detail["signing_key_id"] == "key-1"
    assert ev.detail["agent_token"] == REDACTED
