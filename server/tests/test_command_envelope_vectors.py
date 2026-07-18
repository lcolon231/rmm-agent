# SPDX-License-Identifier: AGPL-3.0-only
"""Python consumer for the repository-owned command-v2 vectors."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.command_envelope import (
    CommandEnvelopeError,
    canonical_command_bytes,
    COMMAND_ENVELOPE_V3,
)


VECTORS_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "test-vectors"
    / "command-v2.json"
)


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _canonical(envelope: dict) -> bytes:
    return canonical_command_bytes(
        envelope.get("envelope_version", ""),
        envelope.get("schema_version"),
        envelope.get("command_id", ""),
        envelope.get("agent_id", ""),
        envelope.get("kind", ""),
        envelope.get("payload"),
        envelope.get("issued_at", ""),
        envelope.get("expires_at", ""),
        envelope.get("nonce", ""),
    )


def test_valid_vectors_match_canonical_bytes_and_signatures(vectors: dict):
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(vectors["public_key_b64"])
    )
    for case in vectors["valid"]:
        canonical = _canonical(case["envelope"])
        assert canonical == case["canonical_json"].encode("utf-8"), case["name"]
        public_key.verify(base64.b64decode(case["signature_b64"]), canonical)


def test_invalid_vectors_fail_closed_with_stable_codes(vectors: dict):
    for case in vectors["invalid"]:
        if case.get("raw_payload") is not None:
            with pytest.raises(json.JSONDecodeError):
                json.loads(case["raw_payload"])
            continue
        with pytest.raises(CommandEnvelopeError) as caught:
            _canonical(case["envelope"])
        assert caught.value.code == case["error"], case["name"]


def test_v3_binds_signing_key_id():
    envelope = {
        "envelope_version": COMMAND_ENVELOPE_V3,
        "schema_version": 1,
        "command_id": "c-key",
        "agent_id": "a-key",
        "kind": "shell",
        "payload": {"script": "whoami"},
        "issued_at": "2026-07-18T12:00:00Z",
        "expires_at": "2026-07-18T12:05:00Z",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    }
    with pytest.raises(CommandEnvelopeError) as caught:
        _canonical(envelope)
    assert caught.value.code == "missing_signing_key_id"

    canonical = canonical_command_bytes(
        **{**envelope, "signing_key_id": "key-2026-a"}
    )
    assert b'"signing_key_id":"key-2026-a"' in canonical


def test_v3_shared_vector():
    path = VECTORS_PATH.with_name("command-v3.json")
    vectors = json.loads(path.read_text(encoding="utf-8"))
    case = vectors["valid"][0]
    envelope = case["envelope"]
    canonical = canonical_command_bytes(
        envelope["envelope_version"], envelope["schema_version"],
        envelope["command_id"], envelope["agent_id"], envelope["kind"],
        envelope["payload"], envelope["issued_at"], envelope["expires_at"],
        envelope["nonce"], envelope["signing_key_id"],
    )
    assert canonical == case["canonical_json"].encode("utf-8")
