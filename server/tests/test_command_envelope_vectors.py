# SPDX-License-Identifier: AGPL-3.0-only
"""Python consumer for the repository-owned command-v1/v2/v3 vectors."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
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


def _load(name: str) -> dict:
    return json.loads(VECTORS_PATH.with_name(name).read_text(encoding="utf-8"))


def _canonical_v3(envelope: dict) -> bytes:
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
        envelope.get("signing_key_id"),
    )


@pytest.fixture(scope="module")
def v3_vectors() -> dict:
    return _load("command-v3.json")


def test_v3_valid_vectors_match_canonical_bytes_and_signatures(v3_vectors: dict):
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(v3_vectors["public_key_b64"])
    )
    assert v3_vectors["valid"]
    for case in v3_vectors["valid"]:
        canonical = _canonical_v3(case["envelope"])
        assert canonical == case["canonical_json"].encode("utf-8"), case["name"]
        public_key.verify(base64.b64decode(case["signature_b64"]), canonical)


def test_v3_tampered_vectors_canonicalize_but_fail_verification(v3_vectors: dict):
    """Each case changes one signed field and keeps valid[0]'s signature.

    signing-key-id-swapped is the one that matters most: it proves the key ID
    is inside the signed bytes, so a command cannot be re-labelled to a
    different (e.g. overlap or retired) key without breaking the signature.
    """
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(v3_vectors["public_key_b64"])
    )
    assert v3_vectors["tampered"]
    for case in v3_vectors["tampered"]:
        canonical = _canonical_v3(case["envelope"])
        with pytest.raises(InvalidSignature):
            public_key.verify(base64.b64decode(case["signature_b64"]), canonical)


def test_v3_invalid_vectors_fail_closed_with_stable_codes(v3_vectors: dict):
    assert v3_vectors["invalid"]
    for case in v3_vectors["invalid"]:
        with pytest.raises(CommandEnvelopeError) as caught:
            _canonical_v3(case["envelope"])
        assert caught.value.code == case["error"], case["name"]


def test_v1_vectors_are_refused_as_a_downgrade():
    """command-v1 is retired; a validly signed v1 command must never canonicalize.

    The vectors stay in the repository as the record of the old format, and
    this is the test that keeps them meaningful.
    """
    vectors = _load("command-v1.json")
    assert vectors["valid"]
    for case in vectors["valid"]:
        with pytest.raises(CommandEnvelopeError) as caught:
            _canonical_v3(case["envelope"])
        assert caught.value.code == "unsupported_version", case["name"]
