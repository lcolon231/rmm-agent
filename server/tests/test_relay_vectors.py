# SPDX-License-Identifier: AGPL-3.0-only
"""Relay contract vectors (issue #87), shared with the Go agent.

The Python side produces both artifacts: relay forwarding signatures are
verified by ``app.core.relays.verify_forward``, and routing manifests are
encoded and signed by ``app.core.relays``. These tests pin that the server's
encoding still matches the committed vectors the agent verifies in
``agent/internal/verify/manifest_test.go``.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_relay_vectors.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from app.core import relays  # noqa: E402

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
VECTORS = CONTRACTS / "test-vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _verifies(pem: str, signature_b64: str, message: bytes) -> bool:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    try:
        key.verify(base64.b64decode(signature_b64), message)
    except InvalidSignature:
        return False
    return True


def test_forward_vector_matches_server_canonicalization():
    vector = _load("relay-forward-v1.json")
    inputs = dict(vector["inputs"])
    body = inputs.pop("body_utf8").encode("utf-8")
    canonical = relays.canonical_forward_bytes(body=body, **inputs)
    assert canonical.decode("utf-8") == vector["canonical"]
    assert _verifies(
        vector["public_key_pem"], vector["headers"]["x-nodelink-relay-signature"], canonical
    )
    schema = json.loads((CONTRACTS / "relay-forward-v1.schema.json").read_text(encoding="utf-8"))
    assert Draft202012Validator(schema).is_valid(vector["headers"])


def test_manifest_vectors_match_server_encoding_and_schema():
    vector = _load("routing-manifest-v1.json")
    schema = json.loads(
        (CONTRACTS / "routing-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    for case in vector["valid"]:
        raw = base64.b64decode(case["signed"]["manifest_b64"])
        doc = json.loads(raw)
        # The server's encoder reproduces the exact signed bytes.
        assert relays.encode_manifest(doc) == raw, case["name"]
        assert validator.is_valid(doc), case["name"]
        assert any(
            _verifies(vector["trusted_keys"][s["key_id"]], s["signature"], relays.MANIFEST_CONTEXT + raw)
            for s in case["signed"]["signatures"]
            if s["key_id"] in vector["trusted_keys"]
        ), case["name"]
        relay_ids = [r["relay_id"] for r in doc["routes"] if r["kind"] == "relay"]
        assert relay_ids == case["expect_relay_ids"], case["name"]


def test_untrusted_manifest_vectors_do_not_verify():
    vector = _load("routing-manifest-v1.json")
    for case in vector["invalid"]:
        if case["error"] != "signature_untrusted":
            continue
        raw = base64.b64decode(case["signed"]["manifest_b64"])
        assert not any(
            _verifies(vector["trusted_keys"][s["key_id"]], s["signature"], relays.MANIFEST_CONTEXT + raw)
            for s in case["signed"]["signatures"]
            if s["key_id"] in vector["trusted_keys"]
        ), case["name"]
