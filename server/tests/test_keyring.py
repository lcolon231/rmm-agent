"""Signing-key registry rotation and retirement behavior."""
from __future__ import annotations

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import keyring
from app.core.config import settings


def _write_key(path):
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def test_registry_exposes_active_and_overlap_but_not_retired(tmp_path):
    active = tmp_path / "active.pem"
    overlap = tmp_path / "overlap.pem"
    retired = tmp_path / "retired.pem"
    for path in (active, overlap, retired):
        _write_key(path)
    registry = tmp_path / "keyring.json"
    registry.write_text(
        json.dumps(
            {
                "active_key_id": "key-b",
                "keys": {
                    "key-a": {"private_key_path": str(overlap), "status": "overlap"},
                    "key-b": {"private_key_path": str(active), "status": "active"},
                    "key-old": {"private_key_path": str(retired), "status": "retired"},
                },
            }
        ),
        encoding="utf-8",
    )
    previous = settings.command_signing_keyring_path
    settings.command_signing_keyring_path = str(registry)
    try:
        active_id, keys = keyring.load_keyring()
        assert active_id == "key-b"
        assert set(keyring.public_key_bundle()) == {"key-a", "key-b"}
        assert keys["key-old"].status == "retired"
    finally:
        settings.command_signing_keyring_path = previous
