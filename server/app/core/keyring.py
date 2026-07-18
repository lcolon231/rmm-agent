"""Operator-managed Ed25519 signing-key registry.

The registry keeps private material outside the database while making key IDs,
overlap, and retirement explicit. A missing registry preserves the existing
single-key deployment as ``default``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import settings


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    private_path: Path | None
    public_path: Path | None = None
    status: str = "active"

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self.private_path is None:
            raise ValueError(f"private material is unavailable for key {self.key_id!r}")
        value = serialization.load_pem_private_key(
            self.private_path.read_bytes(), password=None
        )
        if not isinstance(value, Ed25519PrivateKey):
            raise ValueError(f"signing key {self.key_id!r} is not Ed25519")
        return value

    @property
    def public_key_pem(self) -> str:
        if self.public_path is not None:
            return self.public_path.read_text(encoding="ascii")
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")


def _validate_id(key_id: str) -> None:
    import re

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id):
        raise ValueError(f"invalid signing key ID {key_id!r}")


def load_keyring() -> tuple[str, dict[str, SigningKey]]:
    """Load active/overlap keys and fail closed on malformed state."""
    registry = settings.command_signing_keyring_path
    if not registry:
        key_id = settings.command_signing_key_id
        _validate_id(key_id)
        key = SigningKey(key_id, Path(settings.command_signing_key_path), None, "active")
        return key_id, {key_id: key}

    doc = json.loads(Path(registry).read_text(encoding="utf-8"))
    active_id = doc.get("active_key_id")
    entries = doc.get("keys")
    if not isinstance(active_id, str) or not isinstance(entries, dict):
        raise ValueError("signing key registry requires active_key_id and keys")
    _validate_id(active_id)
    keys: dict[str, SigningKey] = {}
    for key_id, item in entries.items():
        if not isinstance(key_id, str) or not isinstance(item, dict):
            raise ValueError("malformed signing key registry entry")
        _validate_id(key_id)
        status = item.get("status", "overlap")
        if status not in {"active", "overlap", "retired"}:
            raise ValueError(f"invalid status for signing key {key_id!r}")
        private_path = item.get("private_key_path")
        public_path = item.get("public_key_path")
        if not isinstance(private_path, str) and not isinstance(public_path, str):
            raise ValueError(f"missing key material for signing key {key_id!r}")
        keys[key_id] = SigningKey(
            key_id,
            Path(private_path) if isinstance(private_path, str) else None,
            Path(public_path) if isinstance(public_path, str) else None,
            status,
        )
    if active_id not in keys or keys[active_id].status != "active":
        raise ValueError("active_key_id must reference an active key")
    return active_id, keys


def active_signing_key() -> SigningKey:
    active_id, keys = load_keyring()
    return keys[active_id]


def public_key_bundle() -> dict[str, str]:
    _, keys = load_keyring()
    return {
        key_id: key.public_key_pem
        for key_id, key in keys.items()
        if key.status in {"active", "overlap"}
    }
