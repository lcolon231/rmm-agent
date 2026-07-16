"""Security primitives: enrollment-token hashing, agent auth tokens, and
Ed25519 command signing.

Two distinct trust mechanisms live here:

1. **Agent identity** — each agent, once enrolled, holds a long-lived bearer
   token (a random secret). We store only its SHA-256 hash server-side, the
   same way you'd store an API key. The agent presents it on every check-in.

2. **Command authenticity** — every command the server dispatches to an agent
   is signed with the server's Ed25519 private key. The agent ships with the
   matching public key and refuses to execute anything that doesn't verify.
   This is what makes the audit trail meaningful: a command in the log can be
   cryptographically tied to the server that issued it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jose import JWTError, jwt

from app.core.config import settings


# --------------------------------------------------------------------------- #
# Operator passwords
# --------------------------------------------------------------------------- #
# We never store passwords — only a bcrypt hash. bcrypt is deliberately slow and
# salts each hash automatically, so identical passwords produce different hashes
# and stolen hashes are expensive to brute-force.
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


# A precomputed hash we verify against when an operator email is unknown, so a
# login attempt takes roughly the same time whether or not the account exists.
# This closes a timing side-channel that would otherwise let an attacker
# enumerate valid emails.
_DUMMY_HASH = hash_password("dummy-password-for-constant-time-comparison")


def dummy_verify() -> None:
    verify_password("wrong", _DUMMY_HASH)


# --------------------------------------------------------------------------- #
# Enrollment + agent tokens
# --------------------------------------------------------------------------- #
def generate_token(nbytes: int = 32) -> str:
    """Return a URL-safe random secret (enrollment token or agent token)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Hash a token for at-rest storage. Tokens are high-entropy secrets, so a
    single SHA-256 pass is appropriate (unlike user passwords)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    return secrets.compare_digest(hash_token(token), token_hash)


# --------------------------------------------------------------------------- #
# Dashboard JWTs (for human operators, Phase 2)
# --------------------------------------------------------------------------- #
def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.jwt_algorithm]
        )
        return payload.get("sub")
    except JWTError:
        return None


# --------------------------------------------------------------------------- #
# Ed25519 command signing
# --------------------------------------------------------------------------- #
def _load_signing_key() -> Ed25519PrivateKey:
    path = Path(settings.command_signing_key_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Command signing key not found at {path}. "
            "Generate one with scripts/gen_command_keys.py"
        )
    return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]


def canonical_command_bytes(command_id: str, agent_id: str, kind: str, payload: dict) -> bytes:
    """Deterministic byte representation of a command for signing/verification.

    Both signer and verifier must serialize identically, so we use sorted-key,
    separator-tight JSON. Never change this format without versioning it.
    """
    doc = {
        "command_id": command_id,
        "agent_id": agent_id,
        "kind": kind,
        "payload": payload,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_command(command_id: str, agent_id: str, kind: str, payload: dict) -> str:
    key = _load_signing_key()
    signature = key.sign(canonical_command_bytes(command_id, agent_id, kind, payload))
    return base64.b64encode(signature).decode("ascii")


def public_key_pem() -> str:
    """Return the PEM-encoded public key, to be baked into / fetched by agents."""
    key = _load_signing_key()
    pub: Ed25519PublicKey = key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
