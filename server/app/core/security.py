# SPDX-License-Identifier: AGPL-3.0-only
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
from app.core.command_envelope import canonical_command_bytes
from app.core.keyring import active_signing_key, public_key_bundle


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


def credential_fingerprint(token: str) -> str:
    """Non-authenticating fingerprint safe to show to administrators.

    This is deliberately domain-separated from the digest used as the database
    credential verifier, so exposing a fingerprint never exposes that verifier.
    """
    return hashlib.sha256(f"nodelink-agent-fingerprint:{token}".encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    return secrets.compare_digest(hash_token(token), token_hash)


# --------------------------------------------------------------------------- #
# Dashboard JWTs (for human operators, Phase 2)
# --------------------------------------------------------------------------- #
# Token types. A token is only ever accepted by the surface that matches its
# type, which is what keeps the half-authenticated state from being useful
# anywhere except finishing the login it belongs to.
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_MFA_PENDING = "mfa_pending"

# Authentication methods recorded in the `amr` claim (RFC 8176 spirit, not its
# exact registry). These are the facts an authorization decision may rest on:
# a password alone is not a second factor, a WebAuthn assertion is, and a
# recovery code is a second factor that deliberately does not confer the
# ability to reconfigure security settings (see app.core.mfa).
AMR_PASSWORD = "pwd"
AMR_WEBAUTHN = "webauthn"
AMR_RECOVERY_CODE = "recovery_code"
#: A session opened by activating a break-glass credential (issue #69). It is
#: deliberately NOT a second factor: it bypassed MFA, which is the whole point,
#: so it satisfies neither `session_is_mfa_verified` nor `step_up_is_fresh`.
AMR_BREAK_GLASS = "break_glass"


def create_access_token(
    subject: str,
    generation: int = 0,
    expires_minutes: int | None = None,
    *,
    amr: tuple[str, ...] = (AMR_PASSWORD,),
    step_up_at: datetime | None = None,
    session_id: str | None = None,
) -> str:
    """Mint a signed JWT for `subject`.

    `generation` is the operator's token_generation at mint time. Validation
    compares it against the current DB value, so bumping the DB counter
    revokes every previously issued token at once (JWTs themselves are
    stateless and cannot be recalled individually).

    `amr` records how the holder authenticated and `step_up_at` when they last
    proved possession of a registered authenticator. Both are *signed* claims:
    the server decides them at mint time from a verified ceremony, so a client
    cannot assert a stronger authentication state than it actually reached.

    `session_id` binds the token to a server-side session row (issue #69), which
    is what makes a session inventoryable and individually revocable. It is
    signed for the same reason as the rest: a client that could choose its own
    `sid` could point at somebody else's session.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload: dict = {
        "sub": subject,
        "gen": generation,
        "exp": expire,
        "typ": TOKEN_TYPE_ACCESS,
        "amr": list(amr),
    }
    if session_id is not None:
        payload["sid"] = session_id
    if step_up_at is not None:
        payload["sua"] = int(step_up_at.timestamp())
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_mfa_pending_token(
    subject: str, generation: int = 0, expires_seconds: int | None = None
) -> str:
    """Mint the restricted token issued between password and second factor.

    It carries a correct password and nothing more, so it is accepted *only* by
    the MFA completion endpoints. Everything else in the app resolves an
    operator through ``get_current_operator``, which refuses this type — that is
    the single choke point that prevents a half-finished login from reading or
    changing anything.
    """
    seconds = expires_seconds or settings.mfa_pending_token_ttl_seconds
    expire = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    payload = {
        "sub": subject,
        "gen": generation,
        "exp": expire,
        "typ": TOKEN_TYPE_MFA_PENDING,
        "amr": [AMR_PASSWORD],
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    """Return the verified claims, or None if the signature/expiry is invalid.

    Callers read `sub` (operator id) and `gen` (token generation). Tokens
    minted before the generation claim existed decode with gen defaulting to
    0, matching the column default, so they stay valid until the first bump.
    Likewise a token minted before MFA existed carries no `typ` or `amr`;
    :func:`token_type` and :func:`token_amr` supply the password-only defaults
    that keep such a session valid until it expires on its own.
    """
    try:
        return jwt.decode(
            token, settings.secret_key, algorithms=[settings.jwt_algorithm]
        )
    except JWTError:
        return None


def token_type(claims: dict) -> str:
    """Read the token type, defaulting to a full access token.

    The default is what makes this change backward compatible: sessions issued
    by the previous build have no `typ` and must keep working. It is safe
    because the restricted type is the *new* one, so it is always explicit —
    an attacker cannot gain privilege by omitting the claim, only by forging a
    signature, which the JWT verification already prevents.
    """
    value = claims.get("typ")
    return value if isinstance(value, str) else TOKEN_TYPE_ACCESS


def token_amr(claims: dict) -> frozenset[str]:
    """Read the authentication methods, defaulting to password-only."""
    value = claims.get("amr")
    if not isinstance(value, list):
        return frozenset({AMR_PASSWORD})
    return frozenset(item for item in value if isinstance(item, str))


def token_session_id(claims: dict) -> str | None:
    """Read the bound session id, or None for a pre-#69 token.

    None is not an error: it means the token predates server-side sessions and
    is handled by the legacy path in ``app.api.deps``, which decides whether an
    unmanaged session is still acceptable.
    """
    value = claims.get("sid")
    return value if isinstance(value, str) and value else None


def token_step_up_at(claims: dict) -> datetime | None:
    """Read when the session last proved possession of an authenticator."""
    value = claims.get("sua")
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Ed25519 command signing
# --------------------------------------------------------------------------- #
def _load_signing_key() -> Ed25519PrivateKey:
    path = active_signing_key().private_path
    if not path.exists():
        raise FileNotFoundError(
            f"Command signing key not found at {path}. "
            "Generate one with scripts/gen_command_keys.py"
        )
    return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]


def sign_command(
    envelope_version: str,
    schema_version: int,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict,
    issued_at: str,
    expires_at: str,
    nonce: str,
    signing_key_id: str | None = None,
) -> str:
    key_record = active_signing_key()
    if signing_key_id is not None and signing_key_id != key_record.key_id:
        raise ValueError("requested signing key is not active")
    signing_key_id = key_record.key_id if envelope_version == "command-v3" else None
    key = key_record.private_key
    signature = key.sign(
        canonical_command_bytes(
            envelope_version,
            schema_version,
            command_id,
            agent_id,
            kind,
            payload,
            issued_at,
            expires_at,
            nonce,
            signing_key_id,
        )
    )
    return base64.b64encode(signature).decode("ascii")


def public_key_pem() -> str:
    """Return the PEM-encoded public key, to be baked into / fetched by agents."""
    bundle = public_key_bundle()
    active_id = active_signing_key().key_id
    return bundle[active_id]


def public_key_bundle_pem() -> dict[str, str]:
    return public_key_bundle()
