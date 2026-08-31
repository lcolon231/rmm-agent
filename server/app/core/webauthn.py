# SPDX-License-Identifier: AGPL-3.0-only
"""WebAuthn (FIDO2) registration and assertion verification (issue #67).

This module is pure verification: it takes the bytes a browser returned, decides
whether they prove possession of a registered authenticator, and returns the
facts the caller must persist. It touches no database and no request context, so
every rule below is testable in isolation and the API layer stays a thin,
auditable shell around it.

What phishing resistance actually rests on, and where each check lives:

* The **origin** in ``clientDataJSON`` is bound by the browser and cannot be set
  by script. Checking it against an exact allow-list is what stops a look-alike
  site from relaying a credential (:func:`_verify_client_data`).
* The **RP ID hash** in the authenticator data is bound by the authenticator,
  which will only produce it for the scope the credential was created under.
  Checking it stops a compromised or misconfigured front end from widening that
  scope (:func:`_parse_authenticator_data` plus the expected value passed in).
* The **challenge** is server-generated, single-use, and short-lived. Replay
  protection is the responsibility of ``app.core.mfa``; this module only proves
  the signed challenge is the one expected, compared in constant time.

Deliberate scope limits, stated plainly rather than implied:

* **Attestation is not verified, and we do not claim it is.** Registration
  options request ``attestation: "none"``, so conforming browsers strip the
  statement. We accept the ``none`` format, and ``packed`` self-attestation
  whose signature we do verify against the credential key being registered.
  Every other format is refused. This binds the credential to the ceremony; it
  does *not* establish authenticator make, model, or certification, so no
  hardware-provenance claim may be built on this module's output.
* **Supported algorithms** are ES256, EdDSA (Ed25519), and RS256. Anything else
  is refused at registration, so an unverifiable key can never be stored.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.cbor import CBORDecodeError, decode, decode_prefix

# COSE algorithm identifiers (IANA COSE Algorithms registry).
COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8
COSE_ALG_RS256 = -257

#: Algorithms offered in registration options, most preferred first. ES256 leads
#: because it is the one algorithm every FIDO2 authenticator implements.
SUPPORTED_ALGORITHMS: tuple[int, ...] = (COSE_ALG_ES256, COSE_ALG_EDDSA, COSE_ALG_RS256)

# COSE key common parameters and per-type labels.
_COSE_KTY = 1
_COSE_ALG = 3
_COSE_KTY_OKP = 1
_COSE_KTY_EC2 = 2
_COSE_KTY_RSA = 3
_COSE_CRV = -1
_COSE_EC2_X = -2
_COSE_EC2_Y = -3
_COSE_OKP_X = -2
_COSE_RSA_N = -1
_COSE_RSA_E = -2
_COSE_CRV_P256 = 1
_COSE_CRV_ED25519 = 6

# Authenticator data flag bits (WebAuthn Level 3, section 6.1).
_FLAG_UP = 0b0000_0001  # user present
_FLAG_UV = 0b0000_0100  # user verified
_FLAG_BE = 0b0000_1000  # backup eligible
_FLAG_BS = 0b0001_0000  # backup state
_FLAG_AT = 0b0100_0000  # attested credential data included
_FLAG_ED = 0b1000_0000  # extension data included

_AUTH_DATA_HEADER_BYTES = 37  # rpIdHash(32) + flags(1) + signCount(4)
_AAGUID_BYTES = 16

#: A credential ID may be up to 1023 bytes (CTAP2). Anything longer is refused
#: before it can be stored.
MAX_CREDENTIAL_ID_BYTES = 1023

#: Ceiling on the raw client data we will parse. Real ceremonies produce a few
#: hundred bytes; this only stops an unbounded JSON parse.
_MAX_CLIENT_DATA_BYTES = 8 * 1024

CHALLENGE_BYTES = 32


class WebAuthnError(ValueError):
    """A WebAuthn ceremony failed verification.

    ``code`` is a stable, non-secret string safe to audit and to return to a
    caller. It names the rule that refused the ceremony, never the value that
    failed it.
    """

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class RegistrationResult:
    """Everything the caller must persist about a newly registered credential."""

    credential_id: bytes
    public_key_cose: bytes
    algorithm: int
    sign_count: int
    aaguid: bytes
    user_verified: bool
    backup_eligible: bool
    backup_state: bool
    attestation_format: str


@dataclass(frozen=True)
class AssertionResult:
    """The facts an accepted assertion establishes about the authenticator."""

    sign_count: int
    user_verified: bool
    backup_state: bool


@dataclass(frozen=True)
class _AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None
    credential_id: bytes | None
    credential_public_key: bytes | None

    @property
    def user_present(self) -> bool:
        return bool(self.flags & _FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & _FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & _FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & _FLAG_BS)


# --------------------------------------------------------------------------- #
# base64url helpers
# --------------------------------------------------------------------------- #
def b64url_encode(raw: bytes) -> str:
    """Encode without padding, the form WebAuthn JSON uses throughout."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url, refusing anything outside the alphabet.

    Python's decoder is lenient by default and silently ignores characters
    outside the alphabet, which would let two different strings decode to the
    same bytes and make a strict equality check upstream meaningless. The
    explicit alphabet check below closes that.
    """
    if not isinstance(value, str):
        raise WebAuthnError("malformed_base64url", "expected a base64url string")
    stripped = value.strip()
    if not stripped or len(stripped) % 4 == 1:
        raise WebAuthnError("malformed_base64url", "invalid base64url value")
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    if not set(stripped) <= allowed:
        raise WebAuthnError("malformed_base64url", "invalid base64url value")
    padding_needed = (-len(stripped)) % 4
    try:
        return base64.urlsafe_b64decode(stripped + "=" * padding_needed)
    except (binascii.Error, ValueError) as exc:
        raise WebAuthnError("malformed_base64url", "invalid base64url value") from exc


def generate_challenge() -> bytes:
    """A fresh, unpredictable challenge. Single-use enforcement is the caller's."""
    return secrets.token_bytes(CHALLENGE_BYTES)


# --------------------------------------------------------------------------- #
# clientDataJSON
# --------------------------------------------------------------------------- #
def _verify_client_data(
    client_data_json: bytes,
    *,
    expected_type: str,
    expected_challenge: bytes,
    expected_origins: frozenset[str],
) -> None:
    if len(client_data_json) > _MAX_CLIENT_DATA_BYTES:
        raise WebAuthnError("client_data_too_large")
    try:
        client_data = json.loads(client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnError("malformed_client_data") from exc
    if not isinstance(client_data, dict):
        raise WebAuthnError("malformed_client_data")

    if client_data.get("type") != expected_type:
        # A registration response replayed into the login ceremony (or the
        # reverse) is refused here: the authenticator signs the type, so the two
        # ceremonies cannot be substituted for one another.
        raise WebAuthnError("client_data_type_mismatch")

    challenge = client_data.get("challenge")
    if not isinstance(challenge, str):
        raise WebAuthnError("malformed_client_data")
    if not secrets.compare_digest(b64url_decode(challenge), expected_challenge):
        raise WebAuthnError("challenge_mismatch")

    origin = client_data.get("origin")
    if not isinstance(origin, str) or origin not in expected_origins:
        raise WebAuthnError("origin_mismatch")

    # An unset crossOrigin means same-origin. Only an explicit true is a
    # cross-origin ceremony, which we do not accept: the RP page is the only
    # context allowed to authenticate an operator.
    if client_data.get("crossOrigin") is True:
        raise WebAuthnError("cross_origin_not_allowed")


# --------------------------------------------------------------------------- #
# authenticatorData
# --------------------------------------------------------------------------- #
def _parse_authenticator_data(raw: bytes) -> _AuthenticatorData:
    if len(raw) < _AUTH_DATA_HEADER_BYTES:
        raise WebAuthnError("malformed_authenticator_data")

    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = int.from_bytes(raw[33:37], "big")
    rest = raw[_AUTH_DATA_HEADER_BYTES:]

    aaguid: bytes | None = None
    credential_id: bytes | None = None
    credential_public_key: bytes | None = None

    if flags & _FLAG_AT:
        if len(rest) < _AAGUID_BYTES + 2:
            raise WebAuthnError("malformed_authenticator_data")
        aaguid = rest[:_AAGUID_BYTES]
        id_length = int.from_bytes(rest[_AAGUID_BYTES : _AAGUID_BYTES + 2], "big")
        if id_length == 0 or id_length > MAX_CREDENTIAL_ID_BYTES:
            raise WebAuthnError("invalid_credential_id")
        offset = _AAGUID_BYTES + 2
        if len(rest) < offset + id_length:
            raise WebAuthnError("malformed_authenticator_data")
        credential_id = rest[offset : offset + id_length]
        remainder = rest[offset + id_length :]
        # The COSE key has no length prefix and may be followed by extension
        # outputs, so decode a prefix and keep the exact bytes it consumed --
        # re-encoding could change them and invalidate stored keys.
        try:
            _, consumed = decode_prefix(remainder)
        except CBORDecodeError as exc:
            raise WebAuthnError("malformed_credential_public_key") from exc
        credential_public_key = remainder[:consumed]
        rest = remainder[consumed:]

    if flags & _FLAG_ED:
        try:
            _, consumed = decode_prefix(rest)
        except CBORDecodeError as exc:
            raise WebAuthnError("malformed_extension_data") from exc
        rest = rest[consumed:]

    if rest:
        raise WebAuthnError("malformed_authenticator_data")

    return _AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key=credential_public_key,
    )


def _check_authenticator_data(
    auth_data: _AuthenticatorData,
    *,
    expected_rp_id: str,
    require_user_verification: bool,
) -> None:
    expected_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
    if not secrets.compare_digest(auth_data.rp_id_hash, expected_hash):
        raise WebAuthnError("rp_id_mismatch")
    if not auth_data.user_present:
        raise WebAuthnError("user_presence_required")
    if require_user_verification and not auth_data.user_verified:
        raise WebAuthnError("user_verification_required")


# --------------------------------------------------------------------------- #
# COSE public keys
# --------------------------------------------------------------------------- #
def _int_from_cose(value: object, label: str) -> int:
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise WebAuthnError("malformed_credential_public_key", label)
    return int.from_bytes(bytes(value), "big")


def _decode_cose_key(public_key_cose: bytes) -> dict:
    try:
        key = decode(public_key_cose)
    except CBORDecodeError as exc:
        raise WebAuthnError("malformed_credential_public_key") from exc
    if not isinstance(key, dict):
        raise WebAuthnError("malformed_credential_public_key")
    return key


def load_cose_key(public_key_cose: bytes):
    """Return a ``cryptography`` public key for a supported COSE key.

    Refusing unsupported curves and key types here (rather than at signature
    time) is what keeps an unverifiable credential out of the database.
    """
    key = _decode_cose_key(public_key_cose)
    kty = key.get(_COSE_KTY)
    algorithm = key.get(_COSE_ALG)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise WebAuthnError("unsupported_algorithm")

    if kty == _COSE_KTY_EC2 and algorithm == COSE_ALG_ES256:
        if key.get(_COSE_CRV) != _COSE_CRV_P256:
            raise WebAuthnError("unsupported_curve")
        x = key.get(_COSE_EC2_X)
        y = key.get(_COSE_EC2_Y)
        # P-256 coordinates are fixed-width; a short or long value would be a
        # different point encoding than the one the authenticator signed under.
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnError("malformed_credential_public_key")
        if len(x) != 32 or len(y) != 32:
            raise WebAuthnError("malformed_credential_public_key")
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:
            raise WebAuthnError("invalid_public_key") from exc

    if kty == _COSE_KTY_OKP and algorithm == COSE_ALG_EDDSA:
        if key.get(_COSE_CRV) != _COSE_CRV_ED25519:
            raise WebAuthnError("unsupported_curve")
        x = key.get(_COSE_OKP_X)
        if not isinstance(x, bytes) or len(x) != 32:
            raise WebAuthnError("malformed_credential_public_key")
        try:
            return Ed25519PublicKey.from_public_bytes(x)
        except ValueError as exc:
            raise WebAuthnError("invalid_public_key") from exc

    if kty == _COSE_KTY_RSA and algorithm == COSE_ALG_RS256:
        modulus = _int_from_cose(key.get(_COSE_RSA_N), "n")
        exponent = _int_from_cose(key.get(_COSE_RSA_E), "e")
        if modulus.bit_length() < 2048:
            raise WebAuthnError("weak_public_key")
        try:
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()
        except ValueError as exc:
            raise WebAuthnError("invalid_public_key") from exc

    raise WebAuthnError("unsupported_key_type")


def cose_algorithm(public_key_cose: bytes) -> int:
    """Return the COSE algorithm of an already-validated key."""
    algorithm = _decode_cose_key(public_key_cose).get(_COSE_ALG)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise WebAuthnError("unsupported_algorithm")
    return int(algorithm)


def _verify_signature(public_key, algorithm: int, signature: bytes, signed: bytes) -> None:
    try:
        if algorithm == COSE_ALG_ES256:
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif algorithm == COSE_ALG_EDDSA:
            public_key.verify(signature, signed)
        elif algorithm == COSE_ALG_RS256:
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("unsupported_algorithm")
    except InvalidSignature as exc:
        raise WebAuthnError("invalid_signature") from exc


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def verify_registration(
    *,
    client_data_json: bytes,
    attestation_object: bytes,
    expected_challenge: bytes,
    expected_origins: frozenset[str],
    expected_rp_id: str,
    require_user_verification: bool = True,
) -> RegistrationResult:
    """Verify a ``navigator.credentials.create()`` response.

    Returns the credential facts to persist. Raises :class:`WebAuthnError` with
    a coded reason on any failure -- the caller is expected to audit the code and
    return a generic message.
    """
    _verify_client_data(
        client_data_json,
        expected_type="webauthn.create",
        expected_challenge=expected_challenge,
        expected_origins=expected_origins,
    )

    try:
        attestation = decode(attestation_object)
    except CBORDecodeError as exc:
        raise WebAuthnError("malformed_attestation_object") from exc
    if not isinstance(attestation, dict):
        raise WebAuthnError("malformed_attestation_object")

    fmt = attestation.get("fmt")
    raw_auth_data = attestation.get("authData")
    att_stmt = attestation.get("attStmt")
    if not isinstance(fmt, str) or not isinstance(raw_auth_data, (bytes, bytearray)):
        raise WebAuthnError("malformed_attestation_object")
    if not isinstance(att_stmt, dict):
        raise WebAuthnError("malformed_attestation_object")

    auth_data = _parse_authenticator_data(bytes(raw_auth_data))
    _check_authenticator_data(
        auth_data,
        expected_rp_id=expected_rp_id,
        require_user_verification=require_user_verification,
    )

    if auth_data.credential_id is None or auth_data.credential_public_key is None:
        raise WebAuthnError("attested_credential_data_missing")

    # Validate the key before any attestation work, so an unusable key is
    # refused by the cheapest check rather than by a signature failure.
    public_key = load_cose_key(auth_data.credential_public_key)
    algorithm = cose_algorithm(auth_data.credential_public_key)

    client_data_hash = hashlib.sha256(client_data_json).digest()
    _verify_attestation(
        fmt,
        att_stmt,
        raw_auth_data=bytes(raw_auth_data),
        client_data_hash=client_data_hash,
        public_key=public_key,
        algorithm=algorithm,
    )

    return RegistrationResult(
        credential_id=auth_data.credential_id,
        public_key_cose=auth_data.credential_public_key,
        algorithm=algorithm,
        sign_count=auth_data.sign_count,
        aaguid=auth_data.aaguid or b"\x00" * _AAGUID_BYTES,
        user_verified=auth_data.user_verified,
        backup_eligible=auth_data.backup_eligible,
        backup_state=auth_data.backup_state,
        attestation_format=fmt,
    )


def _verify_attestation(
    fmt: str,
    att_stmt: dict,
    *,
    raw_auth_data: bytes,
    client_data_hash: bytes,
    public_key,
    algorithm: int,
) -> None:
    """Apply the narrow attestation policy this module documents.

    ``none`` carries no statement to check. ``packed`` self-attestation is
    signed by the credential key itself, which we already hold, so verifying it
    is free and strictly better than ignoring it. ``packed`` with an ``x5c``
    chain would require a trusted attestation root we deliberately do not
    operate, so rather than accept a chain we cannot evaluate, we refuse it.
    """
    if fmt == "none":
        if att_stmt:
            raise WebAuthnError("unexpected_attestation_statement")
        return

    if fmt == "packed":
        if "x5c" in att_stmt or "ecdaaKeyId" in att_stmt:
            raise WebAuthnError("unsupported_attestation_format")
        statement_alg = att_stmt.get("alg")
        signature = att_stmt.get("sig")
        if statement_alg != algorithm:
            raise WebAuthnError("attestation_algorithm_mismatch")
        if not isinstance(signature, (bytes, bytearray)):
            raise WebAuthnError("malformed_attestation_statement")
        _verify_signature(
            public_key, algorithm, bytes(signature), raw_auth_data + client_data_hash
        )
        return

    raise WebAuthnError("unsupported_attestation_format")


# --------------------------------------------------------------------------- #
# Assertion
# --------------------------------------------------------------------------- #
def verify_assertion(
    *,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    expected_challenge: bytes,
    expected_origins: frozenset[str],
    expected_rp_id: str,
    credential_public_key_cose: bytes,
    stored_sign_count: int,
    require_user_verification: bool = True,
) -> AssertionResult:
    """Verify a ``navigator.credentials.get()`` response for a known credential.

    The caller must have already resolved ``credential_public_key_cose`` from
    the presented credential ID and confirmed the credential belongs to the
    operator being authenticated; this function does not know about operators.
    """
    _verify_client_data(
        client_data_json,
        expected_type="webauthn.get",
        expected_challenge=expected_challenge,
        expected_origins=expected_origins,
    )

    auth_data = _parse_authenticator_data(authenticator_data)
    _check_authenticator_data(
        auth_data,
        expected_rp_id=expected_rp_id,
        require_user_verification=require_user_verification,
    )
    # An assertion must not carry attested credential data; that shape belongs
    # to registration and accepting it here would blur the two ceremonies.
    if auth_data.credential_id is not None:
        raise WebAuthnError("unexpected_attested_credential_data")

    public_key = load_cose_key(credential_public_key_cose)
    algorithm = cose_algorithm(credential_public_key_cose)
    client_data_hash = hashlib.sha256(client_data_json).digest()
    _verify_signature(
        public_key, algorithm, signature, authenticator_data + client_data_hash
    )

    # Signature-counter cloning check. An authenticator that implements a
    # counter must strictly increase it; one that does not (many platform
    # authenticators, and all synced passkeys) reports 0 forever. So a reported
    # 0 means "no counter, nothing to check", and any non-zero value must beat
    # what we stored. A stale or equal non-zero counter is evidence of a cloned
    # credential and fails closed.
    if auth_data.sign_count != 0 and auth_data.sign_count <= stored_sign_count:
        raise WebAuthnError("sign_count_regressed")

    return AssertionResult(
        sign_count=auth_data.sign_count,
        user_verified=auth_data.user_verified,
        backup_state=auth_data.backup_state,
    )
