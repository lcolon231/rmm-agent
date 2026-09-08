# SPDX-License-Identifier: AGPL-3.0-only
"""A software WebAuthn authenticator for tests (issue #67).

The verification code under test only ever sees bytes, so the honest way to test
it is to produce those bytes the way a real authenticator does: build the
authenticator data, hash the real ``clientDataJSON``, and sign the concatenation
with a real key. Every assertion in the MFA tests is therefore a genuine ES256
(or Ed25519) signature, and a negative test is negative because the
cryptography actually fails, not because a stub returned False.

This deliberately includes a small CBOR *encoder*: the decoder in
``app.core.cbor`` is the code under test, so the test fixture must not reuse it
to build its inputs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FLAG_UP = 0b0000_0001
FLAG_UV = 0b0000_0100
FLAG_BE = 0b0000_1000
FLAG_BS = 0b0001_0000
FLAG_AT = 0b0100_0000
FLAG_ED = 0b1000_0000

COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))


# --------------------------------------------------------------------------- #
# Minimal CBOR encoder (canonical enough for the structures we emit)
# --------------------------------------------------------------------------- #
def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument < 0x100:
        return bytes([(major << 5) | 24, argument])
    if argument < 0x10000:
        return bytes([(major << 5) | 25]) + argument.to_bytes(2, "big")
    if argument < 0x100000000:
        return bytes([(major << 5) | 26]) + argument.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + argument.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return bytes([0xF6])
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        # CTAP2 canonical ordering: ints before strings, shorter keys first.
        def sort_key(item):
            key = item[0]
            encoded = cbor_encode(key)
            return (len(encoded), encoded)

        items = sorted(value.items(), key=sort_key)
        return _head(5, len(items)) + b"".join(
            cbor_encode(k) + cbor_encode(v) for k, v in items
        )
    raise TypeError(f"cannot CBOR-encode {type(value)!r}")


# --------------------------------------------------------------------------- #
# Software authenticator
# --------------------------------------------------------------------------- #
@dataclass
class SoftwareAuthenticator:
    """One virtual authenticator holding one credential."""

    rp_id: str
    origin: str
    algorithm: int = COSE_ALG_ES256
    aaguid: bytes = b"\x00" * 16
    sign_count: int = 0
    #: When False the authenticator reports "user present" but not "verified",
    #: which the server refuses wherever user verification is required.
    user_verified: bool = True
    backup_eligible: bool = False
    backup_state: bool = False
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    _private_key: object = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.algorithm == COSE_ALG_ES256:
            self._private_key = ec.generate_private_key(ec.SECP256R1())
        elif self.algorithm == COSE_ALG_EDDSA:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"unsupported test algorithm {self.algorithm}")

    # -- key encoding ------------------------------------------------------- #
    def cose_public_key(self) -> bytes:
        public_key = self._private_key.public_key()
        if self.algorithm == COSE_ALG_ES256:
            numbers = public_key.public_numbers()
            return cbor_encode(
                {
                    1: 2,  # kty: EC2
                    3: COSE_ALG_ES256,
                    -1: 1,  # crv: P-256
                    -2: numbers.x.to_bytes(32, "big"),
                    -3: numbers.y.to_bytes(32, "big"),
                }
            )
        from cryptography.hazmat.primitives import serialization

        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cbor_encode({1: 1, 3: COSE_ALG_EDDSA, -1: 6, -2: raw})

    def _sign(self, message: bytes) -> bytes:
        if self.algorithm == COSE_ALG_ES256:
            return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return self._private_key.sign(message)

    # -- ceremony pieces ---------------------------------------------------- #
    def _flags(self, *, attested: bool) -> int:
        flags = FLAG_UP
        if self.user_verified:
            flags |= FLAG_UV
        if self.backup_eligible:
            flags |= FLAG_BE
        if self.backup_state:
            flags |= FLAG_BS
        if attested:
            flags |= FLAG_AT
        return flags

    def _authenticator_data(
        self,
        *,
        attested: bool,
        rp_id: str | None = None,
        sign_count: int | None = None,
        flags: int | None = None,
    ) -> bytes:
        effective_rp_id = self.rp_id if rp_id is None else rp_id
        effective_count = self.sign_count if sign_count is None else sign_count
        effective_flags = self._flags(attested=attested) if flags is None else flags
        data = hashlib.sha256(effective_rp_id.encode("utf-8")).digest()
        data += bytes([effective_flags])
        data += effective_count.to_bytes(4, "big")
        if attested:
            public_key = self.cose_public_key()
            data += self.aaguid
            data += len(self.credential_id).to_bytes(2, "big")
            data += self.credential_id
            data += public_key
        return data

    def client_data(
        self,
        *,
        ceremony_type: str,
        challenge: bytes,
        origin: str | None = None,
        cross_origin: bool | None = None,
    ) -> bytes:
        payload = {
            "type": ceremony_type,
            "challenge": b64url(challenge),
            "origin": self.origin if origin is None else origin,
        }
        if cross_origin is not None:
            payload["crossOrigin"] = cross_origin
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # -- registration ------------------------------------------------------- #
    def register(
        self,
        challenge: bytes,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        attestation_format: str = "none",
        cross_origin: bool | None = None,
        flags: int | None = None,
    ) -> dict:
        client_data_json = self.client_data(
            ceremony_type="webauthn.create",
            challenge=challenge,
            origin=origin,
            cross_origin=cross_origin,
        )
        auth_data = self._authenticator_data(
            attested=True, rp_id=rp_id, flags=flags
        )

        att_stmt: dict = {}
        if attestation_format == "packed":
            client_data_hash = hashlib.sha256(client_data_json).digest()
            att_stmt = {
                "alg": self.algorithm,
                "sig": self._sign(auth_data + client_data_hash),
            }

        attestation_object = cbor_encode(
            {"fmt": attestation_format, "attStmt": att_stmt, "authData": auth_data}
        )
        return {
            "id": b64url(self.credential_id),
            "raw_client_data_json": client_data_json,
            "client_data_json": b64url(client_data_json),
            "attestation_object": b64url(attestation_object),
            "raw_attestation_object": attestation_object,
        }

    # -- assertion ---------------------------------------------------------- #
    def assert_(
        self,
        challenge: bytes,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        sign_count: int | None = None,
        cross_origin: bool | None = None,
        ceremony_type: str = "webauthn.get",
        flags: int | None = None,
        corrupt_signature: bool = False,
        attested: bool = False,
    ) -> dict:
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        client_data_json = self.client_data(
            ceremony_type=ceremony_type,
            challenge=challenge,
            origin=origin,
            cross_origin=cross_origin,
        )
        auth_data = self._authenticator_data(
            attested=attested, rp_id=rp_id, sign_count=sign_count, flags=flags
        )
        client_data_hash = hashlib.sha256(client_data_json).digest()
        signature = self._sign(auth_data + client_data_hash)
        if corrupt_signature:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        return {
            "id": b64url(self.credential_id),
            "raw_client_data_json": client_data_json,
            "client_data_json": b64url(client_data_json),
            "authenticator_data": b64url(auth_data),
            "raw_authenticator_data": auth_data,
            "signature": b64url(signature),
            "raw_signature": signature,
        }
