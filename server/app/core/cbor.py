# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal, strict CBOR decoder for WebAuthn structures (issue #67).

WebAuthn carries two CBOR blobs: the registration ``attestationObject`` and the
COSE public key embedded in its attested credential data. Decoding them is the
only reason this module exists, so it deliberately implements a *subset* of
RFC 8949 and rejects everything else rather than growing toward a general
codec.

Why hand-rolled instead of a dependency: the server's dependency set is pinned
and audited (``requirements.txt``), and the available CBOR-carrying WebAuthn
libraries pull a newer ``cryptography`` plus ``pyOpenSSL`` into a lock set whose
Ed25519 command signing is already qualified at the pinned version. Decoding a
handful of well-specified CBOR major types is a much smaller, more reviewable
change than moving that signing dependency.

Fail-closed decisions, all of which matter because the input is attacker-
supplied:

* **Definite lengths only.** Indefinite-length strings, arrays, and maps are
  rejected. WebAuthn requires CTAP2 canonical CBOR, which forbids them, and
  streaming forms are where length-confusion bugs live.
* **Bounded work.** Nesting depth and collection sizes are capped before any
  allocation, so a small input cannot ask for a large allocation.
* **No trailing data.** :func:`decode` requires the item to consume the whole
  buffer; :func:`decode_prefix` is the explicit opt-in for the one caller that
  legitimately decodes a COSE key followed by extension bytes.
* **No duplicate map keys.** A duplicate is a parser-differential primitive:
  two implementations can disagree about which value wins.
* **Unsupported majors are errors.** Tags (major 6) and floats carry no meaning
  in these structures, so accepting them would only widen the input surface.
"""
from __future__ import annotations

from typing import Any

# Bounds. These are far above anything a real authenticator emits (a COSE P-256
# key is ~77 bytes and nests one level; an attestation object nests three) and
# far below anything that could exhaust memory.
_MAX_DEPTH = 16
_MAX_ITEMS = 1024
_MAX_STRING_BYTES = 64 * 1024


class CBORDecodeError(ValueError):
    """The input is not CBOR this decoder accepts."""


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def position(self) -> int:
        return self._pos

    def _take(self, count: int) -> bytes:
        if count < 0 or self._pos + count > len(self._data):
            raise CBORDecodeError("truncated CBOR input")
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def _head(self) -> tuple[int, int]:
        """Return (major type, argument) for the next item head."""
        (initial,) = self._take(1)
        major = initial >> 5
        info = initial & 0x1F
        if info < 24:
            return major, info
        if info == 24:
            return major, self._take(1)[0]
        if info == 25:
            return major, int.from_bytes(self._take(2), "big")
        if info == 26:
            return major, int.from_bytes(self._take(4), "big")
        if info == 27:
            return major, int.from_bytes(self._take(8), "big")
        # 28-30 are reserved; 31 is the indefinite-length marker.
        raise CBORDecodeError(f"unsupported CBOR additional information {info}")

    def decode_item(self, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            raise CBORDecodeError("CBOR nesting too deep")

        major, argument = self._head()

        if major == 0:  # unsigned integer
            return argument
        if major == 1:  # negative integer, encoded as -1 - argument
            return -1 - argument
        if major == 2:  # byte string
            self._check_string_length(argument)
            return self._take(argument)
        if major == 3:  # text string
            self._check_string_length(argument)
            raw = self._take(argument)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORDecodeError("CBOR text string is not valid UTF-8") from exc
        if major == 4:  # array
            self._check_item_count(argument)
            return [self.decode_item(depth + 1) for _ in range(argument)]
        if major == 5:  # map
            self._check_item_count(argument)
            result: dict[Any, Any] = {}
            for _ in range(argument):
                key = self.decode_item(depth + 1)
                if not isinstance(key, (int, str, bytes)):
                    raise CBORDecodeError("CBOR map keys must be scalars")
                if key in result:
                    raise CBORDecodeError("duplicate CBOR map key")
                result[key] = self.decode_item(depth + 1)
            return result
        if major == 7:  # simple values; only the three singletons are useful
            if argument == 20:
                return False
            if argument == 21:
                return True
            if argument == 22:
                return None
            raise CBORDecodeError("unsupported CBOR simple value")

        raise CBORDecodeError(f"unsupported CBOR major type {major}")

    def _check_string_length(self, length: int) -> None:
        if length > _MAX_STRING_BYTES:
            raise CBORDecodeError("CBOR string exceeds the accepted size")

    def _check_item_count(self, count: int) -> None:
        if count > _MAX_ITEMS:
            raise CBORDecodeError("CBOR collection exceeds the accepted size")


def decode(data: bytes) -> Any:
    """Decode exactly one CBOR item that consumes all of ``data``."""
    value, consumed = decode_prefix(data)
    if consumed != len(data):
        raise CBORDecodeError("trailing bytes after CBOR item")
    return value


def decode_prefix(data: bytes) -> tuple[Any, int]:
    """Decode the leading CBOR item and report how many bytes it consumed.

    Used for the COSE public key inside attested credential data, which is
    followed by the optional extension-output map with no length prefix of its
    own — the only place where trailing bytes are legitimate.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CBORDecodeError("CBOR input must be bytes")
    decoder = _Decoder(bytes(data))
    value = decoder.decode_item()
    return value, decoder.position
