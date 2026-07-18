# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the Ed25519 keypair used to sign agent commands.

Usage:
    python scripts/gen_command_keys.py

Writes:
    command_signing_key.pem   (PRIVATE — keep secret, never commit)
    command_public_key.pem     (public — safe to distribute to agents)
"""
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PRIV = Path("command_signing_key.pem")
PUB = Path("command_public_key.pem")


def main() -> None:
    if PRIV.exists():
        print(f"{PRIV} already exists — refusing to overwrite.")
        return

    key = Ed25519PrivateKey.generate()
    PRIV.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PUB.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"Wrote {PRIV} (private) and {PUB} (public).")
    print("Add command_signing_key.pem to .gitignore — it must never be committed.")


if __name__ == "__main__":
    main()
