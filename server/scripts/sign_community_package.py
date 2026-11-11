# SPDX-License-Identifier: AGPL-3.0-only
"""Offline publisher tooling for signed community script packages (issue #74).

Runs on the publisher's machine with only ``cryptography`` installed; it never
talks to a server. The canonical encoding below must stay byte-identical to
``app.core.community_packages.canonical_manifest_bytes`` (a parity test pins it).

    python sign_community_package.py keygen --out acme-2026
    python sign_community_package.py sign --key acme-2026.key --key-id acme-2026 \
        --publisher acme --name disk-cleanup --version 1.0.0 --language powershell \
        --platform windows --capability filesystem.write --script cleanup.ps1 \
        --out submission.json

The resulting JSON is the body of ``POST /api/v1/community/submissions``.
Register ``<out>.pub`` with an admin before submitting.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MANIFEST_SCHEMA = "nodelink.community-package/v1"
SIGNING_CONTEXT = b"nodelink-community-package:v1\n"
RUN_CAPABILITY = {"powershell": "script.run.powershell", "shell": "script.run.shell"}


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return SIGNING_CONTEXT + json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_content(value: str) -> str:
    """Mirror of the server's line-ending/whitespace normalization."""
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def build_manifest(
    *,
    publisher: str,
    name: str,
    version: str,
    language: str,
    content: str,
    platforms: list[str],
    capabilities: list[str],
    description: str | None = None,
    tags: list[str] | None = None,
    parameters: list[dict] | None = None,
) -> dict:
    encoded = content.encode("utf-8")
    declared = set(capabilities) | {RUN_CAPABILITY[language]}
    declared |= {f"platform.{item}" for item in platforms}
    return {
        "schema": MANIFEST_SCHEMA,
        "publisher": publisher,
        "name": name,
        "version": version,
        "language": language,
        "content_sha256": hashlib.sha256(encoded).hexdigest(),
        "content_bytes": len(encoded),
        "description": description,
        "tags": sorted({item.strip().lower() for item in tags or []}),
        "supported_platforms": sorted(set(platforms)),
        "capabilities": sorted(declared),
        "parameters": parameters or [],
    }


def sign_manifest(private_key: Ed25519PrivateKey, manifest: dict) -> str:
    return base64.b64encode(private_key.sign(canonical_manifest_bytes(manifest))).decode(
        "ascii"
    )


def _keygen(args: argparse.Namespace) -> int:
    key = Ed25519PrivateKey.generate()
    out = Path(args.out)
    out.with_suffix(".key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    out.with_suffix(".pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"wrote {out.with_suffix('.key')} (keep private) and {out.with_suffix('.pub')}")
    return 0


def _sign(args: argparse.Namespace) -> int:
    key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("signing key must be Ed25519", file=sys.stderr)
        return 2
    content = canonical_content(Path(args.script).read_text(encoding="utf-8"))
    parameters = json.loads(Path(args.parameters).read_text()) if args.parameters else []
    manifest = build_manifest(
        publisher=args.publisher,
        name=args.name,
        version=args.version,
        language=args.language,
        content=content,
        platforms=args.platform,
        capabilities=args.capability or [],
        description=args.description,
        tags=args.tag,
        parameters=parameters,
    )
    submission = {
        "manifest": manifest,
        "content": content,
        "key_id": args.key_id,
        "signature": sign_manifest(key, manifest),
    }
    Path(args.out).write_text(json.dumps(submission, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()
    print(f"wrote {args.out}; manifest sha256 {digest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="generate an Ed25519 publisher keypair")
    keygen.add_argument("--out", required=True, help="path prefix for .key/.pub")
    keygen.set_defaults(func=_keygen)
    sign = sub.add_parser("sign", help="build and sign a submission")
    sign.add_argument("--key", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--publisher", required=True)
    sign.add_argument("--name", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--language", required=True, choices=sorted(RUN_CAPABILITY))
    sign.add_argument("--platform", required=True, action="append",
                      choices=["windows", "linux", "macos"])
    sign.add_argument("--capability", action="append")
    sign.add_argument("--tag", action="append")
    sign.add_argument("--description")
    sign.add_argument("--parameters", help="JSON file with parameter definitions")
    sign.add_argument("--script", required=True)
    sign.add_argument("--out", required=True)
    sign.set_defaults(func=_sign)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
