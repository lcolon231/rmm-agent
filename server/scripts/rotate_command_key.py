# SPDX-License-Identifier: AGPL-3.0-only
"""Operator tool for the command-signing key registry.

Manages the JSON registry that `app/core/keyring.py` loads (the file named by
COMMAND_SIGNING_KEYRING_PATH). Private keys live on disk beside the registry,
never in the database. Every mutation is written atomically and appended to a
tamper-evident-ish rotation journal (`<registry>.rotation.log`, append-only
JSON lines) so the sequence of activations, overlaps, and retirements is
auditable after the fact.

Key states (see the runbook, docs/KEY-ROTATION.md):
  active   — the one key new commands are signed with (exactly one)
  overlap  — still trusted by agents (its public key is in the bundle) but no
             longer used for signing; the safe landing state for both the
             outgoing key during a rotation and a freshly generated key before
             it is promoted
  retired  — no longer trusted; dropped from the agent bundle

Rotation is staged so a mixed fleet never rejects a valid command:
  1. generate NEW as overlap        -> agents learn NEW's public key
  2. (wait for the fleet to beat)
  3. activate NEW                    -> OLD becomes overlap, NEW signs
  4. (wait until no in-flight command was signed by OLD)
  5. retire OLD                      -> OLD leaves the bundle

Compromise response is the same minus the waiting: generate + activate + retire
the compromised key immediately, accepting that commands it signed and still
in flight will be refused (which is the point).

Commands (all take --registry PATH and --operator WHO):
  init         --active-id ID --private KEY.pem [--public PUB.pem]
  generate     --key-id ID [--dir DIR]            # new Ed25519 key, added overlap
  add          --key-id ID --private KEY.pem [--public PUB.pem]   # register existing
  activate     --key-id ID                        # promote to active
  retire       --key-id ID                        # drop from the bundle
  status                                           # print redacted state

Exit code 0 on success; non-zero (with a message) on any invariant violation —
the registry is never left in a state keyring.load_keyring() would reject.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


class RotationError(RuntimeError):
    pass


def _validate_id(key_id: str) -> None:
    if not _ID_RE.fullmatch(key_id):
        raise RotationError(f"invalid key id {key_id!r} (allowed: A-Za-z0-9._- up to 64)")


def _load(registry: Path) -> dict:
    if not registry.exists():
        raise RotationError(f"registry {registry} does not exist; run 'init' first")
    doc = json.loads(registry.read_text(encoding="utf-8"))
    if not isinstance(doc.get("active_key_id"), str) or not isinstance(doc.get("keys"), dict):
        raise RotationError("registry is malformed (need active_key_id and keys)")
    return doc


def _validate_invariants(doc: dict) -> None:
    """Reject any state keyring.load_keyring() would reject, plus the
    single-active rule, before we ever write it out."""
    active_id = doc["active_key_id"]
    keys = doc["keys"]
    _validate_id(active_id)
    actives = [k for k, v in keys.items() if v.get("status") == "active"]
    if len(actives) != 1:
        raise RotationError(f"exactly one active key required, found {len(actives)}: {actives}")
    if active_id not in keys or keys[active_id].get("status") != "active":
        raise RotationError("active_key_id must reference the active key")
    for key_id, item in keys.items():
        _validate_id(key_id)
        if item.get("status") not in {"active", "overlap", "retired"}:
            raise RotationError(f"invalid status for {key_id!r}: {item.get('status')!r}")
        if not item.get("private_key_path") and not item.get("public_key_path"):
            raise RotationError(f"key {key_id!r} has no key material path")


def _write_atomic(registry: Path, doc: dict) -> None:
    _validate_invariants(doc)
    registry.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=registry.parent, prefix=".registry-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, registry)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _journal(registry: Path, operator: str, action: str, detail: dict) -> None:
    """Append one JSON line recording the mutation. Best-effort ordering
    evidence for an offline operation; the DB audit chain covers online acts."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "operator": operator,
        "action": action,
        **detail,
    }
    log = registry.with_suffix(registry.suffix + ".rotation.log")
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _generate_keypair(key_id: str, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / f"command_signing_key_{key_id}.pem"
    pub_path = directory / f"command_public_key_{key_id}.pem"
    if priv_path.exists():
        raise RotationError(f"{priv_path} already exists — refusing to overwrite")
    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def _entry(private: str | None, public: str | None, status: str) -> dict:
    e: dict = {"status": status}
    if private:
        e["private_key_path"] = private
    if public:
        e["public_key_path"] = public
    return e


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_init(args) -> None:
    registry = Path(args.registry)
    if registry.exists():
        raise RotationError(f"{registry} already exists — refusing to re-init")
    _validate_id(args.active_id)
    doc = {
        "active_key_id": args.active_id,
        "keys": {args.active_id: _entry(args.private, args.public, "active")},
    }
    _write_atomic(registry, doc)
    _journal(registry, args.operator, "init", {"active_key_id": args.active_id})
    print(f"initialized {registry} with active key {args.active_id}")


def cmd_generate(args) -> None:
    registry = Path(args.registry)
    doc = _load(registry)
    if args.key_id in doc["keys"]:
        raise RotationError(f"key {args.key_id!r} already in the registry")
    directory = Path(args.dir) if args.dir else registry.parent
    priv, pub = _generate_keypair(args.key_id, directory)
    doc["keys"][args.key_id] = _entry(str(priv), str(pub), "overlap")
    _write_atomic(registry, doc)
    _journal(registry, args.operator, "generate", {"key_id": args.key_id, "status": "overlap"})
    print(f"generated {args.key_id} as overlap ({priv})")
    print("agents will trust it after their next heartbeat; then run 'activate'")


def cmd_add(args) -> None:
    registry = Path(args.registry)
    doc = _load(registry)
    if args.key_id in doc["keys"]:
        raise RotationError(f"key {args.key_id!r} already in the registry")
    doc["keys"][args.key_id] = _entry(args.private, args.public, "overlap")
    _write_atomic(registry, doc)
    _journal(registry, args.operator, "add", {"key_id": args.key_id, "status": "overlap"})
    print(f"added existing key {args.key_id} as overlap")


def cmd_activate(args) -> None:
    registry = Path(args.registry)
    doc = _load(registry)
    keys = doc["keys"]
    if args.key_id not in keys:
        raise RotationError(f"key {args.key_id!r} is not in the registry")
    if keys[args.key_id]["status"] == "retired":
        raise RotationError(f"key {args.key_id!r} is retired; generate a new key instead")
    previous_active = doc["active_key_id"]
    if previous_active == args.key_id:
        raise RotationError(f"key {args.key_id!r} is already active")
    # Old active steps down to overlap so its still-in-flight commands verify.
    keys[previous_active]["status"] = "overlap"
    keys[args.key_id]["status"] = "active"
    doc["active_key_id"] = args.key_id
    _write_atomic(registry, doc)
    _journal(registry, args.operator, "activate",
             {"key_id": args.key_id, "previous_active": previous_active})
    print(f"activated {args.key_id}; {previous_active} demoted to overlap")
    print("retire the previous key only after its in-flight commands have expired")


def cmd_retire(args) -> None:
    registry = Path(args.registry)
    doc = _load(registry)
    keys = doc["keys"]
    if args.key_id not in keys:
        raise RotationError(f"key {args.key_id!r} is not in the registry")
    if args.key_id == doc["active_key_id"]:
        raise RotationError("cannot retire the active key; activate another key first")
    keys[args.key_id]["status"] = "retired"
    _write_atomic(registry, doc)
    _journal(registry, args.operator, "retire", {"key_id": args.key_id})
    print(f"retired {args.key_id}; it is no longer in the agent trust bundle")


def cmd_status(args) -> None:
    registry = Path(args.registry)
    doc = _load(registry)
    _validate_invariants(doc)
    print(f"registry: {registry}")
    print(f"active:   {doc['active_key_id']}")
    for key_id in sorted(doc["keys"]):
        item = doc["keys"][key_id]
        marker = " (active)" if key_id == doc["active_key_id"] else ""
        print(f"  {key_id}: {item['status']}{marker}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", required=True, help="path to the registry JSON")
    parser.add_argument("--operator", default=os.getenv("USER", "unknown"),
                        help="who is running this (recorded in the rotation journal)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a registry with one active key")
    p.add_argument("--active-id", required=True)
    p.add_argument("--private")
    p.add_argument("--public")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("generate", help="generate a new Ed25519 key as overlap")
    p.add_argument("--key-id", required=True)
    p.add_argument("--dir", help="directory for the new key files (default: registry dir)")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("add", help="register an existing key as overlap")
    p.add_argument("--key-id", required=True)
    p.add_argument("--private")
    p.add_argument("--public")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("activate", help="promote a key to active")
    p.add_argument("--key-id", required=True)
    p.set_defaults(func=cmd_activate)

    p = sub.add_parser("retire", help="drop a key from the trust bundle")
    p.add_argument("--key-id", required=True)
    p.set_defaults(func=cmd_retire)

    p = sub.add_parser("status", help="print redacted registry state")
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except RotationError as exc:
        print(f"rotate: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
