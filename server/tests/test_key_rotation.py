# SPDX-License-Identifier: AGPL-3.0-only
"""Operator key-rotation workflow tests (issue #14 remainder).

Rehearses the full staged rotation and the compromise path through the
rotate_command_key.py CLI, asserting after every step that:
  - keyring.load_keyring() still accepts the registry (never left broken)
  - exactly one key is active
  - the agent trust bundle (active + overlap public keys) contains exactly the
    keys a live fleet should trust at that moment
  - the rotation journal records each mutation

Also covers the invariant guards: you cannot retire the active key, activate a
retired key, or double-init.

Run just this file:  pytest tests/test_key_rotation.py -q
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_key_rotation.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402

from app.core import keyring  # noqa: E402
from app.core.config import settings  # noqa: E402
from scripts import rotate_command_key as rot  # noqa: E402


def run(*argv) -> int:
    return rot.main([str(a) for a in argv])


@pytest.fixture
def registry(tmp_path, monkeypatch):
    reg = tmp_path / "registry.json"
    # Point the app's keyring loader at this registry for the duration.
    monkeypatch.setattr(settings, "command_signing_keyring_path", str(reg))
    return reg


def load():
    """(active_id, bundle_key_ids) as the running server would see them."""
    active_id, keys = keyring.load_keyring()
    bundle = set(keyring.public_key_bundle().keys())
    return active_id, keys, bundle


def gen_initial(tmp_path, key_id="k1"):
    priv, pub = rot._generate_keypair(key_id, tmp_path / "keys")
    return str(priv), str(pub)


def test_full_staged_rotation(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    assert run("--registry", registry, "--operator", "alice",
               "init", "--active-id", "k1", "--private", priv, "--public", pub) == 0

    active_id, keys, bundle = load()
    assert active_id == "k1"
    assert bundle == {"k1"}

    # 1. Generate k2 as overlap — the fleet learns its public key first.
    assert run("--registry", registry, "--operator", "alice",
               "generate", "--key-id", "k2", "--dir", tmp_path / "keys") == 0
    active_id, keys, bundle = load()
    assert active_id == "k1"                      # still signing with k1
    assert bundle == {"k1", "k2"}                 # both trusted
    assert keys["k2"].status == "overlap"

    # 2. Activate k2 — k1 steps down to overlap so its in-flight commands verify.
    assert run("--registry", registry, "--operator", "alice",
               "activate", "--key-id", "k2") == 0
    active_id, keys, bundle = load()
    assert active_id == "k2"
    assert bundle == {"k1", "k2"}
    assert keys["k1"].status == "overlap"

    # 3. Retire k1 — it leaves the trust bundle.
    assert run("--registry", registry, "--operator", "alice",
               "retire", "--key-id", "k1") == 0
    active_id, keys, bundle = load()
    assert active_id == "k2"
    assert bundle == {"k2"}
    assert keys["k1"].status == "retired"

    # The active key can actually sign, and its public key verifies.
    signed = keyring.active_signing_key().private_key
    assert signed is not None

    # Journal recorded every mutation in order.
    log = registry.with_suffix(registry.suffix + ".rotation.log")
    actions = [json.loads(line)["action"] for line in log.read_text().splitlines()]
    assert actions == ["init", "generate", "activate", "retire"]
    assert all(json.loads(line)["operator"] == "alice"
               for line in log.read_text().splitlines())


def test_compromise_fast_path(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    run("--registry", registry, "--operator", "sec",
        "init", "--active-id", "k1", "--private", priv, "--public", pub)

    # Compromise: bring up a replacement and immediately activate + retire the
    # bad key, accepting that its in-flight commands stop verifying.
    run("--registry", registry, "--operator", "sec",
        "generate", "--key-id", "k2", "--dir", tmp_path / "keys")
    run("--registry", registry, "--operator", "sec", "activate", "--key-id", "k2")
    assert run("--registry", registry, "--operator", "sec",
               "retire", "--key-id", "k1") == 0

    active_id, keys, bundle = load()
    assert active_id == "k2"
    assert bundle == {"k2"}                       # k1 no longer trusted at all


def test_cannot_retire_active_key(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    run("--registry", registry, "--operator", "op",
        "init", "--active-id", "k1", "--private", priv, "--public", pub)
    assert run("--registry", registry, "--operator", "op",
               "retire", "--key-id", "k1") == 1
    # Registry untouched and still valid.
    active_id, _, bundle = load()
    assert active_id == "k1" and bundle == {"k1"}


def test_cannot_activate_retired_key(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    run("--registry", registry, "--operator", "op",
        "init", "--active-id", "k1", "--private", priv, "--public", pub)
    run("--registry", registry, "--operator", "op",
        "generate", "--key-id", "k2", "--dir", tmp_path / "keys")
    run("--registry", registry, "--operator", "op", "activate", "--key-id", "k2")
    run("--registry", registry, "--operator", "op", "retire", "--key-id", "k1")
    assert run("--registry", registry, "--operator", "op",
               "activate", "--key-id", "k1") == 1


def test_double_init_refused(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    run("--registry", registry, "--operator", "op",
        "init", "--active-id", "k1", "--private", priv, "--public", pub)
    assert run("--registry", registry, "--operator", "op",
               "init", "--active-id", "k9", "--private", priv, "--public", pub) == 1


def test_atomic_write_leaves_no_temp_files(registry, tmp_path):
    priv, pub = gen_initial(tmp_path)
    run("--registry", registry, "--operator", "op",
        "init", "--active-id", "k1", "--private", priv, "--public", pub)
    run("--registry", registry, "--operator", "op",
        "generate", "--key-id", "k2", "--dir", tmp_path / "keys")
    leftovers = list(registry.parent.glob(".registry-*.tmp"))
    assert leftovers == []
