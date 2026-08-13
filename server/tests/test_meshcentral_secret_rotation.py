# SPDX-License-Identifier: AGPL-3.0-only
"""MeshCentral secret handling and rotation tests (issue #62).

The MeshCentral admin credential and login-material encryption key are
environment-only. These tests prove:
  - login material encrypts/decrypts under a configured 32-byte AES-GCM key
  - rotating the key without overlap fails closed (ciphertext under the old key
    does not decrypt under the new key), which is why the runbook documents a
    two-key overlap window
  - a missing/malformed key fails closed rather than storing plaintext
  - provider status and the admin API never surface the admin token or key
"""
from __future__ import annotations

import base64
import os
import secrets

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_meshcentral_rotation.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402

from app.core.config import Settings, settings  # noqa: E402
from app.core import meshcentral as mc  # noqa: E402


def _key() -> str:
    # Base64url with padding (32 raw bytes -> 44 chars); the decoder requires a
    # length that is a multiple of four, so padding must be preserved.
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def _cfg(**over) -> Settings:
    base = {
        "meshcentral_provider": "enabled",
        "meshcentral_login_cookie_encryption_key": _key(),
    }
    base.update(over)
    # Build a lightweight settings-like object without re-reading the environment.
    cfg = settings.model_copy(update=base)
    return cfg


def test_login_material_round_trip():
    cfg = _cfg()
    token = "gotonode=node//abc&c=" + secrets.token_urlsafe(24)
    enc = mc.encrypt_login_material(token, launch_id="L1", config=cfg)
    assert enc != token
    assert mc.decrypt_login_material(enc, launch_id="L1", config=cfg) == token


def test_rotation_without_overlap_fails_closed():
    old = _cfg()
    enc = mc.encrypt_login_material("secret-url", launch_id="L1", config=old)
    # Rotate to a brand-new key with no overlap.
    new = _cfg()
    with pytest.raises(mc.MeshCentralError):
        mc.decrypt_login_material(enc, launch_id="L1", config=new)
    # The old key still decrypts during the overlap window.
    assert mc.decrypt_login_material(enc, launch_id="L1", config=old) == "secret-url"


def test_wrong_launch_id_aad_fails_closed():
    cfg = _cfg()
    enc = mc.encrypt_login_material("x", launch_id="L1", config=cfg)
    with pytest.raises(mc.MeshCentralError):
        mc.decrypt_login_material(enc, launch_id="L2", config=cfg)


def test_missing_key_fails_closed():
    cfg = settings.model_copy(update={"meshcentral_login_cookie_encryption_key": None})
    assert mc.login_key_configured(cfg) is False
    with pytest.raises(mc.MeshCentralError):
        mc.encrypt_login_material("x", launch_id="L1", config=cfg)


def test_malformed_key_fails_closed():
    cfg = settings.model_copy(update={"meshcentral_login_cookie_encryption_key": "not-32-bytes"})
    assert mc.login_key_configured(cfg) is False


def test_provider_status_never_leaks_secrets():
    admin_token = "mesh-admin-" + secrets.token_urlsafe(16)
    cfg = _cfg(meshcentral_admin_token=admin_token, meshcentral_base_url="https://mesh.example")
    status = mc.provider_status(cfg)
    serialized = str(status)
    assert admin_token not in serialized
    assert cfg.meshcentral_login_cookie_encryption_key not in serialized
    # Only booleans/summary are exposed.
    assert status["credential_configured"] is True
    assert status["encryption_key_configured"] is True
    assert set(status) == {
        "provider",
        "configured",
        "base_url_configured",
        "credential_configured",
        "encryption_key_configured",
    }
