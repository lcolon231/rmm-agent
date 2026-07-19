# SPDX-License-Identifier: AGPL-3.0-only
"""Production configuration validation and proxy-trust tests (issue #17).

Covers the fail-closed startup matrix — debug mode, placeholder/short
SECRET_KEY, missing/HTTP/loopback public URL, absent signing keys — plus the
opt-in X-Forwarded-For handling used for rate-limit/audit client IPs.

Run just this file:  pytest tests/test_prodcheck.py -q
"""
from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_prodcheck.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
from fastapi import Request  # noqa: E402

from app.core.clientip import client_ip  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.core.prodcheck import (  # noqa: E402
    ProductionConfigError,
    ensure_safe_production_config,
    is_production,
    production_config_problems,
)


def make_settings(tmp_path: Path, **overrides) -> Settings:
    """A fully safe production baseline; tests break one thing at a time."""
    key = tmp_path / "signing_key.pem"
    key.write_text("not-a-real-key-but-present")
    base = dict(
        environment="production",
        debug=False,
        secret_key="x" * 48,
        public_base_url="https://rmm.example.com",
        command_signing_key_path=str(key),
        command_signing_keyring_path=None,
        _env_file=None,
    )
    base.update(overrides)
    return Settings(**base)


def problems(tmp_path: Path, **overrides) -> list[str]:
    return production_config_problems(make_settings(tmp_path, **overrides))


def test_safe_production_config_passes(tmp_path):
    s = make_settings(tmp_path)
    assert production_config_problems(s) == []
    ensure_safe_production_config(s)  # must not raise


def test_non_production_is_exempt(tmp_path):
    s = make_settings(
        tmp_path, environment="development", debug=True, secret_key="dev",
        public_base_url=None,
    )
    assert not is_production(s)
    ensure_safe_production_config(s)  # unsafe values, but not production


@pytest.mark.parametrize(
    "overrides, needle",
    [
        ({"debug": True}, "DEBUG"),
        ({"secret_key": "CHANGE_ME_IN_PRODUCTION"}, "placeholder"),
        ({"secret_key": "test-secret"}, "placeholder"),
        ({"secret_key": "short-but-not-placeholder"}, "shorter"),
        ({"public_base_url": None}, "PUBLIC_BASE_URL is required"),
        ({"public_base_url": "http://rmm.example.com"}, "https://"),
        ({"public_base_url": "https://localhost"}, "loopback"),
        ({"public_base_url": "https://127.0.0.1:8443"}, "loopback"),
    ],
)
def test_each_violation_is_reported(tmp_path, overrides, needle):
    found = problems(tmp_path, **overrides)
    assert any(needle in p for p in found), (overrides, found)


def test_missing_signing_key_is_reported(tmp_path):
    found = problems(tmp_path, command_signing_key_path=str(tmp_path / "absent.pem"))
    assert any("COMMAND_SIGNING_KEY_PATH" in p for p in found)


def test_missing_keyring_is_reported(tmp_path):
    found = problems(
        tmp_path, command_signing_keyring_path=str(tmp_path / "absent.json")
    )
    assert any("COMMAND_SIGNING_KEYRING_PATH" in p for p in found)


def test_all_violations_collected_in_one_error(tmp_path):
    s = make_settings(
        tmp_path,
        debug=True,
        secret_key="dev",
        public_base_url="http://rmm.example.com",
        command_signing_key_path=str(tmp_path / "absent.pem"),
    )
    with pytest.raises(ProductionConfigError) as exc:
        ensure_safe_production_config(s)
    assert len(exc.value.problems) == 4
    # The message an operator sees lists every problem at once.
    for fragment in ("DEBUG", "SECRET_KEY", "PUBLIC_BASE_URL", "COMMAND_SIGNING_KEY_PATH"):
        assert fragment in str(exc.value)


# --------------------------------------------------------------------------- #
# Proxy trust / client IP
# --------------------------------------------------------------------------- #
def make_request(peer: str, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "client": (peer, 12345),
    }
    return Request(scope)


def test_forwarded_header_ignored_by_default(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    req = make_request("203.0.113.7", {"X-Forwarded-For": "6.6.6.6"})
    # A spoofed header must not let a caller pick its own rate-limit bucket.
    assert client_ip(req) == "203.0.113.7"


def test_forwarded_header_used_when_trusted(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    req = make_request("10.0.0.2", {"X-Forwarded-For": "198.51.100.9"})
    assert client_ip(req) == "198.51.100.9"


def test_only_rightmost_forwarded_entry_is_trusted(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    # The left entries are caller-supplied junk; only the value appended by
    # the trusted immediate proxy counts.
    req = make_request("10.0.0.2", {"X-Forwarded-For": "6.6.6.6, 7.7.7.7, 198.51.100.9"})
    assert client_ip(req) == "198.51.100.9"


def test_trusted_but_absent_header_falls_back_to_peer(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    assert client_ip(make_request("10.0.0.2")) == "10.0.0.2"
