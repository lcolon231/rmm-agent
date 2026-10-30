# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for ``app.core.clientip`` X-Forwarded-For trust (issue #285)."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_clientip.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
from starlette.requests import Request  # noqa: E402

from app.core.clientip import client_ip  # noqa: E402
from app.core.config import settings  # noqa: E402


def _request(peer: str | None = "10.0.0.5", xff: str | None = None) -> Request:
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {"type": "http", "headers": headers}
    if peer is not None:
        scope["client"] = (peer, 1234)
    return Request(scope)


@pytest.fixture
def trust(monkeypatch):
    def _set(value: bool) -> None:
        monkeypatch.setattr(settings, "trust_proxy_headers", value)

    return _set


@pytest.mark.parametrize(
    "xff",
    [None, "", "203.0.113.9", "198.51.100.1, 203.0.113.9"],
)
def test_untrusted_ignores_forwarded_header(trust, xff):
    trust(False)
    assert client_ip(_request(xff=xff)) == "10.0.0.5"


def test_missing_peer_is_unknown(trust):
    trust(False)
    assert client_ip(_request(peer=None, xff="203.0.113.9")) == "unknown"
    trust(True)
    assert client_ip(_request(peer=None)) == "unknown"


@pytest.mark.parametrize(
    "xff,expected",
    [
        (None, "10.0.0.5"),
        ("", "10.0.0.5"),
        ("203.0.113.9", "203.0.113.9"),
        # Rightmost entry is what our trusted proxy saw; the left is spoofable.
        ("1.1.1.1, 203.0.113.9", "203.0.113.9"),
        ("1.1.1.1,203.0.113.9 ", "203.0.113.9"),
        # A trailing empty entry falls back to the socket peer, never to a
        # caller-controlled entry further left.
        ("1.1.1.1, ", "10.0.0.5"),
        (" , ", "10.0.0.5"),
    ],
)
def test_trusted_uses_rightmost_forwarded_entry(trust, xff, expected):
    trust(True)
    assert client_ip(_request(xff=xff)) == expected
