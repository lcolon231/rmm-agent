# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for the real MeshCentral control client (issue #62).

These guard two defects that only appear against a live MeshCentral and that the
in-memory ``FakeMeshCentralClient`` cannot model:

1. **Response correlation.** MeshCentral pushes several *unsolicited* control
   frames (``serverinfo``, ``userinfo``, events) the moment the socket
   authenticates. The client must tag its request with a ``responseid`` and read
   until the matching reply arrives; a bare ``recv()`` returns the first push and
   the mint fails closed. See ``PinnedHTTPSMeshCentralClient._control``.
2. **Desktop permission bitmask.** A desktop share is ``p=2``. ``p=8`` is an HTTP
   relay share, not a remote desktop, so a session would mint but never open the
   desktop.

A scripted mock of ``control.ashx`` replays the real frame ordering so both
defects are caught without a live server.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_meshcentral_control.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pytest  # noqa: E402

from app.core import meshcentral as mc  # noqa: E402
from app.core.config import Settings  # noqa: E402


class _ScriptedControlWS:
    """Mock MeshCentral control socket: unsolicited pushes, then the reply.

    Records every sent message so a test can assert on the request, and only
    queues the correlated ``createDeviceShareLink`` reply *after* the unsolicited
    frames, exactly as the live server orders them.
    """

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self._frames: list[dict] = [
            {"action": "serverinfo", "serverinfo": {}},
            {"action": "userinfo", "userinfo": {}},
            {"action": "event", "event": {"etype": "node"}},
        ]

    async def __aenter__(self) -> "_ScriptedControlWS":
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def send(self, data: str) -> None:
        msg = json.loads(data)
        self.sent.append(msg)
        if msg.get("action") == "createDeviceShareLink":
            self._frames.append(
                {
                    "action": "createDeviceShareLink",
                    "responseid": msg.get("responseid"),
                    "result": "OK",
                    "url": "https://mesh.test/sharing?c=SECRET",
                    "publicid": "share-xyz",
                }
            )

    async def recv(self) -> str:
        assert self._frames, "recv() called with no frames queued"
        return json.dumps(self._frames.pop(0))


@pytest.fixture
def client(monkeypatch):
    async def _no_validate(*args, **kwargs):
        return None

    monkeypatch.setattr(mc, "validate_destination", _no_validate)

    ws = _ScriptedControlWS()
    import websockets

    monkeypatch.setattr(websockets, "connect", lambda *a, **k: ws)

    cfg = Settings(
        meshcentral_provider="enabled",
        meshcentral_base_url="https://mesh.test",
        meshcentral_admin_token="dXNlcg==,cGFzcw==",  # base64(user),base64(pass)
    )
    return mc.PinnedHTTPSMeshCentralClient(cfg), ws


@pytest.mark.asyncio
async def test_mint_correlates_reply_past_unsolicited_frames(client):
    """The mint must skip serverinfo/userinfo/event and return the real reply."""
    c, _ws = client
    minted = await c.mint_device_login(
        node_id="node//abc", ttl_seconds=120, operator_ref="op-1"
    )
    assert minted.login_url == "https://mesh.test/sharing?c=SECRET"
    assert minted.session_ref == "share-xyz"


@pytest.mark.asyncio
async def test_mint_requests_desktop_permission_bitmask(client):
    """A remote-desktop share is p=2; p=8 would be an HTTP relay share."""
    c, ws = client
    await c.mint_device_login(node_id="node//abc", ttl_seconds=120, operator_ref="op-1")
    share = next(m for m in ws.sent if m.get("action") == "createDeviceShareLink")
    assert share["p"] == 2


@pytest.mark.asyncio
async def test_mint_tags_request_with_responseid(client):
    """Every control request carries a responseid so replies can be correlated."""
    c, ws = client
    await c.mint_device_login(node_id="node//abc", ttl_seconds=120, operator_ref="op-1")
    share = next(m for m in ws.sent if m.get("action") == "createDeviceShareLink")
    assert isinstance(share.get("responseid"), str) and share["responseid"]
