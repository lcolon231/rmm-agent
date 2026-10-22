# SPDX-License-Identifier: AGPL-3.0-only
"""ASGI ingress that authenticates relay-forwarded requests (issue #87).

A request with no ``X-NodeLink-Relay-*`` header is a direct origin request and
passes through untouched. A request carrying any of them is buffered (bounded
by ``relay_max_forward_body_bytes``), verified by
:func:`app.core.relays.verify_forward`, and either refused with a stable
``{"detail": {"code": ...}}`` body or replayed to the application with the
verified :class:`~app.core.relays.RelayContext` in ``request.state.relay``.

Doing this at the ASGI layer rather than in a route dependency means the
signature covers the exact body bytes the handler will parse, and that no
endpoint can forget to check: an agent route that is not explicitly relayable
is refused before any handler runs.
"""
from __future__ import annotations

import json

from app.core import relays
from app.core.config import settings
from app.core.database import AsyncSessionLocal


async def _send_refusal(send, http_status: int, code: str) -> None:
    body = json.dumps({"detail": {"code": code}}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": http_status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RelayIngressMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])
        }
        if not relays.has_relay_headers(headers):
            await self.app(scope, receive, send)
            return

        # Buffer the body with a hard bound before any database work.
        limit = settings.relay_max_forward_body_bytes
        chunks: list[bytes] = []
        size = 0
        more = True
        too_large = False
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                too_large = True
                break
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"" if too_large else b"".join(chunks)

        method = scope["method"].upper()
        path = scope["path"]
        query = scope.get("query_string", b"")
        if query:
            path = f"{path}?{query.decode('latin-1')}"

        async with AsyncSessionLocal() as db:
            try:
                if too_large:
                    # Still attribute the refusal to the relay when it is real.
                    relay = None
                    relay_id = headers.get(relays.HEADER_RELAY_ID, "")
                    if relays.UUID_RE.fullmatch(relay_id):
                        relay = await db.get(relays.Relay, relay_id)
                    await relays.record_refusal(
                        db,
                        relay=relay,
                        key_id=headers.get(relays.HEADER_KEY_ID, ""),
                        code="relay_body_too_large",
                        path=path,
                    )
                    await _send_refusal(send, 413, "relay_body_too_large")
                    return
                ctx = await relays.verify_forward(
                    db, method=method, path=path, headers=headers, body=body
                )
            except relays.RelayRefusal as refusal:
                await _send_refusal(send, refusal.http_status, refusal.code)
                return

        scope.setdefault("state", {})["relay"] = ctx
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
