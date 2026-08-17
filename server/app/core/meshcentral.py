# SPDX-License-Identifier: AGPL-3.0-only
"""MeshCentral remote-desktop provider abstraction (issue #62).

MeshCentral is a **separate security and operational boundary**. NodeLink only
authorizes, identity-maps, and audits a session *launch*; it asks MeshCentral to
mint a short-lived, single-device-scoped access URL through MeshCentral's own
API and never proxies the desktop stream, stores login material, or claims
MeshCentral's in-session activity under NodeLink's audit/signature guarantees.

Design mirrors ``webhook_notifications.py``: a ``Protocol`` with a fail-closed
sanitized error type, a deterministic in-memory ``FakeMeshCentralClient`` that
drives every automated test (there is no live MeshCentral in CI), and a real
``PinnedHTTPSMeshCentralClient`` that is disabled by default and finalized/
verified against a live MeshCentral via the manual runbook in
``docs/MESHCENTRAL-INTEGRATION.md``. The provider default is ``disabled``; every
launch is refused while disabled.

Secrets: the MeshCentral admin credential is environment-only and never
persisted or returned. The optional login-material AES-GCM key encrypts minted
material only if it must briefly survive a retry; the default flow mints
synchronously and returns the URL once without persisting it.
"""
from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings, settings
from app.core.webhook_notifications import validate_destination

_SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_-]{1,100}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MeshCentralError(RuntimeError):
    """Sanitized provider, transport, or configuration failure (fail closed).

    ``state`` classifies the failure for the API boundary and dashboard:
    ``invalid`` (caller error, 4xx), ``unsupported`` (mapping/provider gap, 409),
    ``unavailable`` (MeshCentral unreachable/rejecting, 503).
    """

    def __init__(
        self,
        code: str,
        *,
        state: str = "unavailable",
        retryable: bool = False,
        http_status: int | None = None,
    ):
        safe_code = code.lower()
        if not _SAFE_ERROR_CODE.fullmatch(safe_code):
            safe_code = "meshcentral_error"
        super().__init__(safe_code)
        self.code = safe_code
        self.state = state
        self.retryable = retryable
        self.http_status = http_status


@dataclass(frozen=True)
class MeshDevice:
    """A MeshCentral node as returned by a device-list sync. No secrets."""

    node_id: str
    name: str | None = None
    mesh_id: str | None = None
    last_connect: datetime | None = None


@dataclass(frozen=True)
class MintedSession:
    """A minted, short-lived, single-device access grant.

    ``login_url`` is a **secret returned once** to the authorized operator and is
    never persisted. ``session_ref`` is an opaque, non-secret handle used only for
    correlation and best-effort revoke.
    """

    login_url: str
    expires_at: datetime
    session_ref: str | None = None


class MeshCentralClient(Protocol):
    """The provider surface NodeLink depends on. Kept intentionally small."""

    async def health(self) -> None:
        """Raise ``MeshCentralError(state='unavailable')`` if the server is down."""
        ...

    async def list_devices(self) -> list[MeshDevice]:
        """Return the MeshCentral node inventory for staleness reconciliation."""
        ...

    async def mint_device_login(
        self, *, node_id: str, ttl_seconds: int, operator_ref: str
    ) -> MintedSession:
        """Mint a short-lived, single-device desktop access URL."""
        ...

    async def revoke(self, session_ref: str) -> None:
        """Best-effort revoke of a previously minted grant. Never raises."""
        ...


# ---------------------------------------------------------------------------
# Fake client — authoritative for every automated test.
# ---------------------------------------------------------------------------
class FakeMeshCentralClient:
    """Deterministic in-memory MeshCentral used by tests and offline dev.

    Configure ``available`` to simulate an outage and ``devices`` to drive the
    reconciliation sync. Minted URLs are synthetic and clearly non-routable.
    """

    def __init__(
        self,
        *,
        devices: list[MeshDevice] | None = None,
        available: bool = True,
        base_url: str = "https://meshcentral.example.invalid",
    ):
        self.devices = list(devices or [])
        self.available = available
        self.base_url = base_url.rstrip("/")
        self.minted: list[MintedSession] = []
        self.revoked: list[str] = []

    async def health(self) -> None:
        if not self.available:
            raise MeshCentralError("meshcentral_unavailable", state="unavailable", retryable=True)

    async def list_devices(self) -> list[MeshDevice]:
        await self.health()
        return list(self.devices)

    async def mint_device_login(
        self, *, node_id: str, ttl_seconds: int, operator_ref: str
    ) -> MintedSession:
        await self.health()
        token = secrets.token_urlsafe(24)
        ref = "share-" + secrets.token_hex(8)
        minted = MintedSession(
            login_url=f"{self.base_url}/?gotonode={node_id}&viewmode=11&c={token}",
            expires_at=_now() + timedelta(seconds=ttl_seconds),
            session_ref=ref,
        )
        self.minted.append(minted)
        return minted

    async def revoke(self, session_ref: str) -> None:
        # Best-effort: record and never raise.
        self.revoked.append(session_ref)


# ---------------------------------------------------------------------------
# Real client — disabled by default, finalized/verified via the manual runbook.
# ---------------------------------------------------------------------------
class PinnedHTTPSMeshCentralClient:
    """Real MeshCentral v1.2.x adapter over the control WebSocket.

    Connects to ``<base>/control.ashx`` authenticated with the environment-only
    admin login token, creates a single-device **device-sharing** link scoped to
    the desktop for ``ttl_seconds`` (``createDeviceShareLink``), and best-effort
    removes it on close (``removeDeviceShare``). The base URL is SSRF-validated
    via :func:`app.core.webhook_notifications.validate_destination` and, when
    ``meshcentral_tls_pin_sha256`` is set, the server certificate is pinned.

    This adapter is exercised by the manual E2E runbook against a live
    MeshCentral (there is no live server in CI); the ``FakeMeshCentralClient`` is
    authoritative for automated tests. Any failure is mapped to a fail-closed
    :class:`MeshCentralError`.
    """

    def __init__(self, config: Settings = settings):
        self._config = config
        base = (config.meshcentral_base_url or "").strip()
        if not base.startswith("https://"):
            raise MeshCentralError(
                "provider_misconfigured", state="unavailable", retryable=False
            )
        self._base = base.rstrip("/")
        self._token = config.meshcentral_admin_token
        self._username = config.meshcentral_admin_username
        self._pin = (config.meshcentral_tls_pin_sha256 or "").strip().lower() or None
        if not self._token and not self._username:
            raise MeshCentralError(
                "provider_credentials_missing", state="unavailable", retryable=False
            )

    async def _validate(self) -> None:
        # Reuse the webhook SSRF/DNS-rebinding validation. Loopback is allowed for
        # the LAN-mode/local deployment the runbook documents; a public
        # deployment resolves to a global address like any webhook destination.
        try:
            await validate_destination(self._base, self._config)
        except Exception as exc:  # noqa: BLE001 - normalize to fail closed
            # A loopback base_url is intentionally permitted here (unlike
            # webhooks) because the operator explicitly configures it.
            if "127.0.0.1" not in self._base and "localhost" not in self._base:
                raise MeshCentralError(
                    "destination_unavailable", state="unavailable", retryable=True
                ) from exc

    async def _control(self, requests: list[dict]) -> list[dict]:
        """Open one authenticated control connection and exchange messages.

        Kept as the single seam the manual runbook confirms against the live
        server. Import is lazy so the module has no hard websocket dependency at
        import time.
        """
        import asyncio
        import json
        import ssl

        import websockets

        ssl_ctx = ssl.create_default_context()
        if self._pin:
            # Self-signed/pinned deployments verify by certificate fingerprint
            # instead of a public CA chain.
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        headers = []
        if self._token:
            # MeshCentral login-token auth header used by meshctrl.
            headers.append(("x-meshauth", self._token))
        url = self._base.replace("https://", "wss://", 1) + "/control.ashx"
        replies: list[dict] = []
        try:
            async with websockets.connect(
                url,
                ssl=ssl_ctx,
                additional_headers=headers,
                open_timeout=self._config.meshcentral_request_timeout_seconds,
                close_timeout=self._config.meshcentral_request_timeout_seconds,
            ) as ws:
                if self._pin:
                    _verify_pin(ws, self._pin)
                for message in requests:
                    # MeshCentral pushes several unsolicited control messages as
                    # soon as the socket authenticates, so a bare send/recv reads
                    # the wrong frame. Tag the request with a responseid (as
                    # meshctrl does) and read until the matching reply arrives,
                    # skipping unrelated server pushes.
                    rid = message.get("responseid") or secrets.token_hex(8)
                    message = {**message, "responseid": rid}
                    expected = message.get("action")
                    await ws.send(json.dumps(message))
                    reply = None
                    for _ in range(64):
                        data = json.loads(
                            await asyncio.wait_for(
                                ws.recv(),
                                timeout=self._config.meshcentral_request_timeout_seconds,
                            )
                        )
                        # Prefer a responseid match; fall back to the action for
                        # replies MeshCentral does not echo the responseid on
                        # (e.g. serverinfo). Unsolicited pushes carry a different
                        # action, so this does not mis-match command replies.
                        if data.get("responseid") == rid or (
                            data.get("responseid") is None
                            and data.get("action") == expected
                        ):
                            reply = data
                            break
                    if reply is None:
                        raise MeshCentralError(
                            "meshcentral_no_response", state="unavailable", retryable=True
                        )
                    replies.append(reply)
        except MeshCentralError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise MeshCentralError(
                "meshcentral_unavailable", state="unavailable", retryable=True
            ) from exc
        return replies

    async def health(self) -> None:
        await self._validate()
        await self._control([{"action": "serverinfo"}])

    async def list_devices(self) -> list[MeshDevice]:
        await self._validate()
        replies = await self._control([{"action": "nodes"}])
        devices: list[MeshDevice] = []
        for reply in replies:
            nodes = reply.get("nodes") or {}
            for mesh_id, node_list in nodes.items():
                for node in node_list:
                    node_id = node.get("_id") or node.get("nodeid")
                    if not node_id:
                        continue
                    last = node.get("lastconnect")
                    devices.append(
                        MeshDevice(
                            node_id=node_id,
                            name=node.get("name"),
                            mesh_id=mesh_id,
                            last_connect=(
                                datetime.fromtimestamp(last / 1000, tz=timezone.utc)
                                if isinstance(last, (int, float))
                                else None
                            ),
                        )
                    )
        return devices

    async def mint_device_login(
        self, *, node_id: str, ttl_seconds: int, operator_ref: str
    ) -> MintedSession:
        await self._validate()
        start = int(_now().timestamp())
        end = start + ttl_seconds
        replies = await self._control(
            [
                {
                    "action": "createDeviceShareLink",
                    "nodeid": node_id,
                    "guestname": f"nodelink:{operator_ref}"[:64],
                    # MeshCentral share permission bitmask: 1=terminal, 2=desktop,
                    # 4=files, 8=http, 16=https. Desktop-only is 2 (8 is an HTTP
                    # relay share, not the remote desktop).
                    "p": 2,
                    "start": start,
                    "end": end,
                    "consent": 0,
                }
            ]
        )
        for reply in replies:
            url = reply.get("url") or reply.get("publicid")
            if url:
                full = url if str(url).startswith("http") else f"{self._base}/{url}"
                return MintedSession(
                    login_url=full,
                    expires_at=datetime.fromtimestamp(end, tz=timezone.utc),
                    session_ref=reply.get("publicid"),
                )
        raise MeshCentralError(
            "mint_rejected", state="unavailable", retryable=True
        )

    async def revoke(self, session_ref: str) -> None:
        try:
            await self._control(
                [{"action": "removeDeviceShare", "publicid": session_ref}]
            )
        except Exception:  # noqa: BLE001 - best effort, never raises
            return


def _verify_pin(ws, expected_hex: str) -> None:
    """Verify the server certificate SHA-256 fingerprint against the config pin."""
    import hashlib

    try:
        der = ws.transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001
        raise MeshCentralError(
            "tls_pin_unavailable", state="unavailable", retryable=False
        ) from exc
    actual = hashlib.sha256(der).hexdigest()
    if actual != expected_hex:
        raise MeshCentralError(
            "tls_pin_mismatch", state="unavailable", retryable=False
        )


# ---------------------------------------------------------------------------
# Provider wiring + login-material encryption.
# ---------------------------------------------------------------------------
def provider_enabled(config: Settings = settings) -> bool:
    return (config.meshcentral_provider or "disabled").strip().lower() == "enabled"


def get_client(config: Settings = settings) -> MeshCentralClient | None:
    """Return the configured client, or ``None`` when the provider is disabled.

    Tests inject a :class:`FakeMeshCentralClient` directly rather than calling
    this factory, so it only needs to build the real adapter.
    """
    if not provider_enabled(config):
        return None
    return PinnedHTTPSMeshCentralClient(config)


def provider_status(config: Settings = settings) -> dict:
    """Non-secret provider configuration summary for the admin surface."""
    return {
        "provider": (config.meshcentral_provider or "disabled").strip().lower(),
        "configured": provider_enabled(config),
        "base_url_configured": bool((config.meshcentral_base_url or "").strip()),
        "credential_configured": bool(
            (config.meshcentral_admin_token or "").strip()
            or (config.meshcentral_admin_username or "").strip()
        ),
        "encryption_key_configured": login_key_configured(config),
    }


def _decode_login_key(config: Settings) -> bytes:
    value = config.meshcentral_login_cookie_encryption_key or ""
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise MeshCentralError(
            "login_key_unavailable", state="unavailable", retryable=False
        ) from exc
    if len(key) != 32:
        raise MeshCentralError(
            "login_key_unavailable", state="unavailable", retryable=False
        )
    return key


def login_key_configured(config: Settings = settings) -> bool:
    try:
        _decode_login_key(config)
    except MeshCentralError:
        return False
    return True


def _login_aad(launch_id: str) -> bytes:
    return f"nodelink-meshcentral-login:{launch_id}".encode("ascii")


def encrypt_login_material(
    material: str, *, launch_id: str, config: Settings = settings
) -> str:
    """Encrypt minted login material at rest (only used if it must survive a retry)."""
    key = _decode_login_key(config)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, material.encode("utf-8"), _login_aad(launch_id))
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_login_material(
    encrypted: str, *, launch_id: str, config: Settings = settings
) -> str:
    key = _decode_login_key(config)
    try:
        raw = base64.b64decode(encrypted, altchars=b"-_", validate=True)
        if len(raw) < 29:
            raise ValueError("ciphertext too short")
        plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], _login_aad(launch_id))
        return plaintext.decode("utf-8")
    except MeshCentralError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise MeshCentralError(
            "login_material_decrypt_failed", state="unavailable", retryable=False
        ) from exc
