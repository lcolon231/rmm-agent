# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-region relay trust, residency, and routing (issue #87).

A relay is a regional HTTPS ingress that forwards agent requests to this
control plane. It is authenticated, but it is never trusted for *content*:

* Every forwarded request carries a relay signature over a domain-separated
  canonical string (:func:`canonical_forward_bytes`). The server verifies it
  against the relay's registered public key, bounds clock skew and the time the
  relay held the request (store-and-forward age), and records a receipt whose
  unique (relay_id, nonce) index refuses replays.
* The agent's own bearer credential still authenticates the agent. A relay
  cannot mint commands: commands remain end-to-end signed by the control-plane
  keyring and verified on the endpoint.
* Routes and command keys reach agents only inside a **routing manifest** that
  the control plane signs with every signing-capable keyring key
  (:func:`signed_routing_manifest`). The agent verifies it with keys it already
  trusts, so a relay that rewrites a heartbeat response cannot plant a key or
  redirect the agent.

Residency here is *ingress* residency: which region's relays may carry a
tenant's agent traffic. The database itself is not partitioned by region.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit, metrics
from app.core.config import settings
from app.core.keyring import load_keyring, public_key_bundle
from app.models.models import (
    Agent,
    Relay,
    RelayForwardReceipt,
    RelayKey,
    RelayRegion,
    TenantRegionPolicy,
)

FORWARD_CONTEXT = b"nodelink-relay-forward-v1"
MANIFEST_VERSION = "routing-manifest-v1"
MANIFEST_CONTEXT = b"nodelink-agent-routing-v1:"
RELAY_ROUTING_CAPABILITY = "relay-routing"

HEADER_PREFIX = "x-nodelink-relay-"
HEADER_RELAY_ID = "x-nodelink-relay-id"
HEADER_KEY_ID = "x-nodelink-relay-key-id"
HEADER_TIMESTAMP = "x-nodelink-relay-timestamp"
HEADER_QUEUED_AT = "x-nodelink-relay-queued-at"
HEADER_NONCE = "x-nodelink-relay-nonce"
HEADER_SIGNATURE = "x-nodelink-relay-signature"
REQUIRED_HEADERS = (
    HEADER_RELAY_ID,
    HEADER_KEY_ID,
    HEADER_TIMESTAMP,
    HEADER_QUEUED_AT,
    HEADER_NONCE,
    HEADER_SIGNATURE,
)

REGION_STATUSES = ("active", "draining", "disabled")
RELAY_STATUSES = ("pending", "active", "draining", "revoked")
KEY_STATUSES = ("active", "retired", "revoked")
RESIDENCY_MODES = ("preferred", "strict")
# A relay may hold at most this many non-retired keys: the current key plus
# one staged successor during rotation.
MAX_LIVE_KEYS_PER_RELAY = 2
MAX_KEY_LIFETIME_DAYS = 400

REGION_CODE_RE = re.compile(r"^[a-z0-9-]{2,32}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")
SPKI_PIN_RE = re.compile(r"^sha256/[A-Za-z0-9+/]{43}=$")

# Agent endpoints a relay may carry. Enrollment, credential reattachment,
# interactive shell, support chat, and self-update stay origin-only: they carry
# one-time secrets or long-lived interactive state that this revision does not
# extend across a relay hop.
_RELAYABLE_ROUTES = (
    ("POST", re.compile(r"^/api/v1/heartbeat$")),
    ("POST", re.compile(r"^/api/v1/commands/[^/]{1,64}/result$")),
    ("POST", re.compile(r"^/api/v1/agents/me/inventory$")),
    ("POST", re.compile(r"^/api/v1/agents/me/monitoring/results$")),
    ("POST", re.compile(r"^/api/v1/agents/credentials/renew$")),
)

# Refusals a registered relay caused. Unauthenticated noise (unknown relay id,
# malformed headers) is counted in metrics only, so a stranger cannot fill the
# audit chain by inventing relay ids.
_AUDITED_REFUSALS = frozenset(
    {
        "relay_not_active",
        "relay_key_unknown",
        "relay_key_inactive",
        "relay_key_expired",
        "relay_signature_invalid",
        "relay_clock_skew",
        "relay_forward_too_old",
        "relay_replay",
        "relay_body_too_large",
        "relay_route_unsupported",
        "relay_region_disabled",
        "relay_region_mismatch",
    }
)


class RelayRefusal(Exception):
    """A fail-closed refusal with a stable machine-readable code."""

    def __init__(self, code: str, http_status: int = status.HTTP_403_FORBIDDEN) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status


@dataclass(frozen=True)
class RelayContext:
    """Verified facts about the relay that carried the current request."""

    relay_id: str
    region_id: str
    region_code: str
    key_id: str
    receipt_id: str
    queued_at: datetime


class _RefusalAuditLimiter:
    """At most one audit row per (relay, reason) per window; the next row
    carries how many identical refusals were suppressed in between."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._last: dict[tuple[str, str], float] = {}
        self._suppressed: dict[tuple[str, str], int] = {}

    def admit(self, relay_id: str, reason: str) -> int | None:
        key = (relay_id, reason)
        now = time.monotonic()
        last = self._last.get(key)
        if last is not None and now - last < self.window_seconds:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return None
        self._last[key] = now
        return self._suppressed.pop(key, 0)

    def reset(self) -> None:
        self._last.clear()
        self._suppressed.clear()


refusal_audit_limiter = _RefusalAuditLimiter()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def has_relay_headers(headers: dict[str, str]) -> bool:
    return any(name.startswith(HEADER_PREFIX) for name in headers)


def is_relayable(method: str, path: str) -> bool:
    return any(method == m and pattern.match(path) for m, pattern in _RELAYABLE_ROUTES)


def canonical_forward_bytes(
    *,
    relay_id: str,
    key_id: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    queued_at: int,
    nonce: str,
) -> bytes:
    """The exact bytes a relay signs for one forwarded request.

    Newline-joined ASCII fields after a domain-separation tag, so a relay
    forwarding signature can never be confused with a command, manifest, or
    evidence-package signature made by any key.
    """
    fields = (
        FORWARD_CONTEXT.decode("ascii"),
        relay_id,
        key_id,
        method.upper(),
        path,
        hashlib.sha256(body).hexdigest(),
        str(int(timestamp)),
        str(int(queued_at)),
        nonce,
    )
    for value in fields:
        if "\n" in value:
            raise ValueError("forward fields must not contain newlines")
    return "\n".join(fields).encode("utf-8")


def load_public_key(pem: str) -> Ed25519PublicKey:
    value = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(value, Ed25519PublicKey):
        raise ValueError("relay keys must be Ed25519")
    return value


def public_key_fingerprint(pem: str) -> str:
    raw = load_public_key(pem).public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()


def _parse_int(value: str, code: str) -> int:
    if not re.fullmatch(r"\d{1,12}", value or ""):
        raise RelayRefusal(code, status.HTTP_400_BAD_REQUEST)
    return int(value)


async def record_refusal(
    db: AsyncSession,
    *,
    relay: Relay | None,
    key_id: str,
    code: str,
    path: str,
) -> None:
    """Count every refusal; audit the ones a registered relay produced."""
    metrics.increment("relay_forward_refused_total")
    if relay is None or code not in _AUDITED_REFUSALS:
        return
    suppressed = refusal_audit_limiter.admit(relay.id, code)
    if suppressed is None:
        return
    await audit.record(
        db,
        action="relay.forward_refused",
        actor=f"relay:{relay.id}",
        detail={
            "relay_id": relay.id,
            "key_id": key_id if KEY_ID_RE.fullmatch(key_id or "") else "",
            "reason": code,
            "path": path[:256],
            "suppressed_count": suppressed,
        },
    )
    await db.commit()


async def verify_forward(
    db: AsyncSession,
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> RelayContext:
    """Authenticate one forwarded request and record its replay receipt.

    The receipt is committed *before* the request reaches its handler, so a
    replayed forward is refused even when the original's handler failed. Any
    refusal is recorded (see :func:`record_refusal`) and raised as
    :class:`RelayRefusal`.
    """
    relay: Relay | None = None
    key_id = headers.get(HEADER_KEY_ID, "")
    try:
        if not settings.relay_routing_enabled:
            raise RelayRefusal("relay_routing_disabled")
        if any(not headers.get(name) for name in REQUIRED_HEADERS):
            raise RelayRefusal("relay_headers_incomplete", status.HTTP_400_BAD_REQUEST)
        relay_id = headers[HEADER_RELAY_ID]
        nonce = headers[HEADER_NONCE]
        if not UUID_RE.fullmatch(relay_id) or not KEY_ID_RE.fullmatch(key_id):
            raise RelayRefusal("relay_headers_invalid", status.HTTP_400_BAD_REQUEST)
        if not NONCE_RE.fullmatch(nonce):
            raise RelayRefusal("relay_headers_invalid", status.HTTP_400_BAD_REQUEST)
        timestamp = _parse_int(headers[HEADER_TIMESTAMP], "relay_headers_invalid")
        queued_at = _parse_int(headers[HEADER_QUEUED_AT], "relay_headers_invalid")

        relay = await db.get(Relay, relay_id)
        if relay is None:
            raise RelayRefusal("relay_unknown")
        if not is_relayable(method, path):
            raise RelayRefusal("relay_route_unsupported")
        if relay.status not in ("active", "draining"):
            raise RelayRefusal("relay_not_active")
        region = await db.get(RelayRegion, relay.region_id)
        if region is None or region.status == "disabled":
            raise RelayRefusal("relay_region_disabled")
        if len(body) > settings.relay_max_forward_body_bytes:
            raise RelayRefusal("relay_body_too_large", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        key = await db.scalar(
            select(RelayKey).where(RelayKey.key_id == key_id, RelayKey.relay_id == relay.id)
        )
        if key is None:
            raise RelayRefusal("relay_key_unknown")
        if key.status != "active":
            raise RelayRefusal("relay_key_inactive")
        now = _now()
        if _as_utc(key.not_after) <= now:
            raise RelayRefusal("relay_key_expired")

        signature_text = headers[HEADER_SIGNATURE]
        try:
            signature = base64.b64decode(signature_text, validate=True)
            load_public_key(key.public_key_pem).verify(
                signature,
                canonical_forward_bytes(
                    relay_id=relay.id,
                    key_id=key_id,
                    method=method,
                    path=path,
                    body=body,
                    timestamp=timestamp,
                    queued_at=queued_at,
                    nonce=nonce,
                ),
            )
        except (InvalidSignature, ValueError):
            raise RelayRefusal("relay_signature_invalid") from None

        # Freshness is checked only after the signature, so the timestamps
        # being judged are the relay's signed claims, not forgeable headers.
        now_s = int(now.timestamp())
        if abs(now_s - timestamp) > settings.relay_clock_skew_seconds:
            raise RelayRefusal("relay_clock_skew")
        if queued_at > timestamp + settings.relay_clock_skew_seconds:
            raise RelayRefusal("relay_clock_skew")
        if now_s - queued_at > settings.relay_max_forward_age_seconds:
            raise RelayRefusal("relay_forward_too_old")

        receipt = RelayForwardReceipt(
            relay_id=relay.id,
            key_id=key_id,
            nonce=nonce,
            method=method.upper(),
            path=path[:256],
            queued_at=datetime.fromtimestamp(queued_at, timezone.utc),
            received_at=now,
        )
        db.add(receipt)
        relay.last_forward_at = now
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            relay = await db.get(Relay, relay_id)
            raise RelayRefusal("relay_replay", status.HTTP_409_CONFLICT) from None
        metrics.increment("relay_forward_accepted_total")
        return RelayContext(
            relay_id=relay.id,
            region_id=region.id,
            region_code=region.code,
            key_id=key_id,
            receipt_id=receipt.id,
            queued_at=datetime.fromtimestamp(queued_at, timezone.utc),
        )
    except RelayRefusal as refusal:
        await record_refusal(db, relay=relay, key_id=key_id, code=refusal.code, path=path)
        raise


async def tenant_policy(db: AsyncSession, client_id: str | None) -> TenantRegionPolicy | None:
    if client_id is None:
        return None
    return await db.get(TenantRegionPolicy, client_id)


def agent_supports_relay_routing(agent: Agent) -> bool:
    return RELAY_ROUTING_CAPABILITY in (agent.supported_capabilities or [])


async def enforce_route_policy(
    db: AsyncSession,
    agent: Agent,
    client_id: str | None,
    ctx: RelayContext | None,
    *,
    path: str = "",
    method: str = "POST",
) -> None:
    """Apply the tenant's ingress-residency policy to one agent request.

    * No policy, or ``preferred``: any active relay or the origin may carry
      the request (``preferred`` only orders routes; it never refuses).
    * ``strict``: a relay from another region is refused. A direct origin
      request is refused for an agent that advertises relay routing, because
      it could have used its home relays. An older agent that cannot route is
      allowed on the origin so the policy never strands a mixed fleet; the
      policy view counts those agents so the gap is visible. Origin-only
      endpoints (shell, chat, self-update) are never refused for going direct:
      they have no relayed path to take.
    """
    if not settings.relay_routing_enabled:
        return
    policy = await tenant_policy(db, client_id)
    if policy is None or policy.mode != "strict":
        return
    if ctx is not None:
        if ctx.region_id != policy.region_id:
            relay = await db.get(Relay, ctx.relay_id)
            await record_refusal(
                db, relay=relay, key_id=ctx.key_id, code="relay_region_mismatch", path=path
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "relay_region_mismatch"},
            )
        return
    if agent_supports_relay_routing(agent) and is_relayable(method.upper(), path):
        metrics.increment("relay_residency_direct_refused_total")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "residency_route_required"},
        )


def order_routes(
    mode: str | None,
    home_region_id: str | None,
    relays: list[tuple[Relay, RelayRegion]],
    max_routes: int,
) -> list[tuple[Relay, RelayRegion]]:
    """Choose and order the relays an agent should try, best first.

    ``relays`` holds every relay currently eligible for new traffic (relay and
    region both ``active``), already sorted by region code then relay name so
    the result is deterministic. The origin is not part of this list: the
    caller appends it as the final fallback unless ``mode`` is ``strict``.
    """
    if mode is None or home_region_id is None:
        # No residency constraint: every eligible relay is fair game. The
        # deterministic input order keeps the manifest stable beat to beat, so
        # agents do not churn between equivalent routes.
        return relays[:max_routes]
    home = [pair for pair in relays if pair[0].region_id == home_region_id]
    if mode == "strict":
        return home[:max_routes]
    # preferred: home first so traffic stays in-region while it is healthy;
    # other regions are availability fallbacks, never a residency violation.
    others = [pair for pair in relays if pair[0].region_id != home_region_id]
    return (home + others)[:max_routes]


async def build_routing_manifest(
    db: AsyncSession, agent: Agent, client_id: str | None, now: datetime | None = None
) -> dict:
    """The unsigned manifest document for one agent."""
    now = now or _now()
    policy = await tenant_policy(db, client_id)
    rows = (
        await db.execute(
            select(Relay, RelayRegion)
            .join(RelayRegion, RelayRegion.id == Relay.region_id)
            .where(Relay.status == "active", RelayRegion.status == "active")
            .order_by(RelayRegion.code.asc(), Relay.name.asc(), Relay.id.asc())
        )
    ).all()
    mode = policy.mode if policy is not None else None
    home_region_id = policy.region_id if policy is not None else None
    chosen = order_routes(
        mode, home_region_id, [(r, g) for r, g in rows], settings.relay_max_routes
    )
    routes: list[dict] = [
        {
            "kind": "relay",
            "relay_id": relay.id,
            "region": region.code,
            "base_url": relay.base_url,
            "tls_spki_pins": list(relay.tls_spki_pins or []),
        }
        for relay, region in chosen
    ]
    if mode != "strict":
        routes.append({"kind": "origin"})
    home_code = ""
    if home_region_id is not None:
        home = await db.get(RelayRegion, home_region_id)
        home_code = home.code if home is not None else ""
    issued = int(now.timestamp())
    return {
        "manifest_version": MANIFEST_VERSION,
        "agent_id": agent.id,
        "issued_at": issued,
        "expires_at": issued + settings.relay_route_manifest_ttl_seconds,
        "residency_mode": mode or "none",
        "home_region": home_code,
        "routes": routes,
        "command_public_keys": public_key_bundle(),
    }


def encode_manifest(manifest: dict) -> bytes:
    """Deterministic JSON bytes. Agents verify these exact bytes, so they never
    need to re-canonicalize the document."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_manifest_bytes(manifest_bytes: bytes) -> list[dict[str, str]]:
    """Sign with every active/overlap key that has private material, so an
    agent mid-rotation can verify with whichever key it already trusts."""
    _, keys = load_keyring()
    signatures: list[dict[str, str]] = []
    for key_id in sorted(keys):
        key = keys[key_id]
        if key.status not in ("active", "overlap") or key.private_path is None:
            continue
        signature = key.private_key.sign(MANIFEST_CONTEXT + manifest_bytes)
        signatures.append(
            {"key_id": key_id, "signature": base64.b64encode(signature).decode("ascii")}
        )
    if not signatures:
        raise RuntimeError("no signing key can sign a routing manifest")
    return signatures


async def signed_routing_manifest(
    db: AsyncSession, agent: Agent, client_id: str | None
) -> dict[str, object] | None:
    """The heartbeat's ``routing_manifest`` field, or None when not offered."""
    if not settings.relay_routing_enabled or not agent_supports_relay_routing(agent):
        return None
    manifest_bytes = encode_manifest(await build_routing_manifest(db, agent, client_id))
    return {
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signatures": sign_manifest_bytes(manifest_bytes),
    }
