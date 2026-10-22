# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-region relay tests (issue #87).

Covers the trust boundary a relay sits on: platform-admin-only
administration, the relay key lifecycle, signed forwarding with clock-skew,
store-and-forward age, body, and replay bounds, tenant ingress residency
(preferred/strict, including the legacy-agent carve-out), the signed routing
manifest across a signing-key rotation, path-change audit continuity, and an
intact audit chain through all of it.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_relays.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from sqlalchemy import select, update  # noqa: E402

from app.core import audit, relays  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    RelayForwardReceipt,
    RelayKey,
)

PLATFORM = "platform@nodelink.test"
TENANT_ADMIN = "tenant-admin@nodelink.test"
OUTSIDER = "outsider@nodelink.test"
HEARTBEAT_PATH = "/api/v1/heartbeat"


@pytest.fixture(autouse=True)
def relay_settings(monkeypatch):
    monkeypatch.setattr(settings, "relay_routing_enabled", True)
    relays.refusal_audit_limiter.reset()
    yield
    relays.refusal_audit_limiter.reset()


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email=PLATFORM,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                ),
                Operator(
                    email=TENANT_ADMIN,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                ),
                Operator(
                    email=OUTSIDER,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def auth(client, email=PLATFORM):
    response = await client.post("/auth/login", json={"email": email, "password": _LOGIN})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def new_key() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private, pem


async def provision_tenant(client, *, capabilities=("relay-routing",)):
    headers = await auth(client)
    org = (await client.post("/clients", json={"name": f"T {uuid4().hex}"}, headers=headers)).json()
    site = (
        await client.post("/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers)
    ).json()
    token = (
        await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)
    ).json()["token"]
    enrollment = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "RELAY-PC",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert enrollment.status_code == 200, enrollment.text
    body = enrollment.json()
    return org["id"], body["agent_id"], body["agent_token"]


async def make_region(client, code: str) -> dict:
    response = await client.post(
        "/relay-regions", json={"code": code, "name": code.upper()}, headers=await auth(client)
    )
    assert response.status_code == 201, response.text
    return response.json()


async def make_relay(client, region_id: str, name: str, *, activate=True):
    """A relay with one registered key; returns (relay, key_id, private_key)."""
    headers = await auth(client)
    relay = await client.post(
        "/relays",
        json={"region_id": region_id, "name": name, "base_url": f"https://{name}.relay.test"},
        headers=headers,
    )
    assert relay.status_code == 201, relay.text
    relay = relay.json()
    private, pem = new_key()
    key_id = f"{name}-k1"
    added = await client.post(
        f"/relays/{relay['id']}/keys",
        json={
            "key_id": key_id,
            "public_key_pem": pem,
            "not_after": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
        headers=headers,
    )
    assert added.status_code == 201, added.text
    if activate:
        activated = await client.patch(
            f"/relays/{relay['id']}", json={"status": "active"}, headers=headers
        )
        assert activated.status_code == 200, activated.text
        relay = activated.json()
    return relay, key_id, private


def heartbeat_body(capabilities=("relay-routing",)) -> dict:
    return {
        "cpu_percent": 3.0,
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
        "supported_capabilities": list(capabilities),
    }


def forward_headers(
    relay_id: str,
    key_id: str,
    private: Ed25519PrivateKey,
    body: bytes,
    *,
    path: str = HEARTBEAT_PATH,
    method: str = "POST",
    timestamp: int | None = None,
    queued_at: int | None = None,
    nonce: str | None = None,
    sign_path: str | None = None,
) -> dict:
    now = int(time.time())
    timestamp = now if timestamp is None else timestamp
    queued_at = timestamp if queued_at is None else queued_at
    nonce = nonce or secrets.token_urlsafe(24)
    signature = private.sign(
        relays.canonical_forward_bytes(
            relay_id=relay_id,
            key_id=key_id,
            method=method,
            path=sign_path or path,
            body=body,
            timestamp=timestamp,
            queued_at=queued_at,
            nonce=nonce,
        )
    )
    return {
        relays.HEADER_RELAY_ID: relay_id,
        relays.HEADER_KEY_ID: key_id,
        relays.HEADER_TIMESTAMP: str(timestamp),
        relays.HEADER_QUEUED_AT: str(queued_at),
        relays.HEADER_NONCE: nonce,
        relays.HEADER_SIGNATURE: base64.b64encode(signature).decode("ascii"),
    }


async def relayed_beat(client, agent_token, relay_id, key_id, private, *, body=None, **kw):
    payload = json.dumps(body or heartbeat_body()).encode("utf-8")
    headers = forward_headers(relay_id, key_id, private, payload, **kw)
    headers.update(
        {"Authorization": f"Bearer {agent_token}", "Content-Type": "application/json"}
    )
    return await client.post("/heartbeat", content=payload, headers=headers)


async def direct_beat(client, agent_token, capabilities=("relay-routing",)):
    return await client.post(
        "/heartbeat",
        json=heartbeat_body(capabilities),
        headers={"Authorization": f"Bearer {agent_token}"},
    )


async def audit_rows(action: str) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        return list(
            (
                await db.execute(
                    select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
                )
            ).scalars()
        )


async def set_policy(client, client_id, region_id, mode):
    return await client.put(
        f"/clients/{client_id}/region-policy",
        json={"region_id": region_id, "mode": mode},
        headers=await auth(client),
    )


def decode_manifest(signed: dict) -> dict:
    return json.loads(base64.b64decode(signed["manifest_b64"]))


# --------------------------------------------------------------------------- #
# Administration and authorization
# --------------------------------------------------------------------------- #
async def test_relay_administration_is_platform_admin_only(client):
    region = await make_region(client, "us-east")
    tenant = await auth(client, TENANT_ADMIN)
    assert (await client.get("/relay-regions", headers=tenant)).status_code == 403
    assert (
        await client.post("/relay-regions", json={"code": "eu", "name": "EU"}, headers=tenant)
    ).status_code == 403
    assert (
        await client.post(
            "/relays",
            json={"region_id": region["id"], "name": "x", "base_url": "https://x.test"},
            headers=tenant,
        )
    ).status_code == 403


async def test_region_policy_read_is_tenant_scoped(client):
    client_id, _, _ = await provision_tenant(client)
    async with AsyncSessionLocal() as db:
        operator = await db.scalar(select(Operator).where(Operator.email == TENANT_ADMIN))
        db.add(
            OperatorClientMembership(
                operator_id=operator.id,
                client_id=client_id,
                role=ClientRole.client_admin,
                granted_by="test",
                reason="test",
            )
        )
        await db.commit()
    member = await client.get(
        f"/clients/{client_id}/region-policy", headers=await auth(client, TENANT_ADMIN)
    )
    assert member.status_code == 200
    assert member.json()["mode"] == "none"
    outsider = await client.get(
        f"/clients/{client_id}/region-policy", headers=await auth(client, OUTSIDER)
    )
    assert outsider.status_code == 404
    # A tenant admin may read but never set residency.
    region = await make_region(client, "eu-west")
    refused = await client.put(
        f"/clients/{client_id}/region-policy",
        json={"region_id": region["id"], "mode": "preferred"},
        headers=await auth(client, TENANT_ADMIN),
    )
    assert refused.status_code == 403


@pytest.mark.parametrize(
    "url",
    [
        "http://relay.test",
        "https://user:pw@relay.test",
        "https://relay.test/path",
        "https://relay.test?x=1",
        "https://relay.test#frag",
    ],
)
async def test_relay_base_url_must_be_a_plain_https_origin(client, url):
    region = await make_region(client, "us-east")
    response = await client.post(
        "/relays",
        json={"region_id": region["id"], "name": "bad", "base_url": url},
        headers=await auth(client),
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "relay_base_url_invalid"


async def test_relay_key_lifecycle_and_audit(client):
    headers = await auth(client)
    region = await make_region(client, "us-east")
    relay, key_id, _ = await make_relay(client, region["id"], "use1", activate=False)

    # A non-Ed25519 or reused key is refused.
    bad = await client.post(
        f"/relays/{relay['id']}/keys",
        json={
            "key_id": "garbage",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            "not_after": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        },
        headers=headers,
    )
    assert bad.json()["detail"]["code"] == "relay_key_invalid"
    too_long = await client.post(
        f"/relays/{relay['id']}/keys",
        json={
            "key_id": "far",
            "public_key_pem": new_key()[1],
            "not_after": (datetime.now(timezone.utc) + timedelta(days=500)).isoformat(),
        },
        headers=headers,
    )
    assert too_long.json()["detail"]["code"] == "relay_key_lifetime_invalid"

    # Two live keys at most (current + staged successor).
    _, pem2 = new_key()
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    second = await client.post(
        f"/relays/{relay['id']}/keys",
        json={"key_id": "use1-k2", "public_key_pem": pem2, "not_after": future},
        headers=headers,
    )
    assert second.status_code == 201
    third = await client.post(
        f"/relays/{relay['id']}/keys",
        json={"key_id": "use1-k3", "public_key_pem": new_key()[1], "not_after": future},
        headers=headers,
    )
    assert third.json()["detail"]["code"] == "relay_key_limit"

    retired = await client.post(f"/relays/{relay['id']}/keys/{key_id}/retire", headers=headers)
    assert retired.status_code == 200
    revoked = await client.post(
        f"/relays/{relay['id']}/keys/use1-k2/revoke",
        json={"reason": "suspected exposure"},
        headers=headers,
    )
    assert revoked.status_code == 200
    # No live key left: activation must refuse.
    activate = await client.patch(f"/relays/{relay['id']}", json={"status": "active"}, headers=headers)
    assert activate.json()["detail"]["code"] == "relay_has_no_key"

    for action in (
        "relay_region.created",
        "relay.registered",
        "relay.key_registered",
        "relay.key_retired",
        "relay.key_revoked",
    ):
        assert await audit_rows(action), action
    revoked_row = (await audit_rows("relay.key_revoked"))[0]
    assert "reason" not in revoked_row.detail and "reason_sha256" in revoked_row.detail


async def test_relay_revocation_revokes_every_key(client):
    headers = await auth(client)
    region = await make_region(client, "us-east")
    relay, key_id, _ = await make_relay(client, region["id"], "use1")
    response = await client.patch(f"/relays/{relay['id']}", json={"status": "revoked"}, headers=headers)
    assert response.status_code == 200
    assert {k["status"] for k in response.json()["keys"]} == {"revoked"}
    # Terminal.
    again = await client.patch(f"/relays/{relay['id']}", json={"status": "active"}, headers=headers)
    assert again.json()["detail"]["code"] == "relay_transition_invalid"


# --------------------------------------------------------------------------- #
# Forwarding
# --------------------------------------------------------------------------- #
async def test_relay_headers_are_refused_while_disabled(client, monkeypatch):
    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")
    monkeypatch.setattr(settings, "relay_routing_enabled", False)
    response = await relayed_beat(client, agent_token, relay["id"], key_id, private)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "relay_routing_disabled"


async def test_relayed_heartbeat_is_accepted_and_path_changes_are_audited_once(client):
    _, agent_id, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")

    first = await relayed_beat(client, agent_token, relay["id"], key_id, private)
    assert first.status_code == 200, first.text
    await relayed_beat(client, agent_token, relay["id"], key_id, private)
    assert (await direct_beat(client, agent_token)).status_code == 200
    await direct_beat(client, agent_token)

    changes = await audit_rows("agent.route_changed")
    assert [(e.detail["previous"], e.detail["current"]) for e in changes] == [
        ("", relay["id"]),
        (relay["id"], "origin"),
    ]
    assert changes[0].detail["region"] == "us-east"
    async with AsyncSessionLocal() as db:
        receipts = list((await db.execute(select(RelayForwardReceipt))).scalars())
    assert len(receipts) == 2
    assert {r.agent_id for r in receipts} == {agent_id}


async def test_store_and_forward_age_bound(client):
    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")
    now = int(time.time())
    held = await relayed_beat(
        client,
        agent_token,
        relay["id"],
        key_id,
        private,
        queued_at=now - settings.relay_max_forward_age_seconds + 5,
    )
    assert held.status_code == 200, held.text
    stale = await relayed_beat(
        client,
        agent_token,
        relay["id"],
        key_id,
        private,
        queued_at=now - settings.relay_max_forward_age_seconds - 5,
    )
    assert stale.status_code == 403
    assert stale.json()["detail"]["code"] == "relay_forward_too_old"


async def test_replayed_forward_is_refused(client):
    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")
    nonce = secrets.token_urlsafe(24)
    first = await relayed_beat(client, agent_token, relay["id"], key_id, private, nonce=nonce)
    assert first.status_code == 200
    replay = await relayed_beat(client, agent_token, relay["id"], key_id, private, nonce=nonce)
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == "relay_replay"
    refused = await audit_rows("relay.forward_refused")
    assert [e.detail["reason"] for e in refused] == ["relay_replay"]


async def _expire_key(key_id: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(RelayKey)
            .where(RelayKey.key_id == key_id)
            .values(not_after=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        await db.commit()


@pytest.mark.parametrize(
    "scenario,expected_status,expected_code",
    [
        ("bad_signature", 403, "relay_signature_invalid"),
        ("unknown_key", 403, "relay_key_unknown"),
        ("retired_key", 403, "relay_key_inactive"),
        ("revoked_key", 403, "relay_key_inactive"),
        ("expired_key", 403, "relay_key_expired"),
        ("future_skew", 403, "relay_clock_skew"),
        ("past_skew", 403, "relay_clock_skew"),
        ("body_too_large", 413, "relay_body_too_large"),
        ("unsupported_route", 403, "relay_route_unsupported"),
        ("pending_relay", 403, "relay_not_active"),
        ("region_disabled", 403, "relay_region_disabled"),
        ("unknown_relay", 403, "relay_unknown"),
        ("incomplete_headers", 400, "relay_headers_incomplete"),
    ],
)
async def test_forward_refusals_fail_closed(
    client, monkeypatch, scenario, expected_status, expected_code
):
    _, _, agent_token = await provision_tenant(client)
    headers = await auth(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(
        client, region["id"], "use1", activate=scenario != "pending_relay"
    )
    kwargs: dict = {}
    relay_id = relay["id"]
    if scenario == "bad_signature":
        private = Ed25519PrivateKey.generate()
    elif scenario == "unknown_key":
        key_id = "never-registered"
    elif scenario == "retired_key":
        await client.post(f"/relays/{relay_id}/keys/{key_id}/retire", headers=headers)
    elif scenario == "revoked_key":
        await client.post(
            f"/relays/{relay_id}/keys/{key_id}/revoke", json={"reason": "x"}, headers=headers
        )
    elif scenario == "expired_key":
        await _expire_key(key_id)
    elif scenario == "future_skew":
        kwargs["timestamp"] = int(time.time()) + settings.relay_clock_skew_seconds + 30
    elif scenario == "past_skew":
        kwargs["timestamp"] = int(time.time()) - settings.relay_clock_skew_seconds - 30
    elif scenario == "body_too_large":
        monkeypatch.setattr(settings, "relay_max_forward_body_bytes", 4096)
        kwargs["body"] = {**heartbeat_body(), "logged_in_user": "x" * 5000}
    elif scenario == "region_disabled":
        await client.patch(
            f"/relay-regions/{region['id']}", json={"status": "disabled"}, headers=headers
        )
    elif scenario == "unknown_relay":
        relay_id = str(uuid4())

    if scenario == "unsupported_route":
        payload = b"{}"
        fwd = forward_headers(relay_id, key_id, private, payload, path="/api/v1/enroll")
        response = await client.post(
            "/enroll", content=payload, headers={**fwd, "Content-Type": "application/json"}
        )
    elif scenario == "incomplete_headers":
        response = await client.post(
            "/heartbeat",
            json=heartbeat_body(),
            headers={relays.HEADER_RELAY_ID: relay_id, "Authorization": f"Bearer {agent_token}"},
        )
    else:
        response = await relayed_beat(client, agent_token, relay_id, key_id, private, **kwargs)
    assert response.status_code == expected_status, response.text
    assert response.json()["detail"]["code"] == expected_code

    refused = await audit_rows("relay.forward_refused")
    if scenario in ("unknown_relay", "incomplete_headers"):
        # Unauthenticated noise never reaches the audit chain.
        assert refused == []
    else:
        assert [e.detail["reason"] for e in refused] == [expected_code]
        assert refused[0].detail["relay_id"] == relay["id"]


async def test_refusal_audit_is_rate_limited_with_suppressed_count(client, monkeypatch):
    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, _ = await make_relay(client, region["id"], "use1")
    forged = Ed25519PrivateKey.generate()
    for _ in range(3):
        await relayed_beat(client, agent_token, relay["id"], key_id, forged)
    assert len(await audit_rows("relay.forward_refused")) == 1
    monkeypatch.setattr(relays.refusal_audit_limiter, "window_seconds", 0.0)
    await relayed_beat(client, agent_token, relay["id"], key_id, forged)
    rows = await audit_rows("relay.forward_refused")
    assert [r.detail["suppressed_count"] for r in rows] == [0, 2]


async def test_signature_binds_path_and_body(client):
    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")
    # Signed for another endpoint, presented on the heartbeat.
    moved = await relayed_beat(
        client, agent_token, relay["id"], key_id, private, sign_path="/api/v1/agents/me/inventory"
    )
    assert moved.json()["detail"]["code"] == "relay_signature_invalid"


# --------------------------------------------------------------------------- #
# Residency
# --------------------------------------------------------------------------- #
async def test_strict_policy_requires_an_active_home_relay(client):
    client_id, _, _ = await provision_tenant(client)
    region = await make_region(client, "eu-west")
    response = await set_policy(client, client_id, region["id"], "strict")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "region_has_no_active_relay"


async def test_strict_residency_routes_only_through_the_home_region(client):
    client_id, _, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    us = await make_region(client, "us-east")
    eu_relay, eu_key, eu_private = await make_relay(client, eu["id"], "euw1")
    us_relay, us_key, us_private = await make_relay(client, us["id"], "use1")
    assert (await set_policy(client, client_id, eu["id"], "strict")).status_code == 200

    home = await relayed_beat(client, agent_token, eu_relay["id"], eu_key, eu_private)
    assert home.status_code == 200, home.text
    foreign = await relayed_beat(client, agent_token, us_relay["id"], us_key, us_private)
    assert foreign.status_code == 403
    assert foreign.json()["detail"]["code"] == "relay_region_mismatch"
    direct = await direct_beat(client, agent_token)
    assert direct.status_code == 403
    assert direct.json()["detail"]["code"] == "residency_route_required"

    refused = await audit_rows("relay.forward_refused")
    assert [(e.detail["reason"], e.detail["relay_id"]) for e in refused] == [
        ("relay_region_mismatch", us_relay["id"])
    ]
    policy_set = await audit_rows("tenant.region_policy_set")
    assert policy_set[-1].detail["mode"] == "strict"


async def test_strict_residency_leaves_origin_only_endpoints_reachable(client):
    client_id, _, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    await make_relay(client, eu["id"], "euw1")
    assert (await set_policy(client, client_id, eu["id"], "strict")).status_code == 200
    # Self-update reports are origin-only; strict residency must not refuse
    # them for going direct (the body is irrelevant to this check).
    response = await client.post(
        "/agents/me/self-update/report",
        json={},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    detail = response.json().get("detail")
    assert not (isinstance(detail, dict) and detail.get("code") == "residency_route_required")


async def test_strict_residency_never_strands_a_legacy_agent(client):
    client_id, _, agent_token = await provision_tenant(client, capabilities=())
    eu = await make_region(client, "eu-west")
    await make_relay(client, eu["id"], "euw1")
    assert (await set_policy(client, client_id, eu["id"], "strict")).status_code == 200
    legacy = await direct_beat(client, agent_token, capabilities=())
    assert legacy.status_code == 200
    assert legacy.json()["routing_manifest"] is None
    view = await client.get(f"/clients/{client_id}/region-policy", headers=await auth(client))
    assert view.json()["legacy_direct_agents"] == 1
    assert view.json()["home_region_active_relays"] == 1


async def test_cross_tenant_policies_are_independent(client):
    strict_client, _, strict_token = await provision_tenant(client)
    _, _, free_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    us = await make_region(client, "us-east")
    await make_relay(client, eu["id"], "euw1")
    us_relay, us_key, us_private = await make_relay(client, us["id"], "use1")
    await set_policy(client, strict_client, eu["id"], "strict")

    assert (
        await relayed_beat(client, free_token, us_relay["id"], us_key, us_private)
    ).status_code == 200
    assert (
        await relayed_beat(client, strict_token, us_relay["id"], us_key, us_private)
    ).status_code == 403


# --------------------------------------------------------------------------- #
# Routing manifest
# --------------------------------------------------------------------------- #
def _verify(signed: dict, public_pems: dict[str, str]) -> set[str]:
    manifest_bytes = base64.b64decode(signed["manifest_b64"])
    verified = set()
    for item in signed["signatures"]:
        pem = public_pems.get(item["key_id"])
        if pem is None:
            continue
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        key.verify(base64.b64decode(item["signature"]), relays.MANIFEST_CONTEXT + manifest_bytes)
        verified.add(item["key_id"])
    return verified


async def test_manifest_preferred_orders_home_region_first(client):
    client_id, agent_id, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    us = await make_region(client, "us-east")
    us_relay, _, _ = await make_relay(client, us["id"], "use1")
    eu_relay, _, _ = await make_relay(client, eu["id"], "euw1")
    draining, _, _ = await make_relay(client, eu["id"], "euw2")
    await client.patch(
        f"/relays/{draining['id']}", json={"status": "draining"}, headers=await auth(client)
    )
    await set_policy(client, client_id, eu["id"], "preferred")

    ack = (await direct_beat(client, agent_token)).json()
    manifest = decode_manifest(ack["routing_manifest"])
    assert manifest["manifest_version"] == "routing-manifest-v1"
    assert manifest["agent_id"] == agent_id
    assert manifest["residency_mode"] == "preferred"
    assert manifest["home_region"] == "eu-west"
    assert [r.get("relay_id", r["kind"]) for r in manifest["routes"]] == [
        eu_relay["id"],
        us_relay["id"],
        "origin",
    ]
    assert manifest["command_public_keys"] == ack["command_public_keys"]
    assert manifest["expires_at"] - manifest["issued_at"] == settings.relay_route_manifest_ttl_seconds
    assert _verify(ack["routing_manifest"], ack["command_public_keys"])


async def test_manifest_strict_excludes_other_regions_and_origin(client):
    client_id, _, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    us = await make_region(client, "us-east")
    await make_relay(client, us["id"], "use1")
    eu_relay, eu_key, eu_private = await make_relay(client, eu["id"], "euw1")
    await set_policy(client, client_id, eu["id"], "strict")
    ack = (await relayed_beat(client, agent_token, eu_relay["id"], eu_key, eu_private)).json()
    manifest = decode_manifest(ack["routing_manifest"])
    assert [r.get("relay_id", r["kind"]) for r in manifest["routes"]] == [eu_relay["id"]]


async def test_manifest_respects_route_cap(client, monkeypatch):
    client_id, _, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    for index in range(4):
        await make_relay(client, eu["id"], f"euw{index}")
    await set_policy(client, client_id, eu["id"], "preferred")
    monkeypatch.setattr(settings, "relay_max_routes", 2)
    ack = (await direct_beat(client, agent_token)).json()
    routes = decode_manifest(ack["routing_manifest"])["routes"]
    assert [r["kind"] for r in routes] == ["relay", "relay", "origin"]


async def test_manifest_is_signed_by_every_key_during_rotation(client, monkeypatch, tmp_path):
    keys = {}
    for key_id in ("old", "new"):
        private = Ed25519PrivateKey.generate()
        path = tmp_path / f"{key_id}.pem"
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        keys[key_id] = str(path)
    registry = tmp_path / "keyring.json"
    registry.write_text(
        json.dumps(
            {
                "active_key_id": "new",
                "keys": {
                    "new": {"status": "active", "private_key_path": keys["new"]},
                    "old": {"status": "overlap", "private_key_path": keys["old"]},
                },
            }
        )
    )
    monkeypatch.setattr(settings, "command_signing_keyring_path", str(registry))
    _, _, agent_token = await provision_tenant(client)
    ack = (await direct_beat(client, agent_token)).json()
    signed = ack["routing_manifest"]
    assert [s["key_id"] for s in signed["signatures"]] == ["new", "old"]
    # An agent that only trusts the outgoing key still verifies the manifest
    # that introduces the incoming one.
    only_old = {"old": ack["command_public_keys"]["old"]}
    assert _verify(signed, only_old) == {"old"}


async def test_no_manifest_when_disabled_or_unsupported(client, monkeypatch):
    _, _, agent_token = await provision_tenant(client)
    legacy = await direct_beat(client, agent_token, capabilities=())
    assert legacy.json()["routing_manifest"] is None
    monkeypatch.setattr(settings, "relay_routing_enabled", False)
    off = await direct_beat(client, agent_token)
    assert off.json()["routing_manifest"] is None
    assert await audit_rows("agent.route_changed") != []  # only from the enabled beat


# --------------------------------------------------------------------------- #
# Audit continuity and retention
# --------------------------------------------------------------------------- #
async def test_audit_chain_stays_intact_through_relay_activity(client):
    client_id, _, agent_token = await provision_tenant(client)
    eu = await make_region(client, "eu-west")
    relay, key_id, private = await make_relay(client, eu["id"], "euw1")
    await set_policy(client, client_id, eu["id"], "strict")
    await relayed_beat(client, agent_token, relay["id"], key_id, private)
    await relayed_beat(client, agent_token, relay["id"], key_id, Ed25519PrivateKey.generate())
    await direct_beat(client, agent_token)
    async with AsyncSessionLocal() as db:
        ok, broken = await audit.verify_chain(db)
        seqs = list((await db.execute(select(AuditEvent.seq).order_by(AuditEvent.seq))).scalars())
    assert ok, broken
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))


async def test_retention_prunes_only_aged_receipts(client):
    from app.core.retention import prune_expired

    _, _, agent_token = await provision_tenant(client)
    region = await make_region(client, "us-east")
    relay, key_id, private = await make_relay(client, region["id"], "use1")
    await relayed_beat(client, agent_token, relay["id"], key_id, private)
    await relayed_beat(client, agent_token, relay["id"], key_id, private)
    async with AsyncSessionLocal() as db:
        oldest = await db.scalar(select(RelayForwardReceipt.id).limit(1))
        await db.execute(
            update(RelayForwardReceipt)
            .where(RelayForwardReceipt.id == oldest)
            .values(received_at=datetime.now(timezone.utc) - timedelta(days=30))
        )
        await db.commit()
        result = await prune_expired(db)
        await db.commit()
        remaining = list((await db.execute(select(RelayForwardReceipt))).scalars())
    assert result.relay_receipts_deleted == 1
    assert len(remaining) == 1


async def test_route_column_starts_empty_for_new_agents(client):
    _, agent_id, _ = await provision_tenant(client)
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
    assert agent.relay_route is None


# --------------------------------------------------------------------------- #
# PostgreSQL: the replay guard holds under concurrency
# --------------------------------------------------------------------------- #
@pytest.mark.postgres
async def test_concurrent_forwards_with_one_nonce_accept_exactly_one(pg_engine):
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.models import Relay, RelayRegion
    from tests.conftest import wait_for_lock_waiters

    maker = async_sessionmaker(pg_engine, expire_on_commit=False, autoflush=False)
    private, pem = new_key()
    async with maker() as db:
        region = RelayRegion(code="us-east", name="US", status="active")
        db.add(region)
        await db.flush()
        relay = Relay(region_id=region.id, name="use1", base_url="https://use1.test", status="active")
        db.add(relay)
        await db.flush()
        db.add(
            RelayKey(
                relay_id=relay.id,
                key_id="use1-k1",
                public_key_pem=pem,
                public_key_sha256=relays.public_key_fingerprint(pem),
                status="active",
                not_after=datetime.now(timezone.utc) + timedelta(days=1),
            )
        )
        await db.commit()
        relay_id = relay.id

    body = b"{}"
    nonce = secrets.token_urlsafe(24)
    headers = forward_headers(relay_id, "use1-k1", private, body, nonce=nonce)

    # Hold the (relay_id, nonce) slot so both forwards park on the unique index
    # after passing every application check, then release it.
    holder = await pg_engine.connect()
    tx = await holder.begin()
    await holder.execute(
        RelayForwardReceipt.__table__.insert().values(
            id=str(uuid4()),
            relay_id=relay_id,
            key_id="use1-k1",
            nonce=nonce,
            method="POST",
            path=HEARTBEAT_PATH,
            queued_at=datetime.now(timezone.utc),
            received_at=datetime.now(timezone.utc),
        )
    )

    async def attempt():
        async with maker() as db:
            try:
                await relays.verify_forward(
                    db, method="POST", path=HEARTBEAT_PATH, headers=headers, body=body
                )
                return "accepted"
            except relays.RelayRefusal as refusal:
                return refusal.code

    tasks = [asyncio.create_task(attempt()) for _ in range(2)]
    await wait_for_lock_waiters(pg_engine, 2)
    await tx.rollback()
    await holder.close()
    outcomes = sorted(await asyncio.gather(*tasks))
    assert outcomes == ["accepted", "relay_replay"]
    async with maker() as db:
        receipts = list((await db.execute(select(RelayForwardReceipt))).scalars())
    assert len(receipts) == 1
