# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for Merkle anchoring of the audit chain.

Behavior under test:
  - the Merkle fold is correct for 1, 2, and odd leaf counts
  - an anchor covers the chain prefix and verifies while it is untouched
  - tampering with a covered event breaks anchor verification even when the
    tamper keeps the hash chain internally consistent (a full rebuild) — the
    scenario the plain chain check cannot catch
  - anchoring with an empty chain is a 400
  - creating an anchor requires the operator role; verification is readonly

Run just this file:  pytest tests/test_anchoring.py -q
"""
from __future__ import annotations

import hashlib
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_anchoring.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core import audit  # noqa: E402
from app.core.anchor import merkle_root  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="anchor-op@nodelink.test",
                password_hash=hash_password("anchor-pass"),
                role=OperatorRole.operator,
            )
        )
        db.add(
            Operator(
                email="anchor-viewer@nodelink.test",
                password_hash=hash_password("viewer-pass"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        r = await c.post(
            "/auth/login",
            json={"email": "anchor-op@nodelink.test", "password": "anchor-pass"},
        )
        c.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _seed_events(n: int) -> None:
    async with AsyncSessionLocal() as db:
        for i in range(n):
            await audit.record(db, action="test.event", detail={"i": i})
        await db.commit()


# --------------------------------------------------------------------------- #
# The Merkle fold itself
# --------------------------------------------------------------------------- #
def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_merkle_single_leaf_is_identity():
    leaf = hashlib.sha256(b"a").hexdigest()
    assert merkle_root([leaf]) == leaf


def test_merkle_pair_is_hash_of_concatenation():
    a, b = _h(b"a"), _h(b"b")
    assert merkle_root([a.hex(), b.hex()]) == _h(a + b).hex()


def test_merkle_odd_leaf_carried_up():
    a, b, c = _h(b"a"), _h(b"b"), _h(b"c")
    # Level 1: H(a||b), c carried up. Root: H(H(a||b) || c).
    assert merkle_root([a.hex(), b.hex(), c.hex()]) == _h(_h(a + b) + c).hex()


def test_merkle_rejects_empty():
    with pytest.raises(ValueError):
        merkle_root([])


# --------------------------------------------------------------------------- #
# Anchor lifecycle over the API
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_anchor_covers_chain_and_verifies(client):
    await _seed_events(5)

    r = await client.post("/audit/anchors")
    assert r.status_code == 200
    body = r.json()
    assert body["event_count"] == 5
    assert len(body["merkle_root"]) == 64

    v = (await client.get(f"/audit/anchors/{body['id']}/verify")).json()
    assert v["intact"] is True and v["reason"] is None

    # The anchoring itself is audited, so a second anchor covers more events
    # (5 + the audit.anchored event).
    r2 = await client.post("/audit/anchors")
    assert r2.json()["event_count"] == 6
    anchors = (await client.get("/audit/anchors")).json()
    assert [a["id"] for a in anchors] == [body["id"], r2.json()["id"]]


@pytest.mark.asyncio
async def test_consistent_rebuild_defeats_chain_check_but_not_anchor(client):
    await _seed_events(3)
    anchor_id = (await client.post("/audit/anchors")).json()["id"]

    # Simulate a privileged attacker: alter one covered event and REBUILD the
    # whole hash chain so it is internally consistent again.
    from sqlalchemy import select
    from app.core.audit import _hash_event, _GENESIS
    from app.models.models import AuditEvent

    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(
                select(AuditEvent).order_by(AuditEvent.ts.asc(), AuditEvent.id.asc())
            )
        ).scalars().all()
        events[1].actor = "attacker"
        prev = _GENESIS
        for ev in events:
            ev.prev_hash = prev
            ev.event_hash = _hash_event(
                prev, ev.ts_iso, ev.actor, ev.action, ev.agent_id, ev.detail
            )
            prev = ev.event_hash
        await db.commit()

    # The plain chain check is fooled by the consistent rebuild...
    chain = (await client.get("/audit/verify")).json()
    assert chain["intact"] is True

    # ...but the anchor still holds the pre-tamper root and catches it.
    v = (await client.get(f"/audit/anchors/{anchor_id}/verify")).json()
    assert v["intact"] is False
    assert v["reason"] == "merkle root mismatch"


@pytest.mark.asyncio
async def test_anchor_requires_events(client):
    r = await client.post("/audit/anchors")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_anchor_creation_requires_operator_role(client):
    await _seed_events(1)
    r = await client.post(
        "/auth/login",
        json={"email": "anchor-viewer@nodelink.test", "password": "viewer-pass"},
    )
    viewer_auth = {"Authorization": f"Bearer {r.json()['access_token']}"}

    assert (await client.post("/audit/anchors", headers=viewer_auth)).status_code == 403
    # Read-only may still list and verify.
    assert (await client.get("/audit/anchors", headers=viewer_auth)).status_code == 200
