# SPDX-License-Identifier: AGPL-3.0-only
"""Operator-facing audit timeline and event detail views (issue #78).

Covers sequence-ordered pagination, filter behavior, the registry-backed event
type list, single-event detail and its 404, authorization at the API boundary,
and the audit evidence the views themselves produce.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_rmm.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.redaction import AUDIT_DETAIL_SCHEMAS  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="auditor@nodelink.test",
                password_hash=hash_password("auditor-password"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        db.add(
            Operator(
                email="ro@nodelink.test",
                password_hash=hash_password("ro-password"),
                role=OperatorRole.readonly,
            )
        )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "auditor@nodelink.test", "password": "auditor-password"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _readonly_token(c) -> str:
    login = await c.post(
        "/auth/login",
        json={"email": "ro@nodelink.test", "password": "ro-password"},
    )
    return login.json()["access_token"]


async def _make_events(c, count: int) -> None:
    """Create real audited work so the chain has sequenced events to page."""
    for _ in range(count):
        await c.post("/clients", json={"name": f"Clinic {uuid4().hex}"})


@pytest.mark.asyncio
async def test_event_types_come_from_the_redaction_registry(client):
    body = (await client.get("/audit/event-types")).json()
    # Exact parity: a filter list that drifts from the registry would offer
    # actions the chain can never contain, or hide ones it does.
    assert body["items"] == sorted(AUDIT_DETAIL_SCHEMAS)
    assert "client.created" in body["items"]


@pytest.mark.asyncio
async def test_timeline_pages_newest_first_without_repeating_or_skipping(client):
    await _make_events(client, 6)

    page1 = (await client.get("/audit/events?page=1&page_size=5")).json()
    assert page1["page"] == 1
    assert page1["page_size"] == 5
    assert len(page1["items"]) == 5
    ceiling = page1["before_seq"]
    assert ceiling is not None
    assert max(item["seq"] for item in page1["items"]) == ceiling

    page2 = (
        await client.get(f"/audit/events?page=2&page_size=5&before_seq={ceiling}")
    ).json()
    assert page2["before_seq"] == ceiling

    seqs = [item["seq"] for item in page1["items"] + page2["items"]]
    # Strictly descending across the page boundary: no row repeats and none is
    # skipped, which is what makes a sequence gap meaningful evidence. Listing
    # the timeline appends its own audit event, so without the ceiling the
    # second page would shift down by one and repeat a row.
    assert seqs == sorted(seqs, reverse=True)
    assert len(set(seqs)) == len(seqs)

    # The snapshot is stable against everything appended after it was taken.
    assert page1["total"] == page2["total"]
    await _make_events(client, 3)
    repeat = (
        await client.get(f"/audit/events?page=1&page_size=5&before_seq={ceiling}")
    ).json()
    assert repeat["total"] == page1["total"]
    assert [item["id"] for item in repeat["items"]] == [
        item["id"] for item in page1["items"]
    ]

    # A fresh request with no ceiling takes a new snapshot that includes them.
    fresh = (await client.get("/audit/events?page=1&page_size=5")).json()
    assert fresh["before_seq"] > ceiling
    assert fresh["total"] > page1["total"]

    # Bounds are rejected rather than silently clamped.
    assert (await client.get("/audit/events?page=0")).status_code == 422
    assert (await client.get("/audit/events?page_size=101")).status_code == 422
    assert (await client.get("/audit/events?before_seq=0")).status_code == 422


@pytest.mark.asyncio
async def test_an_empty_chain_reports_no_ceiling_instead_of_failing(client):
    """A deployment with no sequenced events must still answer the timeline."""
    async with AsyncSessionLocal() as db:
        for event in (await db.execute(select(AuditEvent))).scalars().all():
            await db.delete(event)
        await db.commit()

    body = (await client.get("/audit/events")).json()
    assert body["before_seq"] is None
    assert body["total"] == 0
    assert body["items"] == []


@pytest.mark.asyncio
async def test_filters_narrow_the_timeline_and_report_the_filtered_total(client):
    await _make_events(client, 3)

    filtered = (
        await client.get("/audit/events?event_type=client.created&page_size=100")
    ).json()
    assert filtered["total"] == 3
    assert {item["action"] for item in filtered["items"]} == {"client.created"}

    # An action no producer emits returns an empty page, not an error.
    unknown = (await client.get("/audit/events?event_type=nope.nope")).json()
    assert unknown["total"] == 0
    assert unknown["items"] == []

    by_actor = (
        await client.get("/audit/events?actor=auditor&page_size=100")
    ).json()
    assert by_actor["total"] >= 3
    assert all("auditor" in item["actor"] for item in by_actor["items"])

    missing_actor = (await client.get("/audit/events?actor=nobody@example.test")).json()
    assert missing_actor["total"] == 0


@pytest.mark.asyncio
async def test_event_detail_returns_the_sanitized_record_and_404s_cleanly(client):
    await _make_events(client, 1)
    listed = (await client.get("/audit/events?event_type=client.created")).json()
    target = listed["items"][0]

    detail = (await client.get(f"/audit/events/{target['id']}")).json()
    assert detail["id"] == target["id"]
    assert detail["action"] == "client.created"
    assert detail["seq"] == target["seq"]
    # The stored detail is the redaction policy's output: the client's name is
    # only present as a digest, never as prose.
    assert set(detail["detail"]) == AUDIT_DETAIL_SCHEMAS["client.created"].stored_fields
    assert "name" not in detail["detail"]

    missing = await client.get(f"/audit/events/{uuid4()}")
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_reading_the_audit_views_is_itself_audited(client):
    await _make_events(client, 1)
    listed = (await client.get("/audit/events?event_type=client.created&page=2")).json()
    target = listed["items"][0] if listed["items"] else None
    if target is None:
        target = (await client.get("/audit/events?event_type=client.created")).json()["items"][0]
    await client.get(f"/audit/events/{target['id']}")

    async with AsyncSessionLocal() as db:
        timeline = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "audit_timeline.viewed")
            )
        ).scalars().all()
        detail = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "audit_event.viewed")
            )
        ).scalars().all()

    assert timeline, "listing the timeline must record who read it"
    assert detail, "opening an event must record who read it"
    assert all(event.actor == "auditor@nodelink.test" for event in timeline + detail)

    viewed = detail[0]
    assert viewed.detail["event_id"] == target["id"]
    assert viewed.detail["action"] == "client.created"

    # A free-text actor filter is recorded as a boolean and an unregistered
    # event type is collapsed, so a query string cannot write prose into the
    # tamper-evident chain.
    await client.get("/audit/events?actor=secret-prose&event_type=made.up")
    async with AsyncSessionLocal() as db:
        latest = (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "audit_timeline.viewed")
                .order_by(AuditEvent.seq.desc())
                .limit(1)
            )
        ).scalar_one()
    assert latest.detail["actor_filter"] is True
    assert latest.detail["event_type"] == "unregistered"
    assert "secret-prose" not in str(latest.detail)


@pytest.mark.asyncio
async def test_audit_views_require_an_operator_session(client):
    unauthenticated = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
    )
    async with unauthenticated as anon:
        for path in (
            "/audit/events",
            "/audit/event-types",
            f"/audit/events/{uuid4()}",
            "/audit/verify",
            "/audit/anchors",
            "/audit/publication-status",
        ):
            assert (await anon.get(path)).status_code == 401, path

    # Readonly is enough to read evidence, and still cannot create an anchor.
    token = await _readonly_token(client)
    readonly = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t/api/v1",
        headers={"Authorization": f"Bearer {token}"},
    )
    async with readonly as ro:
        assert (await ro.get("/audit/events")).status_code == 200
        assert (await ro.get("/audit/event-types")).status_code == 200
        assert (await ro.get("/audit/verify")).status_code == 200
        assert (await ro.post("/audit/anchors")).status_code == 403


@pytest.mark.asyncio
async def test_chain_stays_verifiable_while_the_views_append_to_it(client):
    await _make_events(client, 2)
    await client.get("/audit/events")
    listed = (await client.get("/audit/events")).json()
    await client.get(f"/audit/events/{listed['items'][0]['id']}")

    verify = (await client.get("/audit/verify")).json()
    assert verify["intact"] is True
    assert verify["first_broken_event_id"] is None

    anchor = await client.post("/audit/anchors")
    assert anchor.status_code == 200
    anchor_id = anchor.json()["id"]
    check = (await client.get(f"/audit/anchors/{anchor_id}/verify")).json()
    assert check["intact"] is True
