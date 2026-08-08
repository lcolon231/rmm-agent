# SPDX-License-Identifier: AGPL-3.0-only
"""Complete cross-endpoint task-run history and dispatch provenance (issue #50).

Covers the run provenance persisted at dispatch (actor, script-library origin,
dispatch audit link), fail-closed rejection of incoherent script provenance,
and the global /task-runs view: cross-endpoint aggregation, filters,
pagination, and effective-expiry reporting.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_rmm.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    Command,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
    ScriptLanguage,
    ScriptLibraryItem,
    ScriptParameterValueSet,
    ScriptVersion,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="runs@nodelink.test",
                password_hash=hash_password("runs-password"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "runs@nodelink.test", "password": "runs-password"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enroll(c, hostname: str = "PC1") -> str:
    cl = (await c.post("/clients", json={"name": f"Clinic {uuid4().hex}"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": hostname,
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
            },
        )
    ).json()
    return enr["agent_id"]


async def _dispatch(c, agent_id: str, script: str, **extra) -> dict:
    body = {"kind": "shell", "payload": {"script": script}, "ttl_seconds": 300}
    body.update(extra)
    r = await c.post(f"/agents/{agent_id}/commands", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def _seed_script_version(value_set: bool = True) -> tuple[str, str | None]:
    """Create an immutable script version (and optional value set) in the DB."""
    content = "Write-Output 'hi'"
    async with AsyncSessionLocal() as db:
        item = ScriptLibraryItem(
            name="Cleanup",
            normalized_name=f"cleanup-{uuid4().hex}",
            created_by="runs@nodelink.test",
        )
        db.add(item)
        await db.flush()
        version = ScriptVersion(
            script_id=item.id,
            version=1,
            language=ScriptLanguage.powershell,
            content=content,
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            content_bytes=len(content.encode()),
            supported_platforms=["windows"],
            created_by="runs@nodelink.test",
        )
        db.add(version)
        await db.flush()
        value_set_id = None
        if value_set:
            vs = ScriptParameterValueSet(
                script_version_id=version.id,
                request_id=uuid4().hex,
                encrypted_values="ciphertext",
                values_fingerprint="c" * 64,
                provided_keys=["path"],
                defaulted_keys=[],
                secret_keys=[],
                created_by="runs@nodelink.test",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            db.add(vs)
            await db.flush()
            value_set_id = vs.id
        version_id = version.id
        await db.commit()
    return version_id, value_set_id


@pytest.mark.asyncio
async def test_dispatch_records_actor_and_script_provenance(client):
    agent_id = await _enroll(client)
    version_id, value_set_id = await _seed_script_version()
    cmd = await _dispatch(
        client,
        agent_id,
        "echo provenance",
        script_version_id=version_id,
        script_parameter_value_set_id=value_set_id,
    )

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Command).where(Command.id == cmd["id"]))
        ).scalar_one()
    assert row.actor_email == "runs@nodelink.test"
    assert row.actor_operator_id is not None
    assert row.script_version_id == version_id
    assert row.script_parameter_value_set_id == value_set_id
    # The run points back at its place in the tamper-evident audit chain.
    assert row.dispatch_audit_event_id is not None
    assert row.attempt == 1

    listed = (await client.get("/task-runs")).json()
    item = next(i for i in listed["items"] if i["id"] == cmd["id"])
    assert item["actor_email"] == "runs@nodelink.test"
    assert item["script_version_id"] == version_id
    assert item["hostname"] == "PC1"
    # Metadata view only: captured output never rides the history row.
    assert "stdout" not in item


@pytest.mark.asyncio
async def test_ad_hoc_dispatch_has_null_script_provenance(client):
    agent_id = await _enroll(client)
    cmd = await _dispatch(client, agent_id, "echo adhoc")
    item = next(
        i for i in (await client.get("/task-runs")).json()["items"] if i["id"] == cmd["id"]
    )
    assert item["script_version_id"] is None
    assert item["script_parameter_value_set_id"] is None
    assert item["actor_email"] == "runs@nodelink.test"


@pytest.mark.asyncio
async def test_incoherent_script_provenance_is_rejected(client):
    agent_id = await _enroll(client)
    version_id, value_set_id = await _seed_script_version()
    other_version_id, _ = await _seed_script_version(value_set=False)

    # Value set without a version.
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "shell",
            "payload": {"script": "x"},
            "script_parameter_value_set_id": value_set_id,
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "script_parameter_value_set_requires_version"

    # Unknown version.
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "shell", "payload": {"script": "x"}, "script_version_id": "nope"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "script_version_not_found"

    # Value set that belongs to a different version.
    r = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "shell",
            "payload": {"script": "x"},
            "script_version_id": other_version_id,
            "script_parameter_value_set_id": value_set_id,
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "script_parameter_value_set_mismatch"

    # None of the rejected dispatches created a run.
    assert (await client.get("/task-runs")).json()["total"] == 0


@pytest.mark.asyncio
async def test_history_aggregates_across_endpoints_newest_first(client):
    agent_a = await _enroll(client, "PC-A")
    agent_b = await _enroll(client, "PC-B")
    a1 = await _dispatch(client, agent_a, "echo a1")
    b1 = await _dispatch(client, agent_b, "echo b1")
    a2 = await _dispatch(client, agent_a, "echo a2")

    listed = (await client.get("/task-runs")).json()
    assert listed["total"] == 3
    ids = [i["id"] for i in listed["items"]]
    assert set(ids) == {a1["id"], b1["id"], a2["id"]}
    # Newest first: the last dispatch leads.
    assert ids[0] == a2["id"]
    # Rows from both endpoints appear with their hostnames.
    hosts = {i["hostname"] for i in listed["items"]}
    assert hosts == {"PC-A", "PC-B"}


@pytest.mark.asyncio
async def test_filters_and_pagination(client):
    agent_a = await _enroll(client, "PC-A")
    agent_b = await _enroll(client, "PC-B")
    for i in range(3):
        await _dispatch(client, agent_a, f"echo a{i}")
    b = await _dispatch(client, agent_b, "echo b")

    # Filter by endpoint.
    only_b = (await client.get(f"/task-runs?agent_id={agent_b}")).json()
    assert only_b["total"] == 1
    assert only_b["items"][0]["id"] == b["id"]

    # Filter by status: everything is queued so far.
    queued = (await client.get("/task-runs?status=queued")).json()
    assert queued["total"] == 4
    assert (await client.get("/task-runs?status=succeeded")).json()["total"] == 0

    # Pagination bounds are enforced, not clamped.
    page1 = (await client.get("/task-runs?page=1&page_size=2")).json()
    assert page1["total"] == 4
    assert len(page1["items"]) == 2
    assert (await client.get("/task-runs?page_size=101")).status_code == 422
    assert (await client.get("/task-runs?page=0")).status_code == 422


@pytest.mark.asyncio
async def test_expired_work_reports_expired_in_global_history(client):
    agent_id = await _enroll(client)
    cmd = await _dispatch(client, agent_id, "echo late")
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Command).where(Command.id == cmd["id"]))
        ).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        await db.commit()

    item = next(
        i for i in (await client.get("/task-runs")).json()["items"] if i["id"] == cmd["id"]
    )
    assert item["status"] == "expired"
    # The view reported expiry without mutating the stored row.
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Command).where(Command.id == cmd["id"]))
        ).scalar_one()
    assert row.status.value == "queued"
