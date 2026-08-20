# SPDX-License-Identifier: AGPL-3.0-only
"""Inventory history, deterministic diffs, and retention (issue #40).

The central concern is that a diff must name what actually changed. A
positional list diff would report a single uninstalled program as hundreds of
modifications, which is worse than no diff at all — so identity-keyed diffing
is what most of these tests exercise.
"""
from __future__ import annotations

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

from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.core import retention  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.inventory_diff import (  # noqa: E402
    diff_payloads,
    is_empty_diff,
    summarize_diff,
)
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentInventorySnapshot,
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)


# --------------------------------------------------------------------------- #
# Diff engine (pure)
# --------------------------------------------------------------------------- #
def _software(*names_versions):
    return {
        "entries": [
            {"name": name, "version": version, "publisher": "Contoso"}
            for name, version in names_versions
        ]
    }


def test_removing_one_program_reports_one_removal_not_a_rewrite():
    """The defect a positional diff would produce, pinned as a test.

    Uninstalling the *first* of many programs shifts every remaining entry by
    one index. An index-based diff would report the whole list as modified and
    the actual event would be invisible.
    """
    before = _software(("Alpha", "1"), ("Beta", "2"), ("Gamma", "3"), ("Delta", "4"))
    after = _software(("Beta", "2"), ("Gamma", "3"), ("Delta", "4"))

    diff = diff_payloads("installed_software", before, after)
    entries = diff["list_changes"]["entries"]

    assert len(entries["removed"]) == 1
    assert entries["removed"][0]["name"] == "Alpha"
    assert entries["added"] == []
    assert entries["changed"] == []
    assert summarize_diff(diff)["items_removed"] == 1


def test_reordering_alone_is_not_a_change():
    """Registry enumeration order is not stable; order must not be a diff."""
    before = _software(("Alpha", "1"), ("Beta", "2"), ("Gamma", "3"))
    after = _software(("Gamma", "3"), ("Alpha", "1"), ("Beta", "2"))
    assert is_empty_diff(diff_payloads("installed_software", before, after))


def test_an_upgrade_is_an_add_and_a_remove_not_a_change():
    """Version is part of software identity, so 1.0 -> 2.0 is a replacement.

    A technician reading "Contoso App changed" would not know whether it was
    upgraded or merely re-registered; add+remove states the version transition
    explicitly.
    """
    diff = diff_payloads(
        "installed_software", _software(("App", "1.0")), _software(("App", "2.0"))
    )
    entries = diff["list_changes"]["entries"]
    assert [item["version"] for item in entries["added"]] == ["2.0"]
    assert [item["version"] for item in entries["removed"]] == ["1.0"]


def test_a_corrected_publisher_is_a_change_on_the_same_program():
    """Identity is not equality: same name and version means same program."""
    before = {"entries": [{"name": "App", "version": "1.0", "publisher": "Contso"}]}
    after = {"entries": [{"name": "App", "version": "1.0", "publisher": "Contoso"}]}

    diff = diff_payloads("installed_software", before, after)
    entries = diff["list_changes"]["entries"]
    assert entries["added"] == []
    assert entries["removed"] == []
    assert len(entries["changed"]) == 1
    change = entries["changed"][0]
    assert change["identity"] == {"name": "App", "version": "1.0"}
    assert change["changes"] == [
        {"field": "publisher", "from": "Contso", "to": "Contoso"}
    ]


def test_volumes_are_identified_by_mount_point():
    before = {"volumes": [{"mount_point": "C:", "protection_status": "on"}]}
    after = {"volumes": [{"mount_point": "C:", "protection_status": "off"}]}
    diff = diff_payloads("security_bitlocker", before, after)
    changed = diff["list_changes"]["volumes"]["changed"]
    assert changed[0]["identity"] == {"mount_point": "C:"}
    assert changed[0]["changes"][0]["field"] == "protection_status"


def test_scalar_fields_diff_independently_of_lists():
    before = {"total_bytes": 8, "modules": [{"slot": "A", "capacity_bytes": 4}]}
    after = {"total_bytes": 16, "modules": [{"slot": "A", "capacity_bytes": 8}]}
    diff = diff_payloads("memory", before, after)
    assert diff["field_changes"] == [{"field": "total_bytes", "from": 8, "to": 16}]
    assert diff["list_changes"]["modules"]["changed"][0]["identity"] == {"slot": "A"}


def test_a_field_that_stops_being_reported_is_a_change():
    """Losing a serial number is a real event, not a non-event."""
    diff = diff_payloads("system", {"serial": "SN-1", "model": "X"}, {"model": "X"})
    assert diff["field_changes"] == [{"field": "serial", "from": "SN-1", "to": None}]


def test_identical_payloads_produce_an_empty_diff():
    payload = _software(("App", "1.0"))
    assert is_empty_diff(diff_payloads("installed_software", payload, payload))
    assert is_empty_diff(diff_payloads("system", {}, {}))


def test_diffs_are_deterministic_across_repeated_runs():
    before = _software(("B", "1"), ("A", "1"), ("C", "1"))
    after = _software(("C", "1"), ("D", "1"))
    first = diff_payloads("installed_software", before, after)
    for _ in range(25):
        assert diff_payloads("installed_software", before, after) == first


def test_lists_without_a_declared_identity_degrade_to_add_remove():
    """An unknown list still produces a usable answer rather than an error."""
    diff = diff_payloads(
        "some_future_section", {"things": ["a", "b"]}, {"things": ["b", "c"]}
    )
    things = diff["list_changes"]["things"]
    assert things["added"] == ["c"]
    assert things["removed"] == ["a"]


def test_a_large_software_change_stays_proportional():
    """500 programs with one removed must report one removal, not 500."""
    before = _software(*[(f"App {i:03d}", "1.0") for i in range(500)])
    after = _software(*[(f"App {i:03d}", "1.0") for i in range(500) if i != 7])
    diff = diff_payloads("installed_software", before, after)
    summary = summarize_diff(diff)
    assert summary == {
        "fields_changed": 0,
        "items_added": 0,
        "items_removed": 1,
        "items_changed": 0,
    }


# --------------------------------------------------------------------------- #
# API and retention
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="hist@nodelink.test",
                password_hash=hash_password("hist-password"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "hist@nodelink.test", "password": "hist-password"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _enroll(c) -> tuple[str, str]:
    cl = (await c.post("/clients", json={"name": f"Clinic {uuid4().hex}"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"]})).json()
    enr = (
        await c.post(
            "/enroll",
            json={
                "enrollment_token": et["token"],
                "hostname": "PC1",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            },
        )
    ).json()
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return enr["agent_id"], enr["agent_token"]


def _agent(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t/api/v1",
        headers={"Authorization": f"Bearer {token}"},
    )


async def _submit(agent, section: str, payload: dict):
    return await agent.post(
        "/agents/me/inventory",
        json={
            "inventory_schema_version": 1,
            "sections": [
                {
                    "section": section,
                    "status": "ok",
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "payload": payload,
                }
            ],
        },
    )


@pytest.mark.asyncio
async def test_current_inventory_lists_reported_and_missing_sections(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        await _submit(agent, "system", {"model": "X1"})
        await _submit(agent, "cpu", {"name": "Xeon"})

    body = (await client.get(f"/endpoints/{agent_id}/inventory")).json()
    assert [item["section"] for item in body["sections"]] == ["cpu", "system"]
    # Never-reported sections are named rather than omitted, so "no data" is
    # visible instead of looking like the section does not exist.
    assert "security_tpm" in body["missing_sections"]


@pytest.mark.asyncio
async def test_history_is_a_list_of_changes_not_of_collections(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        await _submit(agent, "system", {"model": "X1"})
        await _submit(agent, "system", {"model": "X1"})  # unchanged: not stored
        await _submit(agent, "system", {"model": "X2"})

    body = (await client.get(f"/endpoints/{agent_id}/inventory/system/history")).json()
    assert body["total"] == 2
    assert [item["payload"]["model"] for item in body["items"]] == ["X2", "X1"]


@pytest.mark.asyncio
async def test_diff_defaults_to_the_two_most_recent_snapshots(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        await _submit(agent, "installed_software", _software(("A", "1"), ("B", "1")))
        await _submit(agent, "installed_software", _software(("B", "1"), ("C", "1")))

    body = (
        await client.get(f"/endpoints/{agent_id}/inventory/installed_software/diff")
    ).json()
    assert body["comparable"] is True
    entries = body["diff"]["list_changes"]["entries"]
    assert [item["name"] for item in entries["added"]] == ["C"]
    assert [item["name"] for item in entries["removed"]] == ["A"]


@pytest.mark.asyncio
async def test_a_single_snapshot_is_not_comparable_but_not_an_error(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        await _submit(agent, "system", {"model": "X1"})

    response = await client.get(f"/endpoints/{agent_id}/inventory/system/diff")
    assert response.status_code == 200
    body = response.json()
    # An endpoint that has never changed a section is a normal state.
    assert body["comparable"] is False
    assert body["after"] is None


@pytest.mark.asyncio
async def test_diff_refuses_snapshots_from_another_endpoint(client):
    first_id, first_token = await _enroll(client)
    second_id, second_token = await _enroll(client)
    async with _agent(first_token) as agent:
        await _submit(agent, "system", {"model": "X1"})
    async with _agent(second_token) as agent:
        await _submit(agent, "system", {"model": "Y1"})

    async with AsyncSessionLocal() as db:
        other = (
            await db.execute(
                select(AgentInventorySnapshot).where(
                    AgentInventorySnapshot.agent_id == second_id
                )
            )
        ).scalar_one()

    # Same 404 as a nonexistent id: no cross-endpoint probing through this
    # parameter, and no accidental comparison of unrelated machines.
    response = await client.get(
        f"/endpoints/{first_id}/inventory/system/diff",
        params={"from_snapshot": other.id, "to_snapshot": other.id},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_inventory_views_are_audited_without_recording_values(client):
    agent_id, token = await _enroll(client)
    telling = "Confidential Trading Platform"
    async with _agent(token) as agent:
        await _submit(agent, "installed_software", {"entries": [{"name": telling}]})
        await _submit(
            agent, "installed_software", {"entries": [{"name": telling + " 2"}]}
        )

    await client.get(f"/endpoints/{agent_id}/inventory")
    await client.get(f"/endpoints/{agent_id}/inventory/installed_software/diff")

    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.action.in_(["inventory.viewed", "inventory.diff_viewed"])
                )
            )
        ).scalars().all()
    assert {event.action for event in events} == {
        "inventory.viewed",
        "inventory.diff_viewed",
    }
    for event in events:
        assert telling not in str(event.detail)


@pytest.mark.asyncio
async def test_history_and_diff_require_a_known_endpoint(client):
    missing = str(uuid4())
    assert (await client.get(f"/endpoints/{missing}/inventory")).status_code == 404
    assert (
        await client.get(f"/endpoints/{missing}/inventory/system/history")
    ).status_code == 404
    assert (
        await client.get(f"/endpoints/{missing}/inventory/system/diff")
    ).status_code == 404


@pytest.mark.asyncio
async def test_an_unknown_section_name_is_rejected(client):
    agent_id, _ = await _enroll(client)
    assert (
        await client.get(f"/endpoints/{agent_id}/inventory/made_up/history")
    ).status_code == 422


@pytest.mark.asyncio
async def test_retention_bounds_history_but_never_drops_current_state(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        for i in range(8):
            await _submit(agent, "system", {"model": f"X{i}"})

    tuned = Settings(**{**settings.model_dump(), "inventory_history_per_section": 3})
    async with AsyncSessionLocal() as db:
        result = await retention.prune_expired(db, tuned)
        await db.commit()
    assert result.inventory_snapshots_deleted == 5

    body = (await client.get(f"/endpoints/{agent_id}/inventory/system/history")).json()
    assert body["total"] == 3
    # The newest survives, so the endpoint's current state is intact.
    assert body["items"][0]["payload"]["model"] == "X7"

    current = (await client.get(f"/endpoints/{agent_id}/inventory")).json()
    assert current["sections"][0]["payload"]["model"] == "X7"


@pytest.mark.asyncio
async def test_retention_keeps_current_state_even_at_a_limit_of_one(client):
    """The newest row is current state, not history, and is never a candidate."""
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        for i in range(4):
            await _submit(agent, "system", {"model": f"X{i}"})

    tuned = Settings(**{**settings.model_dump(), "inventory_history_per_section": 1})
    async with AsyncSessionLocal() as db:
        await retention.prune_expired(db, tuned)
        await db.commit()

    current = (await client.get(f"/endpoints/{agent_id}/inventory")).json()
    assert len(current["sections"]) == 1
    assert current["sections"][0]["payload"]["model"] == "X3"


@pytest.mark.asyncio
async def test_retention_prunes_each_section_independently(client):
    """Sections change at very different rates; one must not starve another."""
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        for i in range(6):
            await _submit(agent, "installed_software", _software((f"App {i}", "1")))
        await _submit(agent, "system", {"model": "X1"})

    tuned = Settings(**{**settings.model_dump(), "inventory_history_per_section": 2})
    async with AsyncSessionLocal() as db:
        await retention.prune_expired(db, tuned)
        await db.commit()

    software = (
        await client.get(f"/endpoints/{agent_id}/inventory/installed_software/history")
    ).json()
    system = (
        await client.get(f"/endpoints/{agent_id}/inventory/system/history")
    ).json()
    assert software["total"] == 2
    # The slow-changing section keeps its single snapshot untouched.
    assert system["total"] == 1


@pytest.mark.asyncio
async def test_retention_is_disabled_by_a_zero_limit(client):
    agent_id, token = await _enroll(client)
    async with _agent(token) as agent:
        for i in range(5):
            await _submit(agent, "system", {"model": f"X{i}"})

    tuned = Settings(**{**settings.model_dump(), "inventory_history_per_section": 0})
    async with AsyncSessionLocal() as db:
        result = await retention.prune_expired(db, tuned)
        await db.commit()
    assert result.inventory_snapshots_deleted == 0
