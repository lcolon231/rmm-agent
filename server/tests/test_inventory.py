# SPDX-License-Identifier: AGPL-3.0-only
"""Windows hardware inventory collection and storage (issue #35).

Covers the bounded submission contract, per-section rejection, hash-negotiated
refresh, content-hash dedup, trust-state enforcement, the audit evidence the
path produces, and cross-language hash agreement with the Go agent.
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

from app.main import app  # noqa: E402
from app.core import inventory as inventory_core  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentInventorySnapshot,
    AgentTrustState,
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)
from app.schemas.inventory import (  # noqa: E402
    MAX_INVENTORY_SECTION_BYTES,
    MAX_SOFTWARE_ENTRIES,
    inventory_content_hash,
)


def _collected_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _submission(sections: list[dict]) -> dict:
    return {"inventory_schema_version": 1, "agent_version": "0.1.2", "sections": sections}


def _section(name: str, payload: dict, status: str = "ok") -> dict:
    return {
        "section": name,
        "status": status,
        "collected_at": _collected_at(),
        "payload": payload,
    }


SYSTEM_PAYLOAD = {
    "manufacturer": "Contoso",
    "model": "X1",
    "serial": "SN-1",
    "bios_vendor": "Contoso",
    "bios_version": "1.2.3",
}


@pytest_asyncio.fixture
async def operator_client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="inv@nodelink.test",
                password_hash=hash_password("inv-password"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "inv@nodelink.test", "password": "inv-password"},
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
    return enr["agent_id"], enr["agent_token"]


def _agent_client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t/api/v1",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.asyncio
async def test_go_and_python_agree_on_the_canonical_content_hash(operator_client):
    """The heartbeat comparison is only meaningful if both sides hash alike.

    These vectors are pinned identically in the Go package's test, so a change
    to either canonicalization breaks a test rather than silently making every
    section look permanently changed (or permanently unchanged).
    """
    empty_digest = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    assert inventory_content_hash({}) == empty_digest

    # Key insertion order must not matter: Go map iteration is randomized.
    forward = inventory_content_hash(
        {"manufacturer": "Contoso", "model": "X1", "serial": "SN-1"}
    )
    reverse = inventory_content_hash(
        {"serial": "SN-1", "model": "X1", "manufacturer": "Contoso"}
    )
    assert forward == reverse

    # Absent must not collapse into empty-string.
    assert inventory_content_hash({"model": "X1"}) != inventory_content_hash(
        {"model": "X1", "serial": ""}
    )


@pytest.mark.asyncio
async def test_submission_stores_sections_and_dedupes_unchanged_resends(operator_client):
    agent_id, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        first = await agent.post(
            "/agents/me/inventory",
            json=_submission(
                [
                    _section("system", SYSTEM_PAYLOAD),
                    _section("cpu", {"name": "Xeon", "logical_cores": 8}),
                ]
            ),
        )
        assert first.status_code == 200
        assert first.json()["stored_sections"] == ["cpu", "system"]
        assert first.json()["unchanged_sections"] == []

        # Byte-identical resend: nothing new is stored.
        repeat = await agent.post(
            "/agents/me/inventory",
            json=_submission([_section("system", SYSTEM_PAYLOAD)]),
        )
        assert repeat.json()["stored_sections"] == []
        assert repeat.json()["unchanged_sections"] == ["system"]

        # A real change appends a new row rather than overwriting the old one,
        # which is what gives #40 its history.
        changed = dict(SYSTEM_PAYLOAD, bios_version="1.2.4")
        assert (
            await agent.post(
                "/agents/me/inventory", json=_submission([_section("system", changed)])
            )
        ).json()["stored_sections"] == ["system"]

    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AgentInventorySnapshot)
                .where(AgentInventorySnapshot.section == "system")
                .order_by(AgentInventorySnapshot.received_at)
            )
        ).scalars().all()
    assert len(rows) == 2
    assert rows[0].payload["bios_version"] == "1.2.3"
    assert rows[1].payload["bios_version"] == "1.2.4"
    assert rows[0].agent_id == agent_id


@pytest.mark.asyncio
async def test_a_status_change_alone_is_stored_as_a_change(operator_client):
    """An unchanged payload that degrades to unavailable is a real event."""
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        await agent.post(
            "/agents/me/inventory", json=_submission([_section("cpu", {"name": "Xeon"})])
        )
        degraded = await agent.post(
            "/agents/me/inventory",
            json=_submission([_section("cpu", {"name": "Xeon"}, status="unavailable")]),
        )
        assert degraded.json()["stored_sections"] == ["cpu"]


@pytest.mark.asyncio
async def test_oversized_and_malformed_sections_are_rejected_not_truncated(
    operator_client,
):
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        oversized = _section(
            "system", {"model": "x" * (MAX_INVENTORY_SECTION_BYTES + 1)}
        )
        assert (
            await agent.post("/agents/me/inventory", json=_submission([oversized]))
        ).status_code == 422

        # Unknown field: the section model forbids extras, so a drifting agent
        # fails loudly instead of having fields silently discarded.
        unknown = _section("cpu", {"name": "Xeon", "turbo_enabled": True})
        assert (
            await agent.post("/agents/me/inventory", json=_submission([unknown]))
        ).status_code == 422

        # Wrong type for a bounded numeric field.
        bad_type = _section("cpu", {"logical_cores": "eight"})
        assert (
            await agent.post("/agents/me/inventory", json=_submission([bad_type]))
        ).status_code == 422

        # Over-long list.
        too_many = _section(
            "memory", {"modules": [{"capacity_bytes": 1} for _ in range(65)]}
        )
        assert (
            await agent.post("/agents/me/inventory", json=_submission([too_many]))
        ).status_code == 422

        assert (
            await agent.post(
                "/agents/me/inventory",
                json=_submission([_section("made_up_section", {})]),
            )
        ).status_code == 422

        # A duplicate section in one submission is ambiguous, not mergeable.
        assert (
            await agent.post(
                "/agents/me/inventory",
                json=_submission(
                    [_section("cpu", {"name": "A"}), _section("cpu", {"name": "B"})]
                ),
            )
        ).status_code == 422

    # Nothing from any rejected submission reached storage.
    async with AsyncSessionLocal() as db:
        stored = (
            await db.execute(select(AgentInventorySnapshot))
        ).scalars().all()
    assert stored == []


@pytest.mark.asyncio
async def test_a_rejected_section_does_not_partially_store_the_submission(
    operator_client,
):
    """One bad section fails the whole request, so a snapshot is never half-applied."""
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        response = await agent.post(
            "/agents/me/inventory",
            json=_submission(
                [
                    _section("system", SYSTEM_PAYLOAD),
                    _section("cpu", {"logical_cores": "eight"}),
                ]
            ),
        )
        assert response.status_code == 422

    async with AsyncSessionLocal() as db:
        stored = (await db.execute(select(AgentInventorySnapshot))).scalars().all()
    assert stored == []


@pytest.mark.asyncio
async def test_heartbeat_requests_only_missing_changed_or_stale_sections(
    operator_client,
):
    _, token = await _enroll(operator_client)
    system_hash = inventory_content_hash(SYSTEM_PAYLOAD)

    async with _agent_client(token) as agent:
        # Nothing stored yet: the advertised section is requested.
        ack = (
            await agent.post("/heartbeat", json={"inventory_hashes": {"system": system_hash}})
        ).json()
        assert ack["inventory_requested"] == ["system"]

        await agent.post(
            "/agents/me/inventory", json=_submission([_section("system", SYSTEM_PAYLOAD)])
        )

        # Stored and matching: nothing is requested, so a steady-state endpoint
        # transfers no inventory bytes at all.
        ack = (
            await agent.post("/heartbeat", json={"inventory_hashes": {"system": system_hash}})
        ).json()
        assert ack["inventory_requested"] == []

        # A changed hash is requested again.
        ack = (
            await agent.post(
                "/heartbeat", json={"inventory_hashes": {"system": "b" * 64}}
            )
        ).json()
        assert ack["inventory_requested"] == ["system"]

        # A section the agent does not advertise is never requested: only the
        # agent knows what it can collect, so asking would loop forever.
        ack = (
            await agent.post("/heartbeat", json={"inventory_hashes": {}})
        ).json()
        assert ack["inventory_requested"] == []

        # A malformed digest is refused at the schema boundary.
        assert (
            await agent.post(
                "/heartbeat", json={"inventory_hashes": {"system": "not-a-digest"}}
            )
        ).status_code == 422


@pytest.mark.asyncio
async def test_a_stale_stored_section_is_refreshed_even_when_the_hash_matches(
    operator_client,
):
    """Staleness bounds how long a missed change can hide."""
    _, token = await _enroll(operator_client)
    system_hash = inventory_content_hash(SYSTEM_PAYLOAD)
    async with _agent_client(token) as agent:
        await agent.post(
            "/agents/me/inventory", json=_submission([_section("system", SYSTEM_PAYLOAD)])
        )

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(AgentInventorySnapshot))).scalar_one()
        row.received_at = datetime.now(timezone.utc) - (
            inventory_core.INVENTORY_REFRESH_INTERVAL + timedelta(minutes=1)
        )
        await db.commit()

    async with _agent_client(token) as agent:
        ack = (
            await agent.post("/heartbeat", json={"inventory_hashes": {"system": system_hash}})
        ).json()
    assert ack["inventory_requested"] == ["system"]


@pytest.mark.asyncio
async def test_quarantined_and_revoked_agents_cannot_report_inventory(operator_client):
    agent_id, token = await _enroll(operator_client)
    await operator_client.post(
        f"/agents/{agent_id}/quarantine", json={"reason": "suspected compromise"}
    )

    async with _agent_client(token) as agent:
        response = await agent.post(
            "/agents/me/inventory", json=_submission([_section("system", SYSTEM_PAYLOAD)])
        )
        assert response.status_code == 403
        # A quarantined beat also carries no inventory request.
        ack = (await agent.post("/heartbeat", json={})).json()
        assert ack["inventory_requested"] == []

    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(AgentInventorySnapshot))).scalars().all() == []
        rejected = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "inventory.rejected")
            )
        ).scalars().all()
    assert rejected, "a refused inventory report must leave evidence"
    assert rejected[0].detail["reason"] == "agent_not_active"


@pytest.mark.asyncio
async def test_inventory_audit_records_sizes_but_never_payload_contents(
    operator_client,
):
    _, token = await _enroll(operator_client)
    secret_serial = "SN-SENSITIVE-0001"
    async with _agent_client(token) as agent:
        await agent.post(
            "/agents/me/inventory",
            json=_submission(
                [_section("system", dict(SYSTEM_PAYLOAD, serial=secret_serial))]
            ),
        )

    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "inventory.received")
            )
        ).scalars().all()
    assert len(events) == 1
    detail = events[0].detail
    assert detail["stored_sections"] == ["system"]
    assert detail["schema_version"] == 1
    assert detail["total_bytes"] > 0
    # Serial numbers, adapter addresses, and volume labels are exactly what the
    # permanent chain must not accumulate.
    assert secret_serial not in str(detail)


@pytest.mark.asyncio
async def test_storage_status_reports_inventory_growth(operator_client):
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        await agent.post(
            "/agents/me/inventory", json=_submission([_section("system", SYSTEM_PAYLOAD)])
        )

    status = (await operator_client.get("/storage/status")).json()
    assert status["inventory"]["snapshot_count"] == 1
    assert status["inventory"]["total_bytes"] > 0
    assert status["inventory"]["oldest_age_seconds"] is not None


@pytest.mark.asyncio
async def test_inventory_requires_agent_authentication(operator_client):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
    ) as anon:
        response = await anon.post(
            "/agents/me/inventory", json=_submission([_section("system", SYSTEM_PAYLOAD)])
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_section_collected_as_unavailable_is_recorded_as_such(operator_client):
    """Fail-closed collection must be storable, not silently dropped."""
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        response = await agent.post(
            "/agents/me/inventory",
            json=_submission([_section("storage", {}, status="unavailable")]),
        )
        assert response.status_code == 200

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(AgentInventorySnapshot))).scalar_one()
    assert row.section == "storage"
    assert row.status == "unavailable"
    assert row.payload == {}


# --------------------------------------------------------------------------- #
# Installed software (issue #36)
# --------------------------------------------------------------------------- #
def _software(entries: list[dict]) -> dict:
    return _section("installed_software", {"entries": entries})


@pytest.mark.asyncio
async def test_installed_software_is_stored_as_a_section_without_migration(
    operator_client,
):
    """The section framework from #35 absorbs a new class with no schema change."""
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        response = await agent.post(
            "/agents/me/inventory",
            json=_submission(
                [
                    _software(
                        [
                            {
                                "name": "7-Zip 23.01 (x64)",
                                "version": "23.01",
                                "publisher": "Igor Pavlov",
                                "architecture": "x64",
                                "scope": "machine",
                                "identifier": "7-Zip",
                            },
                            {"name": "Contoso Agent", "scope": "user"},
                        ]
                    )
                ]
            ),
        )
        assert response.status_code == 200
        assert response.json()["stored_sections"] == ["installed_software"]

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(AgentInventorySnapshot))).scalar_one()
    assert row.section == "installed_software"
    assert len(row.payload["entries"]) == 2
    # Defaults are explicit, not inferred later by a reader.
    assert row.payload["entries"][1]["name"] == "Contoso Agent"


@pytest.mark.asyncio
async def test_software_entries_require_a_name_and_reject_unknown_fields(
    operator_client,
):
    _, token = await _enroll(operator_client)
    async with _agent_client(token) as agent:
        # A row with no display name is a registry artifact, not a program.
        assert (
            await agent.post(
                "/agents/me/inventory",
                json=_submission([_software([{"version": "1.0"}])]),
            )
        ).status_code == 422

        # Field drift fails loudly rather than being silently discarded.
        assert (
            await agent.post(
                "/agents/me/inventory",
                json=_submission([_software([{"name": "X", "install_size": 42}])]),
            )
        ).status_code == 422

        # Enumerated values are constrained.
        assert (
            await agent.post(
                "/agents/me/inventory",
                json=_submission([_software([{"name": "X", "scope": "everyone"}])]),
            )
        ).status_code == 422


@pytest.mark.asyncio
async def test_software_section_is_bounded_by_bytes_before_entry_count(
    operator_client,
):
    """The count ceiling is not the binding constraint for this section.

    At the schema's 255-character field bounds an entry approaches 1 KiB, so a
    payload well under MAX_SOFTWARE_ENTRIES can still exceed the byte cap. The
    server must reject it — which is exactly why the agent fits to bytes rather
    than trimming to the count, or such a machine would be refused forever and
    would silently never report software at all.
    """
    _, token = await _enroll(operator_client)
    fat_entry = {
        "name": "n" * 255,
        "version": "v" * 255,
        "publisher": "p" * 255,
        "identifier": "i" * 128,
    }
    entries = [dict(fat_entry, name=f"{i:04d}" + "n" * 250) for i in range(400)]
    assert len(entries) < MAX_SOFTWARE_ENTRIES  # under the count ceiling

    async with _agent_client(token) as agent:
        response = await agent.post(
            "/agents/me/inventory", json=_submission([_software(entries)])
        )
    assert response.status_code == 422

    # Nothing partial was stored.
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(AgentInventorySnapshot))).scalars().all() == []


@pytest.mark.asyncio
async def test_software_entry_count_ceiling_is_enforced(operator_client):
    _, token = await _enroll(operator_client)
    entries = [{"name": f"P{i}"} for i in range(MAX_SOFTWARE_ENTRIES + 1)]
    async with _agent_client(token) as agent:
        assert (
            await agent.post(
                "/agents/me/inventory", json=_submission([_software(entries)])
            )
        ).status_code == 422


@pytest.mark.asyncio
async def test_software_dedupes_on_content_hash_like_every_other_section(
    operator_client,
):
    _, token = await _enroll(operator_client)
    entries = [{"name": "Stable App", "version": "1.0"}]
    async with _agent_client(token) as agent:
        first = await agent.post(
            "/agents/me/inventory", json=_submission([_software(entries)])
        )
        assert first.json()["stored_sections"] == ["installed_software"]

        repeat = await agent.post(
            "/agents/me/inventory", json=_submission([_software(entries)])
        )
        assert repeat.json()["unchanged_sections"] == ["installed_software"]

        upgraded = [{"name": "Stable App", "version": "1.1"}]
        changed = await agent.post(
            "/agents/me/inventory", json=_submission([_software(upgraded)])
        )
        assert changed.json()["stored_sections"] == ["installed_software"]


@pytest.mark.asyncio
async def test_software_participates_in_hash_negotiation(operator_client):
    _, token = await _enroll(operator_client)
    payload = {"entries": [{"name": "Negotiated App"}]}
    digest = inventory_content_hash(payload)

    async with _agent_client(token) as agent:
        ack = (
            await agent.post(
                "/heartbeat", json={"inventory_hashes": {"installed_software": digest}}
            )
        ).json()
        assert ack["inventory_requested"] == ["installed_software"]

        await agent.post(
            "/agents/me/inventory",
            json=_submission(
                [_section("installed_software", payload)]
            ),
        )
        ack = (
            await agent.post(
                "/heartbeat", json={"inventory_hashes": {"installed_software": digest}}
            )
        ).json()
        assert ack["inventory_requested"] == []


@pytest.mark.asyncio
async def test_software_audit_records_sizes_but_never_program_names(operator_client):
    """Installed programs are sensitive: they disclose what runs on an endpoint."""
    _, token = await _enroll(operator_client)
    telling_name = "Confidential Trading Platform 9.4"
    async with _agent_client(token) as agent:
        await agent.post(
            "/agents/me/inventory",
            json=_submission([_software([{"name": telling_name}])]),
        )

    async with AsyncSessionLocal() as db:
        event = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "inventory.received")
            )
        ).scalars().one()
    assert event.detail["stored_sections"] == ["installed_software"]
    assert telling_name not in str(event.detail)
