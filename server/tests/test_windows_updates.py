# SPDX-License-Identifier: AGPL-3.0-only
"""Windows Update scan + inventory tests (issue #51), Phase 1.

Behavior under test:
  - scan_updates is a typed operation: an operator may dispatch it even without
    an arbitrary-script scope (unlike powershell/shell), readonly may not, and
    the queued command is signed with kind "scan_updates"
  - the windows_updates inventory section validates a well-formed payload through
    the existing section framework and rejects field drift and over-cap lists

Run just this file:  pytest tests/test_windows_updates.py -q
"""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_windows_updates.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.schemas.inventory import (  # noqa: E402
    MAX_MISSING_UPDATES,
    InventorySectionIn,
    WindowsUpdatesInventory,
)
from app.models.models import (  # noqa: E402
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
                email="wu-op@nodelink.test",
                password_hash=hash_password("op-pass"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        db.add(
            Operator(
                email="wu-noscope@nodelink.test",
                password_hash=hash_password("noscope-pass"),
                role=OperatorRole.operator,
                script_execution_scope=None,
            )
        )
        db.add(
            Operator(
                email="wu-viewer@nodelink.test",
                password_hash=hash_password("viewer-pass"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _auth(c, email, password) -> dict:
    r = await c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth) -> str:
    cl = (await c.post("/clients", json={"name": f"WU Clinic {uuid4().hex}"}, headers=op_auth)).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth)).json()
    et = (
        await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5}, headers=op_auth)
    ).json()
    r = await c.post(
        "/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-WU",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["agent_id"]


async def _dispatch(c, auth, agent_id, kind, payload=None):
    return await c.post(
        f"/agents/{agent_id}/commands", json={"kind": kind, "payload": payload or {}}, headers=auth
    )


# --------------------------------------------------------------------------- #
# Dispatch authorization
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_operator_dispatches_signed_scan_updates(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _dispatch(client, op, agent_id, "scan_updates")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "scan_updates"
    assert body["signature"]


@pytest.mark.asyncio
async def test_scan_updates_is_typed_op_and_needs_no_script_scope(client):
    """An operator without any arbitrary-script scope may still scan (typed op),
    but may not run powershell — proving scan_updates is not script execution."""
    noscope = await _auth(client, "wu-noscope@nodelink.test", "noscope-pass")
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)

    ok = await _dispatch(client, noscope, agent_id, "scan_updates")
    assert ok.status_code == 200, ok.text

    denied = await _dispatch(client, noscope, agent_id, "powershell")
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "script_execution_not_authorized"


@pytest.mark.asyncio
async def test_readonly_cannot_dispatch_scan_updates(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    viewer = await _auth(client, "wu-viewer@nodelink.test", "viewer-pass")
    r = await _dispatch(client, viewer, agent_id, "scan_updates")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_operator_dispatches_signed_install_updates(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _dispatch(client, op, agent_id, "install_updates", payload={"kb_ids": ["KB5034123"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "install_updates"
    assert body["signature"]


@pytest.mark.asyncio
async def test_install_updates_accepts_update_ids_for_drivers(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    update_id = "12345678-1234-ABCD-9876-1234567890AB"
    r = await _dispatch(
        client,
        op,
        agent_id,
        "install_updates",
        payload={"update_ids": [update_id]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["payload"] == {
        "kb_ids": [],
        "update_ids": [update_id.lower()],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"update_ids": ["not-a-guid"]},
        {"install_all": True, "kb_ids": ["KB5034123"]},
        {"install_all": "yes"},
        {"install_all": True, "unexpected": True},
    ],
)
async def test_install_updates_rejects_ambiguous_or_invalid_scope(client, payload):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _dispatch(client, op, agent_id, "install_updates", payload=payload)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_install_updates_accepts_explicit_install_all(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _dispatch(
        client,
        op,
        agent_id,
        "install_updates",
        payload={"install_all": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["payload"] == {"install_all": True}


@pytest.mark.asyncio
async def test_install_updates_normalizes_legacy_target_kbs(client):
    op = await _auth(client, "wu-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, op)
    r = await _dispatch(
        client,
        op,
        agent_id,
        "install_updates",
        payload={"target_kbs": ["5101650"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["payload"] == {"kb_ids": ["KB5101650"], "update_ids": []}


# --------------------------------------------------------------------------- #
# windows_updates inventory section
# --------------------------------------------------------------------------- #
def _section(payload: dict) -> InventorySectionIn:
    return InventorySectionIn(
        section="windows_updates",
        status="ok",
        collected_at="2026-08-08T00:00:00+00:00",
        payload=payload,
    )


def test_windows_updates_section_validates_well_formed_payload():
    section = _section(
        {
            "scanned_at": "2026-08-08T00:00:00Z",
            "reboot_required": True,
            "missing": [
                {
                    "title": "2026-08 Cumulative Update (KB5034123)",
                    "kb_id": "KB5034123",
                    "classification": "Security Updates",
                    "severity": "Critical",
                    "reboot_required": True,
                    "priority_grade": "P1 - Critical",
                }
            ],
            "installed": [
                {
                    "kb_id": "KB5030211",
                    "update_id": "12345678-1234-1234-1234-1234567890ab",
                    "revision_number": 7,
                    "installed_on": "2026-07-01T00:00:00Z",
                    "result_code": 2,
                    "hresult": "0x00000000",
                }
            ],
        }
    )
    model = section.typed_payload()
    assert isinstance(model, WindowsUpdatesInventory)
    assert len(model.missing) == 1 and model.missing[0].severity == "Critical"
    assert model.missing[0].priority_grade == "P1 - Critical"
    assert len(model.installed) == 1


def test_windows_updates_section_rejects_field_drift():
    with pytest.raises(ValidationError):
        _section({"missing": [{"title": "U", "bogus_field": "x"}]}).typed_payload()


def test_windows_updates_section_rejects_over_cap_missing_list():
    over = {"missing": [{"title": "U"} for _ in range(MAX_MISSING_UPDATES + 1)]}
    with pytest.raises(ValidationError):
        _section(over).typed_payload()
