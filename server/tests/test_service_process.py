# SPDX-License-Identifier: AGPL-3.0-only
"""Policy, payload validation, authz, capability, and audit tests for issue #57."""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_service_process.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import audit  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    CommandKind,
    Operator,
    OperatorRole,
)
from app.schemas.schemas import CommandCreate  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="svc-admin@nodelink.test", password_hash=hash_password("admin-pass"), role=OperatorRole.admin),
                Operator(email="svc-op@nodelink.test", password_hash=hash_password("op-pass"), role=OperatorRole.operator),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="svc-admin@nodelink.test", password="admin-pass"):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=("service-process-v1",)):
    organization = (await client.post("/clients", json={"name": f"Client {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": organization["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC-SVCPROC",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert response.status_code == 200, response.text
    return response.json(), site["id"]


def test_command_create_schema_validation():
    # list_services / list_processes must have empty payload
    with pytest.raises(ValidationError, match="list_services payload must be empty"):
        CommandCreate(kind=CommandKind.list_services, payload={"extra": 1})
    with pytest.raises(ValidationError, match="list_processes payload must be empty"):
        CommandCreate(kind=CommandKind.list_processes, payload={"extra": 1})

    c_svc = CommandCreate(kind=CommandKind.list_services, payload={})
    assert c_svc.payload == {}

    c_proc = CommandCreate(kind=CommandKind.list_processes, payload={})
    assert c_proc.payload == {}

    # control_service: protected service refusal
    for protected in ("nodelinkagent", "WinDefend", "wInMgMt", "eventlog"):
        with pytest.raises(ValidationError, match="service is protected"):
            CommandCreate(
                kind=CommandKind.control_service,
                payload={"name": protected, "action": "restart", "confirm": True, "reason": "Valid reason for restart"},
            )

    # control_service: invalid action, confirm, reason length, or name pattern
    with pytest.raises(ValidationError, match="service action must be start, stop, or restart"):
        CommandCreate(kind=CommandKind.control_service, payload={"name": "Spooler", "action": "pause", "confirm": True, "reason": "Valid reason for pause"})
    with pytest.raises(ValidationError, match="control_service requires confirm=true"):
        CommandCreate(kind=CommandKind.control_service, payload={"name": "Spooler", "action": "start", "confirm": False, "reason": "Valid reason for start"})
    with pytest.raises(ValidationError, match="reason must contain 10-512 printable UTF-8 bytes"):
        CommandCreate(kind=CommandKind.control_service, payload={"name": "Spooler", "action": "start", "confirm": True, "reason": "short"})
    with pytest.raises(ValidationError, match="service name is invalid"):
        CommandCreate(kind=CommandKind.control_service, payload={"name": "Spooler;bad", "action": "start", "confirm": True, "reason": "Valid reason for start"})

    # control_service: valid payload
    valid_ctrl = CommandCreate(
        kind=CommandKind.control_service,
        payload={"name": "Spooler", "action": "restart", "confirm": True, "reason": "Valid reason for restart"},
    )
    assert valid_ctrl.payload == {"name": "Spooler", "action": "restart", "confirm": True, "reason": "Valid reason for restart"}

    # terminate_process: protected PIDs 0, 4
    for pid in (0, 4):
        with pytest.raises(ValidationError, match="process is protected"):
            CommandCreate(
                kind=CommandKind.terminate_process,
                payload={"pid": pid, "confirm": True, "reason": "Valid reason for terminate"},
            )

    # terminate_process: negative PID, missing confirm, short reason
    with pytest.raises(ValidationError, match="process pid must be a positive integer"):
        CommandCreate(kind=CommandKind.terminate_process, payload={"pid": -1, "confirm": True, "reason": "Valid reason for terminate"})
    with pytest.raises(ValidationError, match="terminate_process requires confirm=true"):
        CommandCreate(kind=CommandKind.terminate_process, payload={"pid": 1234, "confirm": False, "reason": "Valid reason for terminate"})
    with pytest.raises(ValidationError, match="reason must contain 10-512 printable UTF-8 bytes"):
        CommandCreate(kind=CommandKind.terminate_process, payload={"pid": 1234, "confirm": True, "reason": "short"})

    # terminate_process: protected expected_name
    for protected in ("svchost.exe", "nodelinkagent.exe", "NodeLinkAgent.exe"):
        with pytest.raises(ValidationError, match="process is protected"):
            CommandCreate(
                kind=CommandKind.terminate_process,
                payload={"pid": 1234, "expected_name": protected, "confirm": True, "reason": "Valid reason for terminate"},
            )

    # terminate_process: valid payload
    valid_term = CommandCreate(
        kind=CommandKind.terminate_process,
        payload={"pid": 1234, "expected_name": "notepad.exe", "confirm": True, "reason": "Valid reason for terminate"},
    )
    assert valid_term.payload == {"pid": 1234, "expected_name": "notepad.exe", "confirm": True, "reason": "Valid reason for terminate"}


@pytest.mark.asyncio
async def test_list_services_and_processes_operator_allowed(client):
    admin_headers = await auth(client, "svc-admin@nodelink.test", "admin-pass")
    agent_info, _ = await enroll(client, admin_headers)
    agent_id = agent_info["agent_id"]

    op_headers = await auth(client, "svc-op@nodelink.test", "op-pass")

    res1 = await client.post(f"/agents/{agent_id}/commands", json={"kind": "list_services", "payload": {}}, headers=op_headers)
    assert res1.status_code == 200, res1.text
    assert res1.json()["kind"] == "list_services"

    res2 = await client.post(f"/agents/{agent_id}/commands", json={"kind": "list_processes", "payload": {}}, headers=op_headers)
    assert res2.status_code == 200, res2.text
    assert res2.json()["kind"] == "list_processes"


@pytest.mark.asyncio
async def test_control_service_and_terminate_process_role_authz(client):
    admin_headers = await auth(client, "svc-admin@nodelink.test", "admin-pass")
    agent_info, _ = await enroll(client, admin_headers)
    agent_id = agent_info["agent_id"]

    op_headers = await auth(client, "svc-op@nodelink.test", "op-pass")

    # Operator is forbidden for control_service and terminate_process
    res_ctrl_op = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "control_service", "payload": {"name": "Spooler", "action": "restart", "confirm": True, "reason": "Reason for restart"}},
        headers=op_headers,
    )
    assert res_ctrl_op.status_code == 403
    assert res_ctrl_op.json()["detail"]["code"] == "service_process_not_authorized"

    res_term_op = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "terminate_process", "payload": {"pid": 1234, "confirm": True, "reason": "Reason for terminate"}},
        headers=op_headers,
    )
    assert res_term_op.status_code == 403
    assert res_term_op.json()["detail"]["code"] == "service_process_not_authorized"

    # Admin is allowed for both
    res_ctrl_admin = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "control_service", "payload": {"name": "Spooler", "action": "restart", "confirm": True, "reason": "Reason for restart"}},
        headers=admin_headers,
    )
    assert res_ctrl_admin.status_code == 200, res_ctrl_admin.text

    res_term_admin = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "terminate_process", "payload": {"pid": 1234, "confirm": True, "reason": "Reason for terminate"}},
        headers=admin_headers,
    )
    assert res_term_admin.status_code == 200, res_term_admin.text


@pytest.mark.asyncio
async def test_service_process_capability_gating(client):
    admin_headers = await auth(client, "svc-admin@nodelink.test", "admin-pass")
    # Enroll agent WITHOUT service-process-v1 capability
    agent_info, _ = await enroll(client, admin_headers, capabilities=())
    agent_id = agent_info["agent_id"]

    res = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "list_services", "payload": {}},
        headers=admin_headers,
    )
    assert res.status_code == 409
    assert res.json()["detail"]["code"] == "agent_capability_unsupported"
    assert "service-process-v1" in res.json()["detail"]["required"]


@pytest.mark.asyncio
async def test_service_process_audit_events_and_redaction(client):
    admin_headers = await auth(client, "svc-admin@nodelink.test", "admin-pass")
    agent_info, _ = await enroll(client, admin_headers)
    agent_id = agent_info["agent_id"]

    reason_str = "Approved maintenance ticket #5555"

    res_ctrl = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "control_service", "payload": {"name": "Spooler", "action": "stop", "confirm": True, "reason": reason_str}},
        headers=admin_headers,
    )
    assert res_ctrl.status_code == 200, res_ctrl.text

    res_term = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "terminate_process", "payload": {"pid": 4321, "expected_name": "notepad.exe", "confirm": True, "reason": reason_str}},
        headers=admin_headers,
    )
    assert res_term.status_code == 200, res_term.text

    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars().all()
        actions = [e.action for e in events]
        assert "service_control.dispatched" in actions
        assert "process_terminate.dispatched" in actions

        ctrl_ev = next(e for e in events if e.action == "service_control.dispatched")
        assert ctrl_ev.detail["action"] == "stop"
        assert ctrl_ev.detail["service"] == "Spooler"
        assert "reason" not in ctrl_ev.detail
        assert len(ctrl_ev.detail["reason_sha256"]) == 64
        assert ctrl_ev.detail["reason_bytes"] == len(reason_str.encode("utf-8"))

        term_ev = next(e for e in events if e.action == "process_terminate.dispatched")
        assert term_ev.detail["pid"] == 4321
        assert term_ev.detail["expected_name_present"] is True
        assert "reason" not in term_ev.detail
        assert len(term_ev.detail["reason_sha256"]) == 64
        assert term_ev.detail["reason_bytes"] == len(reason_str.encode("utf-8"))

        ok, broken = await audit.verify_chain(db)
        assert ok, f"audit chain failed at {broken}"
