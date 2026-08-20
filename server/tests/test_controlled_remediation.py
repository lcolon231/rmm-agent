# SPDX-License-Identifier: AGPL-3.0-only
"""Controlled file transfer and registry command tests (issue #59)."""
from __future__ import annotations

import base64
import hashlib
import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_controlled_remediation.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402
from app.schemas.schemas import CommandCreate, MAX_FILE_UPLOAD_BYTES  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="rem-admin@nodelink.test", password_hash=hash_password("admin-pass"), role=OperatorRole.admin, is_platform_admin=True),
                Operator(email="rem-op@nodelink.test", password_hash=hash_password("op-pass"), role=OperatorRole.operator),
            ]
        )
        await grant_all_memberships(db)
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _auth(client, email, password):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _enroll(client, auth, capabilities):
    organization = (await client.post("/clients", json={"name": f"Remediation {uuid4().hex}"}, headers=auth)).json()
    site = (await client.post("/sites", json={"client_id": organization["id"], "name": "HQ"}, headers=auth)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=auth)).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC-REM",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": capabilities,
        },
    )
    assert response.status_code == 200, response.text
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return response.json()["agent_id"]


def _upload_payload(content=b"signed patch payload", **updates):
    payload = {
        "path": r"C:\ProgramData\NodeLink\Managed\patch.bin",
        "content_base64": base64.b64encode(content).decode(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "overwrite": False,
    }
    payload.update(updates)
    return payload


def test_file_upload_normalizes_and_verifies_digest():
    command = CommandCreate(kind="file_upload", payload=_upload_payload(path="c:/programdata/nodelink/managed/patch.bin"))
    assert command.payload["path"] == r"c:\programdata\nodelink\managed\patch.bin"


@pytest.mark.parametrize(
    "path",
    [
        r"C:\ProgramData\NodeLink\Managed\..\secret.txt",
        r"\\server\share\payload.exe",
        r"\\?\C:\ProgramData\NodeLink\Managed\payload.exe",
        r"\\.\PhysicalDrive0",
        r"C:\ProgramData\NodeLink\Managed\payload.exe:stream",
        r"C:\ProgramData\NodeLink\Managed\CON",
        r"C:\ProgramData\NodeLink\Managed\LPT1.txt",
        "C:\\ProgramData\\NodeLink\\Managed\\payload. ",
        r"C:\Windows\System32\drivers\etc\hosts",
    ],
)
def test_file_transfer_rejects_traversal_device_and_unmanaged_paths(path):
    with pytest.raises(ValidationError):
        CommandCreate(kind="file_upload", payload=_upload_payload(path=path))


def test_file_upload_rejects_tampered_and_oversized_content():
    with pytest.raises(ValidationError):
        CommandCreate(kind="file_upload", payload=_upload_payload(sha256="0" * 64))
    oversized = b"x" * (MAX_FILE_UPLOAD_BYTES + 1)
    with pytest.raises(ValidationError):
        CommandCreate(kind="file_upload", payload=_upload_payload(oversized))


@pytest.mark.parametrize(
    "payload",
    [
        {"hive": "HKCR", "key": r"Software\NodeLink\Managed", "value_name": "Mode", "view": 64},
        {"hive": "HKLM", "key": r"Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "Backdoor", "view": 64},
        {"hive": "HKLM", "key": r"Software\NodeLink\Managed", "value_name": "Mode", "view": 128},
    ],
)
def test_registry_read_rejects_unsupported_hives_views_and_protected_keys(payload):
    with pytest.raises(ValidationError):
        CommandCreate(kind="registry_read", payload=payload)


def test_registry_types_and_delete_confirmation_are_strict():
    base = {"hive": "HKLM", "key": r"Software\NodeLink\Managed\Policy", "value_name": "Mode", "view": 64}
    assert CommandCreate(kind="registry_write", payload={**base, "type": "dword", "data": 1}).payload["data"] == 1
    with pytest.raises(ValidationError):
        CommandCreate(kind="registry_write", payload={**base, "type": "dword", "data": -1})
    with pytest.raises(ValidationError):
        CommandCreate(kind="registry_write", payload={**base, "type": "mystery", "data": "x"})
    with pytest.raises(ValidationError):
        CommandCreate(kind="registry_delete", payload={**base, "confirm": False})


def test_rollback_contract_accepts_only_local_backup_identifiers():
    assert CommandCreate(kind="remediation_rollback", payload={"backup_id": "a" * 32}).payload["backup_id"] == "a" * 32
    with pytest.raises(ValidationError):
        CommandCreate(kind="remediation_rollback", payload={"backup_id": "../journal"})


@pytest.mark.asyncio
async def test_admin_dispatches_capability_gated_upload_and_operator_is_denied(client):
    admin = await _auth(client, "rem-admin@nodelink.test", "admin-pass")
    operator = await _auth(client, "rem-op@nodelink.test", "op-pass")
    agent_id = await _enroll(client, admin, ["file-transfer-v1", "registry-operations-v1"])
    allowed = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "file_upload", "payload": _upload_payload()},
        headers=admin,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["signature"]
    command_id = allowed.json()["id"]
    admin_detail = await client.get(
        f"/agents/{agent_id}/commands/{command_id}", headers=admin
    )
    assert admin_detail.status_code == 200
    operator_detail = await client.get(
        f"/agents/{agent_id}/commands/{command_id}", headers=operator
    )
    assert operator_detail.status_code == 403
    assert (
        operator_detail.json()["detail"]["code"]
        == "privileged_command_detail_not_authorized"
    )
    denied = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "file_download", "payload": {"path": r"C:\ProgramData\NodeLink\Managed\patch.bin"}},
        headers=operator,
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_mixed_version_agent_fails_closed_when_capability_is_missing(client):
    admin = await _auth(client, "rem-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(client, admin, [])
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "file_download", "payload": {"path": r"C:\ProgramData\NodeLink\Managed\patch.bin"}},
        headers=admin,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "agent_capability_unsupported"
