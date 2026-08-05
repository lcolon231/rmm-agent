# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable script-library API, authorization, lifecycle, and evidence."""
from __future__ import annotations

import hashlib
import os

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_script_library.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import AuditEvent, Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def clients():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="library-admin@nodelink.test",
                    password_hash=hash_password("admin-password"),
                    role=OperatorRole.admin,
                ),
                Operator(
                    email="library-operator@nodelink.test",
                    password_hash=hash_password("operator-password"),
                    role=OperatorRole.operator,
                ),
                Operator(
                    email="library-viewer@nodelink.test",
                    password_hash=hash_password("viewer-password"),
                    role=OperatorRole.readonly,
                ),
            ]
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test/api/v1"
    ) as client:
        headers = {}
        for role, password in (
            ("admin", "admin-password"),
            ("operator", "operator-password"),
            ("viewer", "viewer-password"),
        ):
            login = await client.post(
                "/auth/login",
                json={
                    "email": f"library-{role}@nodelink.test",
                    "password": password,
                },
            )
            assert login.status_code == 200
            headers[role] = {
                "Authorization": f"Bearer {login.json()['access_token']}"
            }
        yield client, headers
    await engine.dispose()


def _script_payload(**overrides):
    payload = {
        "name": "Restart Print Spooler",
        "language": "powershell",
        "content": "\r\n  Restart-Service -Name Spooler\r\n",
        "description": "Restarts a stuck print queue.",
        "tags": ["Remediation", "windows.service"],
        "supported_platforms": ["windows"],
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_technician_workflow_is_immutable_role_gated_and_audited(clients):
    client, headers = clients
    created = await client.post(
        "/script-library", json=_script_payload(), headers=headers["operator"]
    )
    assert created.status_code == 201, created.text
    script = created.json()
    script_id = script["id"]
    canonical = "Restart-Service -Name Spooler"
    assert script["latest"]["content_sha256"] == hashlib.sha256(
        canonical.encode()
    ).hexdigest()
    assert script["latest"]["content_bytes"] == len(canonical.encode())
    assert script["latest"]["tags"] == ["remediation", "windows.service"]
    assert script["latest"]["review"] is None

    listing = await client.get("/script-library", headers=headers["viewer"])
    assert listing.status_code == 200
    assert listing.json()["items"][0]["id"] == script_id
    assert (
        await client.post(
            "/script-library",
            json=_script_payload(name="Denied"),
            headers=headers["viewer"],
        )
    ).status_code == 403

    first_version = await client.get(
        f"/script-library/{script_id}/versions/1", headers=headers["viewer"]
    )
    assert first_version.status_code == 200
    assert first_version.json()["content"] == canonical

    second = await client.post(
        f"/script-library/{script_id}/versions",
        json={
            "language": "powershell",
            "content": "Restart-Service -Name Spooler -Force",
            "description": "Force restart after manual review.",
            "tags": ["remediation", "windows.service"],
            "supported_platforms": ["windows"],
        },
        headers=headers["operator"],
    )
    assert second.status_code == 201, second.text
    assert second.json()["latest_version"] == 2
    assert (
        await client.get(
            f"/script-library/{script_id}/versions/1", headers=headers["viewer"]
        )
    ).json()["content"] == canonical

    review_path = f"/script-library/{script_id}/versions/2/review"
    assert (
        await client.post(
            review_path,
            json={"state": "approved", "reason": "Reviewed in staging"},
            headers=headers["operator"],
        )
    ).status_code == 403
    reviewed = await client.post(
        review_path,
        json={"state": "approved", "reason": "Reviewed in staging"},
        headers=headers["admin"],
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["latest"]["review"]["state"] == "approved"
    duplicate = await client.post(
        review_path,
        json={"state": "rejected", "reason": "Changed our minds"},
        headers=headers["admin"],
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "review_already_final"

    record_version = reviewed.json()["record_version"]
    stale = await client.post(
        f"/script-library/{script_id}/deprecate",
        json={
            "expected_record_version": record_version - 1,
            "request_id": "deprecate-request-1",
            "reason": "Superseded by managed policy",
        },
        headers=headers["admin"],
    )
    assert stale.status_code == 409
    deprecated = await client.post(
        f"/script-library/{script_id}/deprecate",
        json={
            "expected_record_version": record_version,
            "request_id": "deprecate-request-1",
            "reason": "Superseded by managed policy",
        },
        headers=headers["admin"],
    )
    assert deprecated.status_code == 200
    assert deprecated.json()["deprecated_at"] is not None
    retry = await client.post(
        f"/script-library/{script_id}/deprecate",
        json={
            "expected_record_version": record_version,
            "request_id": "deprecate-request-1",
            "reason": "Superseded by managed policy",
        },
        headers=headers["admin"],
    )
    assert retry.status_code == 200
    assert (
        await client.post(
            f"/script-library/{script_id}/versions",
            json={
                "language": "powershell",
                "content": "Get-Service",
                "tags": [],
                "supported_platforms": ["windows"],
            },
            headers=headers["operator"],
        )
    ).status_code == 409

    async with AsyncSessionLocal() as db:
        deprecation_events = await db.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == "script_library.deprecated"
            )
        )
        events = (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.action.like("script_library.%")
                )
            )
        ).scalars().all()
    assert deprecation_events == 1
    serialized = str([event.detail for event in events])
    assert "Restart-Service" not in serialized
    assert "Superseded by managed policy" not in serialized


@pytest.mark.asyncio
async def test_validation_and_unavailable_states_are_explicit(clients):
    client, headers = clients
    for payload in (
        _script_payload(content="\x00Get-Service"),
        _script_payload(content="Write-Host \u202esecret"),
        _script_payload(content="x" * 57_345),
        _script_payload(tags=["bad tag"]),
        _script_payload(language="python"),
        _script_payload(supported_platforms=["android"]),
    ):
        response = await client.post(
            "/script-library", json=payload, headers=headers["operator"]
        )
        assert response.status_code == 422, response.text

    assert (
        await client.get("/script-library/missing", headers=headers["viewer"])
    ).status_code == 404
    assert (
        await client.get(
            "/script-library/missing/versions/1", headers=headers["viewer"]
        )
    ).status_code == 404
