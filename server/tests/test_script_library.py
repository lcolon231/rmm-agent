# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable script-library API, authorization, lifecycle, and evidence."""
from __future__ import annotations

import hashlib
import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_script_library.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

# Applied to the live Settings object by the fixture below rather than through
# the environment: another test module may already have built Settings, and an
# import-time environment default would then silently lose the race.
TEST_ENCRYPTION_KEY = base64.urlsafe_b64encode(
    b"script-parameter-test-key-32-byt"
).decode()

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core import script_parameters  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptParameterValueSet,
)


@pytest_asyncio.fixture
async def clients(monkeypatch):
    monkeypatch.setattr(
        script_parameters.settings,
        "script_parameter_encryption_key",
        TEST_ENCRYPTION_KEY,
    )
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
                    is_platform_admin=True,
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


@pytest.mark.asyncio
async def test_typed_parameter_workflow_encrypts_redacts_and_is_idempotent(clients):
    client, headers = clients
    payload = _script_payload(
        content=(
            "Write-Host $NL_PARAM_ServiceName\n"
            "Write-Host $NL_PARAM_Attempts\n"
            "Write-Host $NL_PARAM_Enabled"
        ),
        parameters=[
            {
                "key": "ServiceName",
                "label": "Service name",
                "kind": "string",
                "required": True,
                "min_length": 1,
                "max_length": 100,
            },
            {
                "key": "Attempts",
                "label": "Attempts",
                "kind": "number",
                "default_value": 3,
                "minimum": 1,
                "maximum": 10,
            },
            {
                "key": "Enabled",
                "label": "Enabled",
                "kind": "boolean",
                "default_value": True,
            },
            {
                "key": "Mode",
                "label": "Mode",
                "kind": "choice",
                "default_value": "safe",
                "choices": ["safe", "force"],
            },
            {
                "key": "ApiToken",
                "label": "API token",
                "kind": "secret",
                "required": True,
                "min_length": 8,
                "max_length": 200,
            },
        ],
    )
    created = await client.post(
        "/script-library", json=payload, headers=headers["operator"]
    )
    assert created.status_code == 201, created.text
    script = created.json()
    assert [item["kind"] for item in script["latest"]["parameters"]] == [
        "string", "number", "boolean", "choice", "secret"
    ]
    assert script["latest"]["parameters"][-1]["has_default"] is False

    path = f"/script-library/{script['id']}/versions/1/parameter-value-sets"
    not_approved = await client.post(
        path,
        json={"request_id": "prepare-before-review", "values": {}},
        headers=headers["operator"],
    )
    assert not_approved.status_code == 409
    reviewed = await client.post(
        f"/script-library/{script['id']}/versions/1/review",
        json={"state": "approved", "reason": "Parameter contract reviewed"},
        headers=headers["admin"],
    )
    assert reviewed.status_code == 200

    missing = await client.post(
        path,
        json={"request_id": "prepare-missing-value", "values": {}},
        headers=headers["operator"],
    )
    assert missing.status_code == 422
    assert missing.json()["detail"]["code"] == "parameter_ServiceName_required"

    secret = "top-secret-value"
    request_body = {
        "request_id": "prepare-run-0001",
        "values": {
            "ServiceName": "Spooler'; Remove-Item C:\\\\* #",
            "ApiToken": secret,
        },
    }
    prepared = await client.post(path, json=request_body, headers=headers["operator"])
    assert prepared.status_code == 201, prepared.text
    evidence = prepared.json()
    assert evidence["state"] == "available"
    assert evidence["provided_keys"] == ["ServiceName", "ApiToken"]
    assert evidence["defaulted_keys"] == ["Attempts", "Enabled", "Mode"]
    assert evidence["secret_keys"] == ["ApiToken"]
    assert len(evidence["values_fingerprint"]) == 64
    assert secret not in prepared.text
    assert "values" not in evidence
    assert (
        await client.post(path, json=request_body, headers=headers["viewer"])
    ).status_code == 403

    retry = await client.post(path, json=request_body, headers=headers["operator"])
    assert retry.status_code == 201
    assert retry.json()["id"] == evidence["id"]
    conflict = await client.post(
        path,
        json={
            "request_id": "prepare-run-0001",
            "values": {"ServiceName": "Other", "ApiToken": secret},
        },
        headers=headers["operator"],
    )
    assert conflict.status_code == 409

    async with AsyncSessionLocal() as db:
        stored = await db.get(ScriptParameterValueSet, evidence["id"])
        assert stored is not None
        assert secret not in stored.encrypted_values
        decrypted = script_parameters.decrypt_values(
            stored.encrypted_values,
            script_version_id=stored.script_version_id,
            value_set_id=stored.id,
        )
        assert decrypted["ApiToken"] == secret
        events = (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == "script_library.parameter_values_prepared"
                )
            )
        ).scalars().all()
    assert len(events) == 1
    assert secret not in str(events[0].detail)


def test_parameter_schema_rejects_invalid_kind_constraints_and_secret_defaults():
    from app.schemas.script_library import ScriptParameterInput

    invalid = (
        {"key": "bad-key", "label": "Bad", "kind": "string"},
        {
            "key": "Token", "label": "Token", "kind": "secret",
            "default_value": "must-not-persist",
        },
        {
            "key": "Mode", "label": "Mode", "kind": "choice",
            "choices": ["safe", "safe"],
        },
        {
            "key": "Attempts", "label": "Attempts", "kind": "number",
            "minimum": 10, "maximum": 1,
        },
        # A default outside its own bounds could never satisfy preparation.
        {
            "key": "Attempts", "label": "Attempts", "kind": "number",
            "minimum": 1, "maximum": 5, "default_value": 9,
        },
        {
            "key": "Name", "label": "Name", "kind": "string",
            "min_length": 4, "default_value": "ab",
        },
    )
    for value in invalid:
        with pytest.raises(ValueError):
            ScriptParameterInput.model_validate(value)


def _parameterized_payload(**overrides):
    return _script_payload(
        content="Write-Host $NL_PARAM_ServiceName",
        parameters=[
            {
                "key": "ServiceName",
                "label": "Service name",
                "kind": "string",
                "required": True,
                "min_length": 1,
                "max_length": 100,
            },
            {
                "key": "ApiToken",
                "label": "API token",
                "kind": "secret",
                "required": True,
                "min_length": 8,
            },
        ],
        **overrides,
    )


async def _approved_parameter_version(client, headers, name: str) -> str:
    created = await client.post(
        "/script-library",
        json=_parameterized_payload(name=name),
        headers=headers["operator"],
    )
    assert created.status_code == 201, created.text
    script_id = created.json()["id"]
    reviewed = await client.post(
        f"/script-library/{script_id}/versions/1/review",
        json={"state": "approved", "reason": "Parameter contract reviewed"},
        headers=headers["admin"],
    )
    assert reviewed.status_code == 200, reviewed.text
    return script_id


@pytest.mark.asyncio
async def test_expired_value_sets_report_expiry_without_extending_their_lifetime(
    clients,
):
    client, headers = clients
    script_id = await _approved_parameter_version(client, headers, "Expiring values")
    path = f"/script-library/{script_id}/versions/1/parameter-value-sets"
    body = {
        "request_id": "prepare-expiry-0001",
        "values": {"ServiceName": "Spooler", "ApiToken": "expiring-secret"},
    }
    prepared = await client.post(path, json=body, headers=headers["operator"])
    assert prepared.status_code == 201, prepared.text
    assert prepared.json()["state"] == "available"
    value_set_id = prepared.json()["id"]

    # Age the set past its TTL. Retrying the same request ID must surface the
    # terminal expired state instead of minting a fresh lifetime.
    async with AsyncSessionLocal() as db:
        stored = await db.get(ScriptParameterValueSet, value_set_id)
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        original_expiry = stored.expires_at
        await db.commit()

    retried = await client.post(path, json=body, headers=headers["operator"])
    assert retried.status_code == 201, retried.text
    evidence = retried.json()
    assert evidence["id"] == value_set_id
    assert evidence["state"] == "expired"
    assert "expiring-secret" not in retried.text

    async with AsyncSessionLocal() as db:
        stored = await db.get(ScriptParameterValueSet, value_set_id)
        assert stored.expires_at.replace(tzinfo=timezone.utc) == original_expiry
        assert await db.scalar(
            select(func.count()).select_from(ScriptParameterValueSet)
        ) == 1

    # An expired set no longer occupies the per-version active budget.
    fresh = await client.post(
        path,
        json={**body, "request_id": "prepare-expiry-0002"},
        headers=headers["operator"],
    )
    assert fresh.status_code == 201
    assert fresh.json()["state"] == "available"
    assert fresh.json()["id"] != value_set_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key", [None, "", "not-base64!!", base64.urlsafe_b64encode(b"short").decode()]
)
async def test_absent_or_malformed_encryption_key_fails_closed(
    clients, monkeypatch, key
):
    client, headers = clients
    script_id = await _approved_parameter_version(
        client, headers, f"Unavailable key {key!r}"
    )
    monkeypatch.setattr(
        script_parameters.settings, "script_parameter_encryption_key", key
    )
    assert script_parameters.encryption_key_configured() is False

    response = await client.post(
        f"/script-library/{script_id}/versions/1/parameter-value-sets",
        json={
            "request_id": "prepare-no-key-0001",
            "values": {"ServiceName": "Spooler", "ApiToken": "never-stored"},
        },
        headers=headers["operator"],
    )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "parameter_encryption_unavailable"
    assert detail["state"] == "unavailable"
    assert "never-stored" not in response.text

    # Failing closed must not persist a value set or an audit claim of success.
    async with AsyncSessionLocal() as db:
        assert await db.scalar(
            select(func.count()).select_from(ScriptParameterValueSet)
        ) == 0
        assert await db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.action == "script_library.parameter_values_prepared"
            )
        ) == 0
