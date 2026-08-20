# SPDX-License-Identifier: AGPL-3.0-only
"""Software deployment dispatch: authorization, capability gating, payload
validation, and audit evidence (issue #56)."""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_software_deployment.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_ADMIN_LOGIN = os.environ.setdefault("NODELINK_TEST_ADMIN_LOGIN", "admin-pass")
_OP_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.models.models import AuditEvent, Operator, OperatorRole  # noqa: E402

_CAP = "software-deployment-v1"
_SHA = "b" * 64


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="dep-admin@nodelink.test", password_hash=hash_password(_ADMIN_LOGIN), role=OperatorRole.admin, is_platform_admin=True),
                Operator(email="dep-op@nodelink.test", password_hash=hash_password(_OP_LOGIN), role=OperatorRole.operator),
            ]
        )
        await grant_all_memberships(db)
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="dep-admin@nodelink.test", password=_ADMIN_LOGIN):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=(_CAP,)):
    org = (await client.post("/clients", json={"name": f"Dep {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "DEP-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": list(capabilities),
            },
        )
    ).json()
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return enrollment["agent_id"]


def deploy_payload(**updates):
    payload = {
        "url": "https://cdn.example.com/app.msi",
        "sha256": _SHA,
        "installer_type": "msi",
        "arguments": ["/quiet"],
        "timeout_seconds": 600,
    }
    payload.update(updates)
    return payload


async def dispatch(client, headers, agent_id, payload):
    return await client.post(
        f"/agents/{agent_id}/commands", headers=headers, json={"kind": "deploy_software", "payload": payload}
    )


@pytest.mark.asyncio
async def test_requires_admin(client):
    admin = await auth(client)
    operator = await auth(client, "dep-op@nodelink.test", _OP_LOGIN)
    agent_id = await enroll(client, admin)

    denied = await dispatch(client, operator, agent_id, deploy_payload())
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "software_deployment_not_authorized"

    allowed = await dispatch(client, admin, agent_id, deploy_payload())
    assert allowed.status_code == 200, allowed.text


@pytest.mark.asyncio
async def test_capability_gating_fails_closed(client):
    admin = await auth(client)
    bare = await enroll(client, admin, capabilities=())
    refused = await dispatch(client, admin, bare, deploy_payload())
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "agent_capability_unsupported"
    assert _CAP in refused.json()["detail"]["missing"]


@pytest.mark.asyncio
async def test_reboot_and_signer_accepted(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    payload = deploy_payload(
        signer_thumbprint="A" * 40,
        success_exit_codes=[0, 3010],
        reboot={"policy": "if_required", "delay_seconds": 300, "requires_no_user": True},
    )
    resp = await dispatch(client, admin, agent_id, payload)
    assert resp.status_code == 200, resp.text
    assert resp.json()["payload"]["reboot"]["policy"] == "if_required"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        deploy_payload(url="http://cdn.example.com/app.msi"),   # not https
        deploy_payload(sha256="nothex"),                        # bad digest
        deploy_payload(installer_type="deb"),                   # bad type
        deploy_payload(timeout_seconds=5),                      # below min
        deploy_payload(timeout_seconds=99999),                  # above max
        deploy_payload(signer_thumbprint="short"),              # bad thumbprint
        deploy_payload(arguments=["ok", "bad\ncontrol"]),       # control char
        {**deploy_payload(), "extra": True},                    # unknown field
        deploy_payload(reboot={"policy": "forced"}),            # missing delay
    ],
)
async def test_payload_is_strict(client, payload):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    resp = await dispatch(client, admin, agent_id, payload)
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_too_many_arguments_rejected(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    resp = await dispatch(client, admin, agent_id, deploy_payload(arguments=[f"/a{i}" for i in range(33)]))
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dispatch_records_redacted_audit(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    payload = deploy_payload(signer_thumbprint="C" * 40)
    assert (await dispatch(client, admin, agent_id, payload)).status_code == 200

    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "software_deployment.dispatched"))
        ).scalars().all()
        assert len(events) == 1
        detail = events[0].detail
        assert detail["installer_type"] == "msi"
        assert detail["sha256"] == _SHA
        assert detail["signer_pinned"] is True
        assert detail["argument_count"] == 1
        assert detail["reboot_policy"] == "never"
        # The source URL is never stored as prose; only its digest.
        assert "url" not in detail
        assert len(detail["url_sha256"]) == 64
