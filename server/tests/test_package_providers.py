# SPDX-License-Identifier: AGPL-3.0-only
"""Package-provider dispatch: authorization, capability gating, payload validation,
and audit evidence (issue #55)."""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_package_providers.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_ADMIN_LOGIN = os.environ.setdefault("NODELINK_TEST_ADMIN_LOGIN", "admin-pass")
_OP_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
_VIEW_LOGIN = os.environ.setdefault("NODELINK_TEST_VIEW_LOGIN", "view-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Operator,
    OperatorRole,
)

_PACKAGE_CAP = "package-management-v1"
_CHOCO_CAP = "chocolatey-provider-v1"
_DIGEST = "a" * 64


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="pkg-admin@nodelink.test", password_hash=hash_password(_ADMIN_LOGIN), role=OperatorRole.admin),
                Operator(email="pkg-op@nodelink.test", password_hash=hash_password(_OP_LOGIN), role=OperatorRole.operator),
                Operator(email="pkg-view@nodelink.test", password_hash=hash_password(_VIEW_LOGIN), role=OperatorRole.readonly),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="pkg-admin@nodelink.test", password=_ADMIN_LOGIN):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=(_PACKAGE_CAP,)):
    org = (await client.post("/clients", json={"name": f"Pkg {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "PKG-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": list(capabilities),
            },
        )
    ).json()
    return enrollment["agent_id"]


def winget_install(**updates):
    payload = {"provider": "winget", "operation": "install", "package_ids": ["Git.Git"]}
    payload.update(updates)
    return payload


def choco_install(**updates):
    payload = {
        "provider": "chocolatey",
        "operation": "install",
        "package_ids": ["googlechrome"],
        "source": "https://community.chocolatey.org/api/v2/",
        "source_digest": _DIGEST,
        "signer": "NodeLink Ops",
    }
    payload.update(updates)
    return payload


async def dispatch(client, headers, agent_id, kind, payload):
    return await client.post(
        f"/agents/{agent_id}/commands", headers=headers, json={"kind": kind, "payload": payload}
    )


@pytest.mark.asyncio
async def test_scan_packages_operator_allowed_readonly_denied(client):
    admin = await auth(client)
    operator = await auth(client, "pkg-op@nodelink.test", _OP_LOGIN)
    readonly = await auth(client, "pkg-view@nodelink.test", _VIEW_LOGIN)
    agent_id = await enroll(client, admin)

    ok = await dispatch(client, operator, agent_id, "scan_packages", {})
    assert ok.status_code == 200, ok.text

    denied = await dispatch(client, readonly, agent_id, "scan_packages", {})
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "package_management_not_authorized"


@pytest.mark.asyncio
async def test_install_packages_requires_admin(client):
    admin = await auth(client)
    operator = await auth(client, "pkg-op@nodelink.test", _OP_LOGIN)
    agent_id = await enroll(client, admin)

    denied = await dispatch(client, operator, agent_id, "install_packages", winget_install())
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "package_management_not_authorized"

    allowed = await dispatch(client, admin, agent_id, "install_packages", winget_install())
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["payload"] == winget_install()


@pytest.mark.asyncio
async def test_capability_gating_fails_closed(client):
    admin = await auth(client)
    # Agent advertises nothing: even scan is refused.
    bare_agent = await enroll(client, admin, capabilities=())
    refused = await dispatch(client, admin, bare_agent, "scan_packages", {})
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "agent_capability_unsupported"
    assert _PACKAGE_CAP in refused.json()["detail"]["missing"]

    # Agent has base package-management but not chocolatey: winget works, choco 409s.
    agent_id = await enroll(client, admin, capabilities=(_PACKAGE_CAP,))
    assert (await dispatch(client, admin, agent_id, "install_packages", winget_install())).status_code == 200
    choco = await dispatch(client, admin, agent_id, "install_packages", choco_install())
    assert choco.status_code == 409
    assert choco.json()["detail"]["missing"] == [_CHOCO_CAP]


@pytest.mark.asyncio
async def test_chocolatey_allowed_when_capability_advertised(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin, capabilities=(_PACKAGE_CAP, _CHOCO_CAP))
    allowed = await dispatch(client, admin, agent_id, "install_packages", choco_install())
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["payload"]["source_digest"] == _DIGEST


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"provider": "apt", "operation": "install", "package_ids": ["Git.Git"]},
        {"provider": "winget", "operation": "remove", "package_ids": ["Git.Git"]},
        {"provider": "winget", "operation": "install", "package_ids": []},
        {"provider": "winget", "operation": "install", "package_ids": ["bad id!"]},
        {"provider": "winget", "operation": "install", "package_ids": ["Git.Git"], "source": "https://x"},
        # Chocolatey missing source evidence must be rejected at validation.
        {"provider": "chocolatey", "operation": "install", "package_ids": ["googlechrome"]},
        {"provider": "winget", "operation": "install", "package_ids": ["A.B"], "extra": True},
    ],
)
async def test_install_payload_is_strict(client, payload):
    admin = await auth(client)
    agent_id = await enroll(client, admin, capabilities=(_PACKAGE_CAP, _CHOCO_CAP))
    response = await dispatch(client, admin, agent_id, "install_packages", payload)
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_over_hundred_targets_rejected(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    payload = winget_install(package_ids=[f"Vendor.Pkg{i}" for i in range(101)])
    response = await dispatch(client, admin, agent_id, "install_packages", payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_install_records_gated_audit_with_redacted_detail(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin, capabilities=(_PACKAGE_CAP, _CHOCO_CAP))
    assert (await dispatch(client, admin, agent_id, "install_packages", choco_install())).status_code == 200

    async with AsyncSessionLocal() as db:
        gated = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "package_install.gated"))
        ).scalars().all()
        assert len(gated) == 1
        detail = gated[0].detail
        assert detail["provider"] == "chocolatey"
        assert detail["operation"] == "install"
        assert detail["requested"] == 1
        assert detail["source_present"] is True
        assert detail["signer_present"] is True
        assert detail["source_digest"] == _DIGEST
        # No package ids or source URLs are stored as prose.
        assert "package_ids" not in detail
        assert "source" not in detail


@pytest.mark.asyncio
async def test_scan_records_dispatched_audit(client):
    admin = await auth(client)
    agent_id = await enroll(client, admin)
    assert (await dispatch(client, admin, agent_id, "scan_packages", {"provider": "winget"})).status_code == 200
    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "package_scan.dispatched"))
        ).scalars().all()
        assert len(events) == 1
        assert events[0].detail["provider"] == "winget"
