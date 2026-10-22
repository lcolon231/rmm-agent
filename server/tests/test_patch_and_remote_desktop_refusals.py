# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal branches of the patch-policy and remote-desktop routes (issue #284).

Behavior under test -- each route refuses with the documented status and
detail instead of falling through to a 500 or leaking a row:
  - patch approval policy get/revise/delete on an unknown policy id -> 404
  - per-agent effective patch policy, compliance, and compliance history on
    an unknown agent -> 404
  - remote-desktop availability, launch, launch lookup, and launch close on an
    unknown agent/launch -> 404 (provider enabled, so the agent lookup runs)
  - manual mapping create on an unknown agent -> 404; delete on an unknown
    mapping or a mapping whose agent row is gone -> 404
  - mapping sync with the provider disabled -> 409 remote_desktop_disabled,
    and with MeshCentral unreachable -> 503 remote_desktop_unavailable

Run just this file:  pytest tests/test_patch_and_remote_desktop_refusals.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_patch_and_remote_desktop_refusals.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
# Login value comes from the environment (defaulted for local runs) so no
# password literal sits next to an operator identity.
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.api.meshcentral import get_meshcentral_client  # noqa: E402
from app.core import meshcentral as mc  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentMeshMapping,
    MeshMappingOrigin,
    MeshMappingState,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)
from tests._tenancy import grant_all_memberships  # noqa: E402

_ADMIN = "refusal-admin@nodelink.test"
_MISSING = "00000000-0000-0000-0000-000000000000"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def env(monkeypatch):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(
            email=_ADMIN,
            password_hash=hash_password(_LOGIN),
            role=OperatorRole.admin,
            is_platform_admin=True,
            script_execution_scope=ScriptExecutionScope.global_,
        ))
        await grant_all_memberships(db)
        await db.commit()
    # Provider enabled with a healthy fake client so every route gets past the
    # provider gate and reaches its own lookup; individual tests flip these.
    monkeypatch.setattr(settings, "meshcentral_provider", "enabled")
    fake = mc.FakeMeshCentralClient()
    app.dependency_overrides[get_meshcentral_client] = lambda: fake
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        r = await c.post("/auth/login", json={"email": _ADMIN, "password": _LOGIN})
        assert r.status_code == 200, r.text
        c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        yield c
    app.dependency_overrides.pop(get_meshcentral_client, None)
    await engine.dispose()


_REVISION = {"rules": [], "default_action": "deny"}


@pytest.mark.parametrize(
    ("method", "path", "body", "detail"),
    [
        ("GET", f"/patch-approval/policies/{_MISSING}", None, "Patch approval policy not found"),
        ("PUT", f"/patch-approval/policies/{_MISSING}", _REVISION, "Patch approval policy not found"),
        ("DELETE", f"/patch-approval/policies/{_MISSING}", None, "Patch approval policy not found"),
        ("GET", f"/agents/{_MISSING}/patch-approval/effective", None, "Agent not found"),
        ("GET", f"/agents/{_MISSING}/patch-compliance", None, "Agent not found"),
        ("GET", f"/agents/{_MISSING}/patch-compliance/history", None, "Agent not found"),
        ("GET", f"/agents/{_MISSING}/remote-desktop/availability", None, "Agent not found"),
        ("POST", f"/agents/{_MISSING}/remote-desktop/launches", {}, "Agent not found"),
        (
            "GET",
            f"/agents/{_MISSING}/remote-desktop/launches/{_MISSING}",
            None,
            "Remote desktop launch not found",
        ),
        (
            "POST",
            f"/agents/{_MISSING}/remote-desktop/launches/{_MISSING}/close",
            {},
            "Remote desktop launch not found",
        ),
        (
            "POST",
            "/remote-desktop/mappings",
            {"agent_id": _MISSING, "meshcentral_node_id": "node//missing"},
            "Agent not found",
        ),
        ("DELETE", f"/remote-desktop/mappings/{_MISSING}", None, "Mapping not found"),
    ],
)
async def test_unknown_resource_is_refused_with_404(env, method, path, body, detail):
    r = await env.request(method, path, json=body)
    assert r.status_code == 404, r.text
    assert r.json()["detail"] == detail


async def _enroll_agent(c) -> str:
    org = (await c.post("/clients", json={"name": f"Refusal {uuid4().hex}"})).json()
    site = (await c.post("/sites", json={"client_id": org["id"], "name": "HQ"})).json()
    token = (await c.post("/enrollment-tokens", json={"site_id": site["id"]})).json()["token"]
    r = await c.post("/enroll", json={
        "enrollment_token": token,
        "hostname": "PC-REFUSAL",
        "os": "windows",
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        "supported_capabilities": [],
    })
    assert r.status_code == 200, r.text
    return r.json()["agent_id"]


async def _seed_mapping(agent_id: str) -> str:
    async with AsyncSessionLocal() as db:
        row = AgentMeshMapping(
            agent_id=agent_id,
            meshcentral_node_id=f"node//{agent_id}",
            state=MeshMappingState.active,
            origin=MeshMappingOrigin.manual,
            created_at=_now(),
            updated_at=_now(),
        )
        db.add(row)
        await db.commit()
        return row.id


async def test_delete_mapping_whose_agent_row_is_gone_is_refused(env):
    # The FK cascades on Postgres; SQLite (the test DB) does not enforce it, so
    # an orphaned mapping row models a mapping that outlived its agent.
    if engine.dialect.name != "sqlite":
        pytest.skip("orphan mapping rows need an unenforced foreign key")
    mapping_id = await _seed_mapping(str(uuid4()))

    r = await env.delete(f"/remote-desktop/mappings/{mapping_id}")
    assert r.status_code == 404, r.text
    assert r.json()["detail"] == "Mapping not found"
    async with AsyncSessionLocal() as db:
        assert await db.get(AgentMeshMapping, mapping_id) is not None


async def test_sync_with_provider_disabled_is_refused(env, monkeypatch):
    monkeypatch.setattr(settings, "meshcentral_provider", "disabled")
    r = await env.post("/remote-desktop/mappings/sync")
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == {"code": "remote_desktop_disabled"}


async def test_sync_with_meshcentral_unreachable_fails_closed(env, monkeypatch):
    # Reconciliation only contacts MeshCentral when a mapping exists. The sync
    # route builds its own client from settings (no dependency), so the
    # factory is swapped for an unavailable fake.
    await _seed_mapping(await _enroll_agent(env))
    monkeypatch.setattr(
        mc, "get_client", lambda config: mc.FakeMeshCentralClient(available=False)
    )
    r = await env.post("/remote-desktop/mappings/sync")
    assert r.status_code == 503, r.text
    assert r.json()["detail"] == {"code": "remote_desktop_unavailable"}
