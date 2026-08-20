# SPDX-License-Identifier: AGPL-3.0-only
"""Personalized, site-scoped agent installer downloads (issue #9).

Covers the server download flow: a technician downloads a ZIP bundling the
verified stock installer with a short-lived, single-use enrollment token; the
bundled token enrolls an agent into the intended site and cannot be replayed;
authorization is role- and site-scoped; the flow fails closed when the artifact
is unavailable or tampered; and the token secret never reaches the audit log.
"""
from __future__ import annotations

import hashlib
import io
import os
import zipfile
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
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password, hash_token  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    EnrollmentToken,
    InstallerDownload,
    Operator,
    OperatorRole,
)


ARTIFACT_BYTES = b"MZ\x90\x00 fake but stable stock installer bytes " + b"\x00" * 64
ARTIFACT_SHA256 = hashlib.sha256(ARTIFACT_BYTES).hexdigest()


@pytest_asyncio.fixture
async def client(tmp_path):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="tech@nodelink.test",
                password_hash=hash_password("tech-password"),
                role=OperatorRole.operator,
            )
        )
        db.add(
            Operator(
                email="viewer@nodelink.test",
                password_hash=hash_password("viewer-password"),
                role=OperatorRole.readonly,
            )
        )
        await grant_all_memberships(db)
        await db.commit()

    artifact = tmp_path / "NodeLinkAgentSetup-stock.exe"
    artifact.write_bytes(ARTIFACT_BYTES)
    saved = (
        settings.installer_artifact_path,
        settings.installer_artifact_version,
        settings.installer_artifact_sha256,
        settings.installer_token_ttl_seconds,
    )
    settings.installer_artifact_path = str(artifact)
    settings.installer_artifact_version = "0.1.2-test"
    settings.installer_artifact_sha256 = None
    settings.installer_token_ttl_seconds = 1800

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "tech@nodelink.test", "password": "tech-password"},
        )
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c

    (
        settings.installer_artifact_path,
        settings.installer_artifact_version,
        settings.installer_artifact_sha256,
        settings.installer_token_ttl_seconds,
    ) = saved
    await engine.dispose()


async def _make_site(c) -> str:
    cl = (await c.post("/clients", json={"name": f"Clinic {uuid4().hex}"})).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"})).json()
    return st["id"]


async def _bearer(c, email: str, password: str) -> dict:
    login = await c.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _unzip(body: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


@pytest.mark.asyncio
async def test_download_bundles_stock_installer_and_working_single_use_token(client):
    site_id = await _make_site(client)
    resp = await client.post(f"/sites/{site_id}/installer-package")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.headers.get("cache-control") == "no-store"

    entries = _unzip(resp.content)
    exe_name = "NodeLinkAgentSetup-0.1.2-test.exe"
    assert entries[exe_name] == ARTIFACT_BYTES  # stock artifact shipped verbatim
    token = entries["nodelink-enroll.token"].decode().strip()
    assert token.startswith("nlenr_")

    async with AsyncSessionLocal() as db:
        etoken = (
            await db.execute(
                select(EnrollmentToken).where(
                    EnrollmentToken.token_hash == hash_token(token)
                )
            )
        ).scalar_one()
        assert etoken.site_id == site_id
        assert etoken.max_uses == 1
        assert etoken.expires_at is not None
        download = (
            await db.execute(select(InstallerDownload))
        ).scalar_one()
        assert download.site_id == site_id
        assert download.enrollment_token_id == etoken.id
        assert download.artifact_sha256 == ARTIFACT_SHA256

    # The bundled token enrolls an agent into the intended site — zero-touch.
    enroll = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC1",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert enroll.status_code == 200, enroll.text
    agent_id = enroll.json()["agent_id"]
    async with AsyncSessionLocal() as db:
        agent = (
            await db.execute(select(Agent).where(Agent.id == agent_id))
        ).scalar_one()
        assert agent.site_id == site_id

    # Single-use: a replayed enrollment with the same token is rejected.
    replay = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC2",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert replay.status_code == 403


@pytest.mark.asyncio
async def test_authorization_is_role_and_site_scoped(client):
    site_id = await _make_site(client)

    # Unknown site: not found.
    missing = await client.post(f"/sites/{uuid4().hex}/installer-package")
    assert missing.status_code == 404

    # Read-only operator cannot mint a package.
    viewer = await _bearer(client, "viewer@nodelink.test", "viewer-password")
    denied = await client.post(
        f"/sites/{site_id}/installer-package", headers=viewer
    )
    assert denied.status_code == 403

    # Unauthenticated request is rejected.
    anon = await client.post(
        f"/sites/{site_id}/installer-package", headers={"Authorization": ""}
    )
    assert anon.status_code == 401


@pytest.mark.asyncio
async def test_fails_closed_when_artifact_missing_or_tampered(client):
    site_id = await _make_site(client)

    # Feature disabled (no artifact configured).
    settings.installer_artifact_path = None
    disabled = await client.post(f"/sites/{site_id}/installer-package")
    assert disabled.status_code == 503
    assert disabled.json()["detail"]["code"] == "installer_downloads_disabled"

    # Artifact path points at a missing file.
    settings.installer_artifact_path = "/nonexistent/NodeLinkAgentSetup.exe"
    gone = await client.post(f"/sites/{site_id}/installer-package")
    assert gone.status_code == 503
    assert gone.json()["detail"]["code"] == "installer_artifact_unavailable"


@pytest.mark.asyncio
async def test_integrity_mismatch_is_rejected_and_audited(client, tmp_path):
    site_id = await _make_site(client)
    artifact = tmp_path / "stock.exe"
    artifact.write_bytes(ARTIFACT_BYTES)
    settings.installer_artifact_path = str(artifact)
    settings.installer_artifact_sha256 = "b" * 64  # wrong digest

    resp = await client.post(f"/sites/{site_id}/installer-package")
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "installer_artifact_integrity"

    # No token or download record was created on a fail-closed refusal.
    async with AsyncSessionLocal() as db:
        assert (
            await db.execute(select(InstallerDownload))
        ).first() is None
        rejected = (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == "installer_package.rejected"
                )
            )
        ).scalar_one()
        assert rejected.detail["reason"] == "installer_artifact_integrity"


@pytest.mark.asyncio
async def test_token_secret_never_appears_in_audit_log(client):
    site_id = await _make_site(client)
    resp = await client.post(f"/sites/{site_id}/installer-package")
    token = _unzip(resp.content)["nodelink-enroll.token"].decode().strip()

    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(AuditEvent))).scalars().all()
    blob = "".join(str(r.detail) for r in rows)
    assert token not in blob
    assert token[6:] not in blob  # not even the random part
    created = [r for r in rows if r.action == "installer_package.created"]
    assert len(created) == 1
    assert created[0].detail["artifact_sha256"] == ARTIFACT_SHA256
    assert created[0].detail["site_id"] == site_id
