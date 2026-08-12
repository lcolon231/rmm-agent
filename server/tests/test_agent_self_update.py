# SPDX-License-Identifier: AGPL-3.0-only
"""Signed, staged agent self-update and rollback (issue #63).

Covers publication and manifest signing, authorization at the API boundary,
capability/channel/platform/anti-rollback targeting, staged rollout dispatch,
the endpoint outcome report, the automatic canary halt, and the operator
rollback path.
"""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_agent_self_update.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_ADMIN_LOGIN = os.environ.setdefault("NODELINK_TEST_ADMIN_LOGIN", "admin-pass")
_OP_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import agent_updates as updates  # noqa: E402
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

_CAP = "agent-self-update-v1"
_ARTIFACT_SHA = "a" * 64


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="upd-admin@nodelink.test",
                    password_hash=hash_password(_ADMIN_LOGIN),
                    role=OperatorRole.admin,
                ),
                Operator(
                    email="upd-op@nodelink.test",
                    password_hash=hash_password(_OP_LOGIN),
                    role=OperatorRole.operator,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test/api/v1"
    ) as value:
        yield value
    await engine.dispose()


async def auth(client, email="upd-admin@nodelink.test", password=_ADMIN_LOGIN):
    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(
    client,
    headers,
    *,
    capabilities=(_CAP,),
    version="0.1.0",
    operating_system="windows",
    architecture="amd64",
    channel=None,
):
    org = (
        await client.post("/clients", json={"name": f"Upd {uuid4().hex}"}, headers=headers)
    ).json()
    site = (
        await client.post(
            "/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers
        )
    ).json()
    token = (
        await client.post(
            "/enrollment-tokens", json={"site_id": site["id"]}, headers=headers
        )
    ).json()["token"]
    body = {
        "enrollment_token": token,
        "hostname": f"UPD-{uuid4().hex[:8]}",
        "os": operating_system,
        "os_version": "10.0.19045",
        "agent_version": version,
        "architecture": architecture,
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
        "supported_capabilities": list(capabilities),
    }
    if channel is not None:
        body["update_channel"] = channel
    enrollment = await client.post("/enroll", json=body)
    assert enrollment.status_code == 200, enrollment.text
    payload = enrollment.json()
    return payload["agent_id"], payload["agent_token"]


def release_body(**updates_):
    body = {
        "version": "0.2.0",
        "channel": "stable",
        "platform": "windows/amd64",
        "artifact_url": "https://releases.example/rmm-agent-0.2.0.exe",
        "artifact_sha256": _ARTIFACT_SHA,
        "artifact_size_bytes": 12_345_678,
        "min_supported_version": "0.1.0",
        "failure_threshold_percent": 50,
        "min_attempts_before_halt": 2,
    }
    body.update(updates_)
    return body


async def publish(client, headers, **updates_):
    response = await client.post(
        "/agent-updates/releases", json=release_body(**updates_), headers=headers
    )
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Version ordering and halt arithmetic (pure policy)
# --------------------------------------------------------------------------- #
def test_version_order_matches_the_agent_parser():
    # Mirrors agent/internal/selfupdate/version_test.go exactly; the two parsers
    # must agree or an anti-rollback decision could differ between the two ends.
    assert updates.compare_versions("0.1.0", "0.2.0") == -1
    assert updates.compare_versions("0.2.0", "0.1.9") == 1
    assert updates.compare_versions("1.0.0", "1.0.0") == 0
    assert updates.compare_versions("1.0.0-rc.1", "1.0.0") == -1
    assert updates.compare_versions("1.0.0-rc.2", "1.0.0-rc.10") == -1
    assert updates.compare_versions("1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert updates.compare_versions("1.0.0-1", "1.0.0-alpha") == -1
    assert updates.compare_versions("0.10.0", "0.9.0") == 1


@pytest.mark.parametrize(
    "raw", ["", "1.2", "v1.2.3", "1.2.3.4", "1.2.3+build7", "latest"]
)
def test_uncomparable_versions_fail_closed(raw):
    with pytest.raises(updates.AgentUpdateError):
        updates.parse_version(raw)


def test_rollout_bucket_is_stable_spread_and_monotone():
    agents = [f"agent-{index}" for index in range(200)]
    buckets = {agent: updates.rollout_bucket("rel-1", agent) for agent in agents}

    # Stable: the same pair always lands in the same bucket, so a rollout stage
    # is reproducible and an operator can predict who a stage reaches.
    assert all(updates.rollout_bucket("rel-1", a) == b for a, b in buckets.items())
    assert all(0 <= value <= 99 for value in buckets.values())
    # Spread: a hash that collapsed the fleet into one bucket would make a canary
    # stage either reach everyone or no one.
    assert len(set(buckets.values())) > 50
    # Independent per release, so an endpoint unlucky in one canary is not
    # permanently the canary for every future release.
    assert any(updates.rollout_bucket("rel-2", agent) != buckets[agent] for agent in agents)

    # Monotone: widening the stage only ever adds endpoints.
    for narrow, wide in ((1, 10), (10, 50), (50, 100)):
        admitted_narrow = {a for a, b in buckets.items() if b < narrow}
        admitted_wide = {a for a, b in buckets.items() if b < wide}
        assert admitted_narrow <= admitted_wide


def test_halt_requires_evidence_then_fires_at_the_threshold():
    below = updates.evaluate_halt(
        status_counts={"succeeded": 1, "failed": 1},
        failure_threshold_percent=50,
        min_attempts_before_halt=5,
    )
    assert not below.halt and below.reason == "insufficient_evidence"

    at_threshold = updates.evaluate_halt(
        status_counts={"succeeded": 1, "rolled_back": 1},
        failure_threshold_percent=50,
        min_attempts_before_halt=2,
    )
    assert at_threshold.halt and at_threshold.reason == "failure_threshold_exceeded"

    healthy = updates.evaluate_halt(
        status_counts={"succeeded": 9, "failed": 1},
        failure_threshold_percent=50,
        min_attempts_before_halt=2,
    )
    assert not healthy.halt and healthy.reason == "within_threshold"

    # Dispatched-but-unreported attempts are not evidence either way.
    unreported = updates.evaluate_halt(
        status_counts={"dispatched": 100, "succeeded": 1},
        failure_threshold_percent=50,
        min_attempts_before_halt=2,
    )
    assert not unreported.halt and unreported.reason == "insufficient_evidence"


# --------------------------------------------------------------------------- #
# Publication
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_publish_signs_the_manifest_and_targets_nothing(client):
    headers = await auth(client)
    release = await publish(client, headers)

    assert release["state"] == "published"
    assert release["rollout_percent"] == 0
    assert release["signature_valid"] is True
    assert release["signing_key_id"]
    manifest = release["manifest"]
    assert manifest["version"] == "0.2.0"
    assert manifest["artifact"]["sha256"] == _ARTIFACT_SHA
    assert manifest["min_supported_version"] == "0.1.0"
    # The signature covers exactly the stored manifest.
    assert updates.verify_manifest(
        manifest, release["signature"], release["signing_key_id"]
    )

    # Publishing alone dispatches nothing.
    async with AsyncSessionLocal() as db:
        commands = (await db.execute(select(Command))).scalars().all()
    assert commands == []


@pytest.mark.asyncio
async def test_tampered_manifest_no_longer_verifies(client):
    headers = await auth(client)
    release = await publish(client, headers)
    tampered = dict(release["manifest"])
    tampered["artifact"] = dict(tampered["artifact"], sha256="b" * 64)
    assert not updates.verify_manifest(
        tampered, release["signature"], release["signing_key_id"]
    )


@pytest.mark.asyncio
async def test_publish_is_admin_only(client):
    operator_headers = await auth(client, "upd-op@nodelink.test", _OP_LOGIN)
    response = await client.post(
        "/agent-updates/releases", json=release_body(), headers=operator_headers
    )
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_release_identity_is_immutable(client):
    headers = await auth(client)
    await publish(client, headers)
    duplicate = await client.post(
        "/agent-updates/releases", json=release_body(), headers=headers
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "agent_update_release_exists"


@pytest.mark.asyncio
async def test_publish_rejects_incoherent_or_unsafe_metadata(client):
    headers = await auth(client)
    cases = [
        # A floor above the release would make it refuse itself everywhere.
        (release_body(min_supported_version="0.9.0"), 400),
        (release_body(artifact_url="http://releases.example/a.exe"), 422),
        (release_body(artifact_sha256="A" * 64), 422),
        (release_body(artifact_size_bytes=0), 422),
        (release_body(version="latest"), 422),
        (release_body(channel="nightly"), 422),
        (release_body(platform="Windows/AMD64"), 422),
        (release_body(signer_thumbprint="ABC"), 422),
        (release_body(failure_threshold_percent=0), 422),
        (release_body(health_timeout_seconds=5), 422),
    ]
    for body, expected in cases:
        response = await client.post(
            "/agent-updates/releases", json=body, headers=headers
        )
        assert response.status_code == expected, (body, response.text)


# --------------------------------------------------------------------------- #
# Staged rollout targeting
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_rollout_dispatches_a_signed_command_and_records_an_attempt(client):
    headers = await auth(client)
    agent_id, _ = await enroll(client, headers)
    release = await publish(client, headers)

    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dispatched"] == 1
    assert body["state"] == "rolling"

    async with AsyncSessionLocal() as db:
        command = (await db.execute(select(Command))).scalars().one()
    assert command.kind == CommandKind.agent_self_update
    assert command.agent_id == agent_id
    assert command.signature  # signed before it can ever be delivered
    assert command.envelope_version == COMMAND_ENVELOPE_V3
    # The payload is a strict projection of the signed manifest.
    assert command.payload["release_id"] == release["id"]
    assert command.payload["version"] == "0.2.0"
    assert command.payload["artifact"]["sha256"] == _ARTIFACT_SHA
    assert command.payload["min_supported_version"] == "0.1.0"
    assert "url" in command.payload["artifact"]

    attempts = await client.get(
        f"/agent-updates/releases/{release['id']}/attempts", headers=headers
    )
    assert attempts.status_code == 200
    attempt = attempts.json()["attempts"][0]
    assert attempt["agent_id"] == agent_id
    assert attempt["status"] == "dispatched"
    assert attempt["from_version"] == "0.1.0"
    assert attempt["to_version"] == "0.2.0"


@pytest.mark.asyncio
async def test_rollout_skips_ineligible_endpoints_with_a_coded_reason(client):
    headers = await auth(client)
    # No self-update capability advertised.
    await enroll(client, headers, capabilities=("shell-session-v2",))
    # Wrong platform for a windows/amd64 artifact.
    await enroll(client, headers, operating_system="linux", architecture="amd64")
    # Following a different channel than the release.
    await enroll(client, headers, channel="canary")
    # Already newer than the release.
    await enroll(client, headers, version="0.9.0")
    # Already exactly the release version.
    await enroll(client, headers, version="0.2.0")

    release = await publish(client, headers)
    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    skipped = response.json()["skipped"]
    assert response.json()["dispatched"] == 0
    assert skipped["capability_unsupported"] == 1
    assert skipped["platform_mismatch"] == 1
    assert skipped["channel_mismatch"] == 1
    assert skipped["downgrade_refused"] == 1
    assert skipped["already_current"] == 1


@pytest.mark.asyncio
async def test_rollout_stage_bounds_which_endpoints_are_targeted(client):
    headers = await auth(client)
    agent_ids = [(await enroll(client, headers))[0] for _ in range(12)]
    release = await publish(client, headers)

    # Buckets are a deterministic function of (release, agent), so the exact set
    # a given stage admits is knowable up front — that is what makes a staged
    # rollout reproducible rather than a coin flip.
    buckets = {
        agent_id: updates.rollout_bucket(release["id"], agent_id)
        for agent_id in agent_ids
    }
    stage = min(buckets.values()) + 1
    expected_first_wave = sum(1 for value in buckets.values() if value < stage)

    narrow = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": stage},
        headers=headers,
    )
    assert narrow.status_code == 200, narrow.text
    staged = narrow.json()
    assert staged["dispatched"] == expected_first_wave
    assert staged["dispatched"] < 12
    assert staged["skipped"]["outside_rollout_stage"] == 12 - expected_first_wave

    wide = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert wide.status_code == 200
    # Widening only ever adds: the already-targeted endpoints are skipped, not
    # re-dispatched, so no endpoint is ever asked to update twice.
    assert wide.json()["dispatched"] == 12 - expected_first_wave
    assert wide.json()["skipped"].get("already_attempted", 0) == expected_first_wave


@pytest.mark.asyncio
async def test_rollout_cannot_shrink(client):
    headers = await auth(client)
    release = await publish(client, headers)
    await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 50},
        headers=headers,
    )
    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 10},
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "agent_update_rollout_cannot_shrink"


@pytest.mark.asyncio
async def test_rollout_dispatch_is_paged(client):
    headers = await auth(client)
    for _ in range(4):
        await enroll(client, headers)
    release = await publish(client, headers)
    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100, "max_dispatch": 2},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["dispatched"] == 2
    assert response.json()["truncated"] is True


@pytest.mark.asyncio
async def test_quarantined_endpoint_is_not_targeted(client):
    headers = await auth(client)
    agent_id, _ = await enroll(client, headers)
    quarantine = await client.post(
        f"/agents/{agent_id}/quarantine",
        json={"reason": "under investigation for a suspected compromise"},
        headers=headers,
    )
    assert quarantine.status_code in (200, 204), quarantine.text
    release = await publish(client, headers)
    response = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["dispatched"] == 0
    assert response.json()["skipped"]["agent_not_trusted"] == 1


# --------------------------------------------------------------------------- #
# Direct dispatch is refused; rollback is not
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_self_update_cannot_be_dispatched_outside_a_release(client):
    headers = await auth(client)
    agent_id, _ = await enroll(client, headers)
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "agent_self_update",
            "payload": {
                "release_id": "hand-rolled",
                "version": "9.9.9",
                "channel": "stable",
                "platform": "windows/amd64",
                "artifact": {
                    "url": "https://attacker.example/agent.exe",
                    "sha256": "b" * 64,
                    "size_bytes": 1024,
                },
                "min_supported_version": "0.0.1",
            },
        },
        headers=headers,
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "agent_self_update_requires_release"


@pytest.mark.asyncio
async def test_rollback_dispatch_is_admin_only_and_validated(client):
    headers = await auth(client)
    operator_headers = await auth(client, "upd-op@nodelink.test", _OP_LOGIN)
    agent_id, _ = await enroll(client, headers)

    denied = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "agent_update_rollback",
            "payload": {"reason": "0.2.0 crashes on start", "confirm": True},
        },
        headers=operator_headers,
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "agent_self_update_not_authorized"

    for payload in (
        {"reason": "0.2.0 crashes on start"},  # no confirmation
        {"reason": "short", "confirm": True},  # reason too short
        {"reason": "0.2.0 crashes on start", "confirm": True, "extra": 1},
        {
            "reason": "0.2.0 crashes on start",
            "confirm": True,
            "expected_current_version": "latest",
        },
    ):
        response = await client.post(
            f"/agents/{agent_id}/commands",
            json={"kind": "agent_update_rollback", "payload": payload},
            headers=headers,
        )
        assert response.status_code == 422, (payload, response.text)

    allowed = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "agent_update_rollback",
            "payload": {
                "reason": "0.2.0 crashes on start",
                "confirm": True,
                "expected_current_version": "0.1.0",
            },
        },
        headers=headers,
    )
    assert allowed.status_code == 200, allowed.text

    async with AsyncSessionLocal() as db:
        actions = set(
            (await db.execute(select(AuditEvent.action))).scalars().all()
        )
    assert "agent_update.rollback_dispatched" in actions


@pytest.mark.asyncio
async def test_rollback_requires_the_self_update_capability(client):
    headers = await auth(client)
    agent_id, _ = await enroll(client, headers, capabilities=())
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "agent_update_rollback",
            "payload": {"reason": "0.2.0 crashes on start", "confirm": True},
        },
        headers=headers,
    )
    assert response.status_code == 409, response.text


# --------------------------------------------------------------------------- #
# Endpoint outcome report and the canary halt
# --------------------------------------------------------------------------- #
async def report(client, agent_token, **body):
    return await client.post(
        "/agents/me/self-update/report",
        json=body,
        headers={"Authorization": f"Bearer {agent_token}"},
    )


@pytest.mark.asyncio
async def test_successful_outcome_is_recorded_and_refreshes_the_build(client):
    headers = await auth(client)
    agent_id, agent_token = await enroll(client, headers)
    release = await publish(client, headers)
    await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )

    response = await report(
        client,
        agent_token,
        release_id=release["id"],
        status="succeeded",
        from_version="0.1.0",
        to_version="0.2.0",
        observed_version="0.2.0",
        reason="health_check_passed",
        attempts=1,
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "ok": True,
        "recorded": True,
        "release_state": "rolling",
    }

    attempts = (
        await client.get(
            f"/agent-updates/releases/{release['id']}/attempts", headers=headers
        )
    ).json()["attempts"]
    assert attempts[0]["status"] == "succeeded"
    assert attempts[0]["observed_version"] == "0.2.0"

    detail = (
        await client.get(f"/agent-updates/releases/{release['id']}", headers=headers)
    ).json()
    assert detail["stats"]["succeeded"] == 1
    assert detail["stats"]["resolved"] == 1
    assert detail["stats"]["failure_percent"] == 0

    endpoint = (await client.get(f"/agents/{agent_id}", headers=headers)).json()
    assert endpoint["agent_version"] == "0.2.0"


@pytest.mark.asyncio
async def test_rollbacks_halt_the_release_automatically(client):
    headers = await auth(client)
    tokens = [(await enroll(client, headers))[1] for _ in range(4)]
    release = await publish(client, headers)
    await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )

    first = await report(
        client,
        tokens[0],
        release_id=release["id"],
        status="rolled_back",
        observed_version="0.1.0",
        reason="health_check_failed",
    )
    assert first.status_code == 200
    # One failure is not yet enough evidence (min_attempts_before_halt=2).
    assert first.json()["release_state"] == "rolling"

    second = await report(
        client,
        tokens[1],
        release_id=release["id"],
        status="rolled_back",
        observed_version="0.1.0",
        reason="health_check_failed",
    )
    assert second.json()["release_state"] == "halted"

    detail = (
        await client.get(f"/agent-updates/releases/{release['id']}", headers=headers)
    ).json()
    assert detail["state"] == "halted"
    assert detail["halted_reason"] == "failure_threshold_exceeded"
    assert detail["stats"]["rolled_back"] == 2

    # A halted release dispatches nothing further, in either direction.
    advance = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert advance.status_code == 409
    assert advance.json()["detail"]["code"] == "agent_update_release_not_active"

    async with AsyncSessionLocal() as db:
        actions = (await db.execute(select(AuditEvent.action))).scalars().all()
    assert "agent_update.rollout_halted" in actions
    assert "agent_update.outcome_reported" in actions


@pytest.mark.asyncio
async def test_report_for_an_untargeted_release_is_evidence_only(client):
    headers = await auth(client)
    _, agent_token = await enroll(client, headers)
    release = await publish(client, headers)

    response = await report(
        client,
        agent_token,
        release_id=release["id"],
        status="rolled_back",
        reason="operator_requested_rollback",
    )
    assert response.status_code == 200
    assert response.json()["recorded"] is False

    detail = (
        await client.get(f"/agent-updates/releases/{release['id']}", headers=headers)
    ).json()
    # An endpoint the rollout never chose cannot move the halt rule.
    assert detail["stats"]["resolved"] == 0
    assert detail["state"] == "published"


@pytest.mark.asyncio
async def test_report_requires_agent_authentication_and_a_known_status(client):
    headers = await auth(client)
    _, agent_token = await enroll(client, headers)

    unauth = await client.post(
        "/agents/me/self-update/report", json={"status": "succeeded"}
    )
    assert unauth.status_code == 401

    bad_status = await report(client, agent_token, status="completed")
    assert bad_status.status_code == 422

    bad_reason = await report(
        client, agent_token, status="failed", reason="Something Went Wrong!"
    )
    assert bad_reason.status_code == 422


# --------------------------------------------------------------------------- #
# Pause, resume, halt
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_pause_stops_targeting_and_resume_restores_it(client):
    headers = await auth(client)
    await enroll(client, headers)
    release = await publish(client, headers)

    paused = await client.post(
        f"/agent-updates/releases/{release['id']}/pause", headers=headers
    )
    assert paused.status_code == 200
    assert paused.json()["state"] == "paused"

    blocked = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "agent_update_release_not_active"

    resumed = await client.post(
        f"/agent-updates/releases/{release['id']}/resume", headers=headers
    )
    assert resumed.status_code == 200
    assert resumed.json()["state"] == "published"

    advance = await client.post(
        f"/agent-updates/releases/{release['id']}/rollout",
        json={"rollout_percent": 100},
        headers=headers,
    )
    assert advance.status_code == 200
    assert advance.json()["dispatched"] == 1


@pytest.mark.asyncio
async def test_halt_is_terminal(client):
    headers = await auth(client)
    release = await publish(client, headers)
    halted = await client.post(
        f"/agent-updates/releases/{release['id']}/halt",
        json={"reason": "0.2.0 corrupts the config on upgrade"},
        headers=headers,
    )
    assert halted.status_code == 200
    assert halted.json()["state"] == "halted"
    assert halted.json()["halted_reason"] == "operator_halted"

    for path in ("resume", "pause"):
        response = await client.post(
            f"/agent-updates/releases/{release['id']}/{path}", headers=headers
        )
        assert response.status_code == 409, (path, response.text)
        assert response.json()["detail"]["code"] == "agent_update_release_halted"


@pytest.mark.asyncio
async def test_release_views_are_admin_only(client):
    headers = await auth(client)
    release = await publish(client, headers)
    operator_headers = await auth(client, "upd-op@nodelink.test", _OP_LOGIN)
    for path in (
        "/agent-updates/releases",
        f"/agent-updates/releases/{release['id']}",
        f"/agent-updates/releases/{release['id']}/attempts",
    ):
        response = await client.get(path, headers=operator_headers)
        assert response.status_code == 403, path


@pytest.mark.asyncio
async def test_unknown_release_is_a_404(client):
    headers = await auth(client)
    response = await client.get(
        f"/agent-updates/releases/{uuid4()}", headers=headers
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "agent_update_release_not_found"
