# SPDX-License-Identifier: AGPL-3.0-only
"""Justified emergency override tests (issue #65).

Each property the exception record is supposed to hold gets its own test:
per-policy opt-in, tenant-admin standing, command authorization, a real
justification, single use with the run linked to the override, payload
binding, expiry, revocation, the activator never spending someone else's
override or reviewing their own, notification outcome recorded either way,
tenant isolation, the scheduler still refusing, opt-in withdrawal invalidating
open overrides, and the audit evidence produced along the way.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_emergency_overrides.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.api import emergency_overrides as overrides_api  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.email_notifications import ProviderError  # noqa: E402
from app.core.emergency_overrides import MAX_OPEN_OVERRIDES_PER_OPERATOR  # noqa: E402
from app.core.scheduler import dispatch_scheduled_tasks_once  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    ClientRole,
    Command,
    CommandKind,
    EmergencyOverride,
    EmergencyOverrideStatus,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
    ScriptExecutionScope,
)

ACTIVATOR = "activator@nodelink.test"  # admin, client_admin on the tenant
REVIEWER = "reviewer@nodelink.test"  # admin, client_admin on the tenant
OPERATOR = "operator@nodelink.test"  # operator, client_operator on the tenant
NOSCRIPT = "noscript@nodelink.test"  # admin, client_admin, no script grant
OUTSIDER = "outsider@nodelink.test"  # admin, no membership
PLATFORM = "platform@nodelink.test"

SCRIPT_PAYLOAD = {"script": "Restart-Service -Name Spooler"}
JUSTIFICATION = "Print server down for 40 users, INC-9001, approvers unreachable"
RECIPIENTS = "soc@nodelink.test, oncall@nodelink.test"


class CapturingProvider:
    def __init__(self) -> None:
        self.messages: list = []

    async def send(self, delivery):  # pragma: no cover
        raise AssertionError("the override path must not use the alert send")

    async def send_message(self, message) -> str:
        self.messages.append(message)
        return "00000000-0000-4000-8000-000000000000"


class FailingProvider:
    def __init__(self, code: str = "internal_server_error") -> None:
        self.code = code
        self.calls = 0

    async def send(self, delivery):  # pragma: no cover
        raise AssertionError("the override path must not use the alert send")

    async def send_message(self, message) -> str:
        self.calls += 1
        raise ProviderError(self.code, retryable=True)


@pytest.fixture
def provider(monkeypatch) -> CapturingProvider:
    captured = CapturingProvider()
    monkeypatch.setattr(settings, "email_alert_recipients", RECIPIENTS)
    monkeypatch.setattr(
        overrides_api, "build_transactional_provider", lambda config=settings: captured
    )
    return captured


@pytest.fixture
def failing_provider(monkeypatch) -> FailingProvider:
    failing = FailingProvider()
    monkeypatch.setattr(settings, "email_alert_recipients", RECIPIENTS)
    monkeypatch.setattr(
        overrides_api, "build_transactional_provider", lambda config=settings: failing
    )
    return failing


@pytest_asyncio.fixture
async def client(provider):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email=ACTIVATOR,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=REVIEWER,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=OPERATOR,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.operator,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=NOSCRIPT,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                ),
                Operator(
                    email=OUTSIDER,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=PLATFORM,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def auth(client, email, password=_LOGIN):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def grant_membership(email: str, client_id: str, role: ClientRole) -> None:
    async with AsyncSessionLocal() as db:
        op_id = (await db.execute(select(Operator.id).where(Operator.email == email))).scalar_one()
        db.add(
            OperatorClientMembership(
                operator_id=op_id,
                client_id=client_id,
                role=role,
                granted_by="test-seed",
                reason="test",
            )
        )
        await db.commit()


async def provision(client):
    """A tenant with one enrolled agent, and the cast admitted to it."""
    headers = await auth(client, PLATFORM)
    org = (await client.post("/clients", json={"name": f"Override {uuid4().hex}"}, headers=headers)).json()
    site = (
        await client.post("/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers)
    ).json()
    token = (
        await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)
    ).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "OVERRIDE-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": [],
            },
        )
    ).json()
    await grant_membership(ACTIVATOR, org["id"], ClientRole.client_admin)
    await grant_membership(REVIEWER, org["id"], ClientRole.client_admin)
    await grant_membership(OPERATOR, org["id"], ClientRole.client_operator)
    await grant_membership(NOSCRIPT, org["id"], ClientRole.client_admin)
    return org["id"], site["id"], enrollment["agent_id"]


async def create_policy(client, client_id: str, *, override_allowed: bool = True):
    headers = await auth(client, PLATFORM)
    response = await client.post(
        "/approval-policies",
        json={
            "name": f"Dual control {uuid4().hex[:8]}",
            "scope": "client",
            "scope_id": client_id,
            "command_kinds": ["powershell"],
            "required_approvals": 2,
            "request_ttl_seconds": 3600,
            "emergency_override_allowed": override_allowed,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


async def activate(client, agent_id: str, *, actor=ACTIVATOR, payload=None, **extra):
    headers = await auth(client, actor)
    body = {
        "agent_id": agent_id,
        "kind": "powershell",
        "payload": SCRIPT_PAYLOAD if payload is None else payload,
        "justification": JUSTIFICATION,
    }
    body.update(extra)
    return await client.post("/emergency-overrides", json=body, headers=headers)


async def dispatch(client, agent_id: str, *, override_id=None, approval_id=None, payload=None, actor=ACTIVATOR):
    headers = await auth(client, actor)
    body = {"kind": "powershell", "payload": SCRIPT_PAYLOAD if payload is None else payload}
    if override_id is not None:
        body["emergency_override_id"] = override_id
    if approval_id is not None:
        body["approval_request_id"] = approval_id
    return await client.post(f"/agents/{agent_id}/commands", json=body, headers=headers)


async def audit_actions() -> list[str]:
    async with AsyncSessionLocal() as db:
        return [r[0] for r in (await db.execute(select(AuditEvent.action).order_by(AuditEvent.seq))).all()]


async def audit_details(action: str) -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            select(AuditEvent.detail).where(AuditEvent.action == action).order_by(AuditEvent.seq)
        )
        return [r[0] for r in rows.all()]


async def load_override(override_id: str) -> EmergencyOverride:
    async with AsyncSessionLocal() as db:
        return await db.get(EmergencyOverride, override_id)


# --------------------------------------------------------------------------- #
# Activation refusals
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_policy_without_opt_in_refuses_activation(client):
    """The flag is the whole opt-in: a strict policy cannot be overridden."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id, override_allowed=False)

    response = await activate(client, agent_id)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_not_permitted"
    denied = await audit_details("emergency_override.denied")
    assert denied and denied[-1]["reason"] == "emergency_override_not_permitted"


@pytest.mark.asyncio
async def test_no_policy_means_no_override_to_mint(client):
    _, _, agent_id = await provision(client)
    response = await activate(client, agent_id)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_not_required"


@pytest.mark.asyncio
async def test_client_operator_cannot_activate(client):
    """Authority to dispatch is not authority to skip the second reviewer."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id, actor=OPERATOR)
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "emergency_override_role_insufficient"


@pytest.mark.asyncio
async def test_admin_without_script_grant_cannot_activate(client):
    """An override never grants an action the activator could not run anyway."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id, actor=NOSCRIPT)
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"].startswith("emergency_override_")
    assert response.json()["detail"]["code"] not in (
        "emergency_override_role_insufficient",
        "emergency_override_not_permitted",
    )


@pytest.mark.asyncio
async def test_outsider_cannot_activate_against_a_foreign_tenant(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id, actor=OUTSIDER)
    assert response.status_code == 404, response.text


@pytest.mark.asyncio
async def test_weak_justification_is_rejected(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id, justification="urgent")
    assert response.status_code == 422, response.text
    assert not await audit_details("emergency_override.activated")


@pytest.mark.asyncio
async def test_open_override_limit_is_enforced(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    for n in range(MAX_OPEN_OVERRIDES_PER_OPERATOR):
        response = await activate(client, agent_id, payload={"script": f"Write-Host {n}"})
        assert response.status_code == 201, response.text
    response = await activate(client, agent_id, payload={"script": "Write-Host overflow"})
    assert response.status_code == 429, response.text
    assert response.json()["detail"]["code"] == "emergency_override_limit_reached"


# --------------------------------------------------------------------------- #
# Spending
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_override_authorizes_exactly_one_dispatch_and_links_the_run(client):
    client_id, _, agent_id = await provision(client)
    policy = await create_policy(client, client_id)

    # Without either an approval or an override the policy still bites.
    refused = await dispatch(client, agent_id)
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "approval_required"

    created = await activate(client, agent_id)
    assert created.status_code == 201, created.text
    override = created.json()
    assert override["status"] == "active"
    assert override["policy_id"] == policy["id"]
    assert override["required_approvals"] == 2
    assert "payload" in override and override["payload_keys"] == ["script"]

    run = await dispatch(client, agent_id, override_id=override["id"])
    assert run.status_code == 200, run.text
    command_id = run.json()["id"]

    async with AsyncSessionLocal() as db:
        command = await db.get(Command, command_id)
        row = await db.get(EmergencyOverride, override["id"])
    assert command.emergency_override_id == override["id"]
    assert command.approval_request_id is None
    assert row.status == EmergencyOverrideStatus.consumed
    assert row.consumed_at is not None

    allowed = await audit_details("approval_gate.allowed")
    assert allowed[-1]["reason"] == "emergency_override_satisfied"
    assert allowed[-1]["emergency_override_id"] == override["id"]
    assert allowed[-1]["approver_operator_ids"] == []

    # Spent once: a replay is a detectable refusal, not a second run.
    replay = await dispatch(client, agent_id, override_id=override["id"])
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"]["code"] == "emergency_override_already_consumed"

    headers = await auth(client, ACTIVATOR)
    detail = await client.get(f"/emergency-overrides/{override['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["consumed_command_id"] == command_id


@pytest.mark.asyncio
async def test_mutated_payload_cannot_spend_the_override(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    response = await dispatch(
        client, agent_id, override_id=override["id"], payload={"script": "Stop-Service -Name MSSQLSERVER"}
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_payload_mismatch"
    assert (await load_override(override["id"])).status == EmergencyOverrideStatus.active


@pytest.mark.asyncio
async def test_expired_override_is_refused_and_reported(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(EmergencyOverride)
            .where(EmergencyOverride.id == override["id"])
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        await db.commit()

    response = await dispatch(client, agent_id, override_id=override["id"])
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_expired"

    headers = await auth(client, REVIEWER)
    listed = await client.get("/emergency-overrides", headers=headers)
    assert [row["status"] for row in listed.json() if row["id"] == override["id"]] == ["expired"]
    assert "emergency_override.expired" in await audit_actions()


@pytest.mark.asyncio
async def test_ttl_is_clamped_to_the_ceiling(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id, ttl_seconds=7200)
    assert response.status_code == 422, response.text
    response = await activate(client, agent_id, ttl_seconds=3600)
    assert response.status_code == 201, response.text
    body = response.json()
    created = datetime.fromisoformat(body["created_at"])
    expires = datetime.fromisoformat(body["expires_at"])
    assert timedelta(minutes=59) < expires - created <= timedelta(hours=1)


@pytest.mark.asyncio
async def test_only_the_activator_can_spend_an_override(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    response = await dispatch(client, agent_id, override_id=override["id"], actor=REVIEWER)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_activator_mismatch"


@pytest.mark.asyncio
async def test_citing_an_approval_and_an_override_together_is_refused(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()
    response = await dispatch(
        client, agent_id, override_id=override["id"], approval_id=str(uuid4())
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "approval_and_override_both_cited"
    assert (await load_override(override["id"])).status == EmergencyOverrideStatus.active


@pytest.mark.asyncio
async def test_override_without_a_governing_policy_is_refused_at_dispatch(client):
    client_id, _, agent_id = await provision(client)
    policy = await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()
    headers = await auth(client, PLATFORM)
    deleted = await client.delete(f"/approval-policies/{policy['id']}", headers=headers)
    assert deleted.status_code == 204, deleted.text

    response = await dispatch(client, agent_id, override_id=override["id"])
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_not_required"


@pytest.mark.asyncio
async def test_withdrawing_the_opt_in_invalidates_open_overrides(client):
    """Eligibility is re-checked live, including the policy flag itself."""
    client_id, _, agent_id = await provision(client)
    policy = await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    headers = await auth(client, PLATFORM)
    patched = await client.patch(
        f"/approval-policies/{policy['id']}",
        json={"emergency_override_allowed": False},
        headers=headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["emergency_override_allowed"] is False
    updated = (await audit_details("approval_policy.updated"))[-1]
    assert updated["previous_emergency_override_allowed"] is True
    assert updated["emergency_override_allowed"] is False

    response = await dispatch(client, agent_id, override_id=override["id"])
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "emergency_override_activator_no_longer_eligible"


# --------------------------------------------------------------------------- #
# Revocation and review
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_revoked_override_cannot_be_spent_or_revoked_twice(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    headers = await auth(client, ACTIVATOR)
    revoked = await client.post(
        f"/emergency-overrides/{override['id']}/revoke",
        json={"reason": "Approver came online, going through normal approval"},
        headers=headers,
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoked_by_email"] == ACTIVATOR

    response = await dispatch(client, agent_id, override_id=override["id"])
    assert response.status_code == 409 and response.json()["detail"]["code"] == "emergency_override_revoked"

    again = await client.post(
        f"/emergency-overrides/{override['id']}/revoke",
        json={"reason": "Trying to revoke a second time"},
        headers=headers,
    )
    assert again.status_code == 409 and again.json()["detail"]["code"] == "emergency_override_not_active"

    detail = (await audit_details("emergency_override.revoked"))[-1]
    assert detail["revoked_by_activator"] is True
    assert "reason" not in detail and detail["reason_bytes"] > 0


@pytest.mark.asyncio
async def test_client_operator_cannot_revoke_someone_elses_override(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()
    headers = await auth(client, OPERATOR)
    response = await client.post(
        f"/emergency-overrides/{override['id']}/revoke",
        json={"reason": "Operator trying to withdraw it"},
        headers=headers,
    )
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_review_requires_a_different_tenant_admin_and_happens_once(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()
    note = {"note": "Checked INC-9001; the override was warranted and the script matched the ticket"}

    own = await client.post(
        f"/emergency-overrides/{override['id']}/review", json=note, headers=await auth(client, ACTIVATOR)
    )
    assert own.status_code == 403 and own.json()["detail"]["code"] == "emergency_override_self_review_not_permitted"

    operator = await client.post(
        f"/emergency-overrides/{override['id']}/review", json=note, headers=await auth(client, OPERATOR)
    )
    assert operator.status_code == 403 and operator.json()["detail"]["code"] == "emergency_override_review_not_permitted"

    reviewer_headers = await auth(client, REVIEWER)
    queue = await client.get("/emergency-overrides?unreviewed_only=true", headers=reviewer_headers)
    assert [row["id"] for row in queue.json()] == [override["id"]]

    first = await client.post(f"/emergency-overrides/{override['id']}/review", json=note, headers=reviewer_headers)
    assert first.status_code == 200, first.text
    assert first.json()["reviewed_by_email"] == REVIEWER
    assert first.json()["review_note"] == note["note"]

    second = await client.post(f"/emergency-overrides/{override['id']}/review", json=note, headers=reviewer_headers)
    assert second.status_code == 409 and second.json()["detail"]["code"] == "emergency_override_already_reviewed"

    queue = await client.get("/emergency-overrides?unreviewed_only=true", headers=reviewer_headers)
    assert queue.json() == []
    reviewed = (await audit_details("emergency_override.reviewed"))[-1]
    assert "note" not in reviewed and reviewed["note_sha256"]


# --------------------------------------------------------------------------- #
# Notification
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_activation_notifies_every_configured_recipient(client, provider):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    assert override["notified_at"] is not None
    assert override["notification_error"] is None
    assert override["notified_recipient_count"] == 2
    assert sorted(m.recipient for m in provider.messages) == ["oncall@nodelink.test", "soc@nodelink.test"]
    for message in provider.messages:
        assert message.namespace == "emergency-override"
        # The payload is operator-controlled and may hold secrets; it never
        # travels by email. The justification and the actor do.
        assert SCRIPT_PAYLOAD["script"] not in message.text_body
        assert SCRIPT_PAYLOAD["script"] not in message.html_body
        assert ACTIVATOR in message.text_body
        assert JUSTIFICATION in message.text_body
    notified = (await audit_details("emergency_override.notified"))[-1]
    assert notified["recipient_count"] == 2


@pytest.mark.asyncio
async def test_notification_failure_is_recorded_and_does_not_block(client, failing_provider):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await activate(client, agent_id)
    assert response.status_code == 201, response.text
    override = response.json()
    assert override["status"] == "active"
    assert override["notified_at"] is None
    assert override["notification_error"] == "internal_server_error"
    assert failing_provider.calls == 2
    failed = (await audit_details("emergency_override.notification_failed"))[-1]
    assert failed["error"] == "internal_server_error" and failed["recipient_count"] == 0

    # Still spendable: the emergency does not wait for SMTP.
    run = await dispatch(client, agent_id, override_id=override["id"])
    assert run.status_code == 200, run.text


@pytest.mark.asyncio
async def test_no_recipients_configured_is_recorded(client, monkeypatch):
    monkeypatch.setattr(settings, "email_alert_recipients", "")
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()
    assert override["notification_error"] == "no_recipients_configured"
    assert "emergency_override.notification_failed" in await audit_actions()


# --------------------------------------------------------------------------- #
# Tenancy and bypasses
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_overrides_are_invisible_and_unspendable_across_tenants(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    outsider = await auth(client, OUTSIDER)
    assert (await client.get("/emergency-overrides", headers=outsider)).json() == []
    assert (await client.get(f"/emergency-overrides/{override['id']}", headers=outsider)).status_code == 404
    review = await client.post(
        f"/emergency-overrides/{override['id']}/review",
        json={"note": "Outsider attempting a review"},
        headers=outsider,
    )
    assert review.status_code == 404


@pytest.mark.asyncio
async def test_scheduled_task_is_still_refused_while_an_override_is_open(client):
    """An override is for one interactive dispatch; it never reaches the scheduler."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    assert (await activate(client, agent_id)).status_code == 201

    async with AsyncSessionLocal() as db:
        db.add(
            ScheduledTask(
                name="Nightly spooler restart",
                kind=CommandKind.powershell,
                payload=SCRIPT_PAYLOAD,
                target_type=ScheduleTargetType.agent,
                target_id=agent_id,
                cron_expression="0 3 * * *",
                timezone="UTC",
                enabled=True,
                next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                concurrency_policy=ScheduleConcurrencyPolicy.skip,
                misfire_policy=ScheduleMisfirePolicy.run_once,
                created_by_email=ACTIVATOR,
            )
        )
        await db.commit()
    async with AsyncSessionLocal() as db:
        await dispatch_scheduled_tasks_once(db)
        await db.commit()
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(Command))).scalars().all() == []
        assert (await db.execute(select(ScheduledTask))).scalar_one().last_status == "approval_required"


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_activation_evidence_is_complete_and_redacted(client):
    client_id, site_id, agent_id = await provision(client)
    policy = await create_policy(client, client_id)
    override = (await activate(client, agent_id)).json()

    activated = (await audit_details("emergency_override.activated"))[-1]
    assert activated["emergency_override_id"] == override["id"]
    assert activated["policy_id"] == policy["id"]
    assert activated["client_id"] == client_id and activated["site_id"] == site_id
    assert activated["payload_keys"] == ["script"]
    assert activated["payload_sha256"] == override["payload_sha256"]
    assert "payload" not in activated
    assert "justification" not in activated
    assert activated["justification_bytes"] == len(JUSTIFICATION.encode("utf-8"))
    assert datetime.fromisoformat(activated["expires_at"]) == datetime.fromisoformat(override["expires_at"])
    actions = await audit_actions()
    assert actions.index("emergency_override.activated") < actions.index("emergency_override.notified")
