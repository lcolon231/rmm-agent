# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant retention policy contract and API (issue #88).

Covers inheritance and source reporting, platform floors/ceilings (including a
floor raised after a policy was saved), optimistic-concurrency conflicts,
strict request validation, the authorization matrix (tenant isolation, client
role, global role, step-up), audit evidence, startup validation, and the
evidence-vault default.

Run just this file:  pytest tests/test_retention_policy.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_retention_policy.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
_PW = os.environ.setdefault("NODELINK_TEST_RETENTION_PW", "retention-pw")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import mfa, retention_policy  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    TenantRetentionPolicy,
)

# (email, global role, client role on tenant A, platform admin)
_PEOPLE = {
    "admin": ("ret-admin@nodelink.test", OperatorRole.admin, ClientRole.client_admin, False),
    "reader": ("ret-reader@nodelink.test", OperatorRole.readonly, ClientRole.client_readonly, False),
    "weak_admin": ("ret-weak@nodelink.test", OperatorRole.admin, ClientRole.client_operator, False),
    "elevated_reader": (
        "ret-elev@nodelink.test", OperatorRole.readonly, ClientRole.client_admin, False
    ),
    "outsider": ("ret-out@nodelink.test", OperatorRole.admin, None, False),
    "platform": ("ret-platform@nodelink.test", OperatorRole.admin, None, True),
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def api():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        tenant_a = Client(name="Alpha Retention")
        tenant_b = Client(name="Bravo Retention")
        people = {
            key: Operator(
                email=email,
                password_hash=hash_password(_PW),
                role=role,
                is_platform_admin=platform,
            )
            for key, (email, role, _a, platform) in _PEOPLE.items()
        }
        db.add_all([tenant_a, tenant_b, *people.values()])
        await db.flush()
        for key, (_email, _role, role_a, _platform) in _PEOPLE.items():
            if role_a is not None:
                db.add(OperatorClientMembership(
                    operator_id=people[key].id, client_id=tenant_a.id, role=role_a,
                    granted_by="seed", reason="retention test",
                ))
        await db.commit()
        ids = {"a": tenant_a.id, "b": tenant_b.id}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as client:
        tokens = {}
        for key, (email, *_rest) in _PEOPLE.items():
            login = await client.post("/auth/login", json={"email": email, "password": _PW})
            assert login.status_code == 200, login.text
            tokens[key] = login.json()["access_token"]
        yield client, ids, tokens
    await engine.dispose()


def _url(client_id: str) -> str:
    return f"/clients/{client_id}/retention-policy"


async def _audit(action: str) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        return list((await db.execute(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
        )).scalars())


# --------------------------------------------------------------------------- #
# Resolution (unit)
# --------------------------------------------------------------------------- #
def test_resolve_inherits_platform_defaults_when_no_policy():
    policy = retention_policy.resolve(None, "c1", settings)
    assert policy.version == 0
    for category in retention_policy.CATEGORIES:
        value = policy.values[category.name]
        assert value.source == "default"
        assert value.value == getattr(settings, category.default_attr)
    # The classes #88 introduces are inert (keep forever) by default.
    assert policy.value("command_record_days") == 0
    assert policy.value("alert_days") == 0
    assert policy.value("notification_days") == 0


def test_resolve_override_null_column_inherits():
    row = TenantRetentionPolicy(client_id="c1", telemetry_days=60, version=2, set_by="x")
    policy = retention_policy.resolve(row, "c1", settings)
    assert policy.values["telemetry_days"].source == "tenant"
    assert policy.value("telemetry_days") == 60
    assert policy.values["alert_days"].source == "default"


def test_floor_raised_after_save_clamps_at_enforcement():
    row = TenantRetentionPolicy(client_id="c1", alert_days=40, version=1, set_by="x")
    raised = Settings(retention_min_alert_days=90)
    policy = retention_policy.resolve(row, "c1", raised)
    assert policy.value("alert_days") == 90
    assert policy.values["alert_days"].source == "floor"
    assert policy.values["alert_days"].override == 40


def test_ceiling_lowered_after_save_clamps_and_forever_respects_ceiling():
    row = TenantRetentionPolicy(client_id="c1", telemetry_days=0, alert_days=500,
                                version=1, set_by="x")
    lowered = Settings(retention_max_alert_days=365, retention_max_telemetry_days=400)
    policy = retention_policy.resolve(row, "c1", lowered)
    assert (policy.value("alert_days"), policy.values["alert_days"].source) == (365, "ceiling")
    # 0 (forever) is longer than any finite ceiling.
    assert (policy.value("telemetry_days"), policy.values["telemetry_days"].source) == (
        400, "ceiling"
    )
    unbounded = Settings(retention_max_telemetry_days=0)
    assert retention_policy.resolve(row, "c1", unbounded).value("telemetry_days") == 0


@pytest.mark.parametrize(
    "values, code",
    [
        ({"alert_days": 29}, "retention_below_minimum"),
        ({"telemetry_days": 3651}, "retention_above_maximum"),
        ({"telemetry_days": 0}, "retention_above_maximum"),
        ({"telemetry_days": -1}, "retention_value_invalid"),
        ({"evidence_default_days": 0}, "retention_value_invalid"),
        ({"bogus_days": 10}, "retention_category_unknown"),
    ],
)
def test_validate_update_rejects_out_of_bounds(values, code):
    with pytest.raises(retention_policy.RetentionPolicyError) as exc:
        retention_policy.validate_update(values, settings)
    assert exc.value.code == code
    assert exc.value.status_code == 422


def test_validate_update_boundaries_accepted():
    retention_policy.validate_update(
        {"alert_days": 30, "telemetry_days": 3650, "command_record_days": None}, settings
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"retention_min_alert_days": 100, "retention_max_alert_days": 50},
        {"telemetry_retention_days": 5, "retention_min_telemetry_days": 10},
    ],
)
def test_contradictory_platform_bounds_fail_closed(overrides):
    with pytest.raises(retention_policy.RetentionConfigurationError):
        retention_policy.validate_settings(Settings(**overrides))


def test_default_platform_bounds_are_consistent():
    retention_policy.validate_settings(Settings())


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_get_reports_inherited_policy(api):
    client, ids, tokens = api
    resp = await client.get(_url(ids["a"]), headers=_auth(tokens["reader"]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 0
    assert body["pruning_suspended"] is False
    telemetry = body["categories"]["telemetry_days"]
    assert telemetry["source"] == "default"
    assert telemetry["effective"] == settings.telemetry_retention_days
    assert telemetry["minimum"] == settings.retention_min_telemetry_days
    assert set(body["categories"]) == set(retention_policy.CATEGORY_NAMES)


@pytest.mark.asyncio
async def test_set_then_clear_with_versioning_and_audit(api):
    client, ids, tokens = api
    put = await client.put(
        _url(ids["a"]),
        json={"expected_version": 0, "telemetry_days": 60, "alert_days": 365},
        headers=_auth(tokens["admin"]),
    )
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["version"] == 1
    assert body["set_by"] == _PEOPLE["admin"][0]
    assert body["categories"]["telemetry_days"] == {
        **body["categories"]["telemetry_days"], "effective": 60, "source": "tenant",
        "override": 60,
    }
    assert body["categories"]["command_output_days"]["source"] == "default"

    # A second writer that read version 0 loses: no silent overwrite.
    stale = await client.put(
        _url(ids["a"]), json={"expected_version": 0, "telemetry_days": 7},
        headers=_auth(tokens["admin"]),
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "retention_policy_conflict"

    # Full replacement: omitted categories go back to inheriting.
    put2 = await client.put(
        _url(ids["a"]), json={"expected_version": 1, "telemetry_days": 45},
        headers=_auth(tokens["admin"]),
    )
    assert put2.status_code == 200
    assert put2.json()["version"] == 2
    assert put2.json()["categories"]["alert_days"]["source"] == "default"

    clear = await client.request(
        "DELETE", _url(ids["a"]), json={"expected_version": 2},
        headers=_auth(tokens["admin"]),
    )
    assert clear.status_code == 200, clear.text
    cleared = clear.json()
    assert cleared["version"] == 3  # versions only increase, even across a clear
    assert all(c["source"] == "default" for c in cleared["categories"].values())

    sets = await _audit("tenant.retention_policy_set")
    assert [e.detail["version"] for e in sets] == [1, 2]
    names = sets[0].detail["categories"]
    first = dict(zip(names, sets[0].detail["values"]))
    assert first["telemetry_days"] == 60 and first["alert_days"] == 365
    assert all(v is None for v in sets[0].detail["previous_values"])
    second_prev = dict(zip(names, sets[1].detail["previous_values"]))
    assert second_prev["alert_days"] == 365
    assert all(e.organization_id == ids["a"] for e in sets)
    assert sets[0].actor == _PEOPLE["admin"][0]
    clears = await _audit("tenant.retention_policy_cleared")
    assert len(clears) == 1
    assert dict(zip(names, clears[0].detail["previous_values"]))["telemetry_days"] == 45


@pytest.mark.asyncio
async def test_put_rejects_out_of_bounds_and_unknown_fields(api):
    client, ids, tokens = api
    below = await client.put(
        _url(ids["a"]), json={"expected_version": 0, "alert_days": 1},
        headers=_auth(tokens["admin"]),
    )
    assert below.status_code == 422
    assert below.json()["detail"] == {"code": "retention_below_minimum", "category": "alert_days"}
    above = await client.put(
        _url(ids["a"]), json={"expected_version": 0, "telemetry_days": 99999},
        headers=_auth(tokens["admin"]),
    )
    assert above.status_code == 422
    assert above.json()["detail"]["code"] == "retention_above_maximum"
    unknown = await client.put(
        _url(ids["a"]), json={"expected_version": 0, "audit_days": 1},
        headers=_auth(tokens["admin"]),
    )
    assert unknown.status_code == 422  # extra="forbid": audit is never configurable
    missing_version = await client.put(
        _url(ids["a"]), json={"telemetry_days": 60}, headers=_auth(tokens["admin"])
    )
    assert missing_version.status_code == 422
    # Nothing was written, and no change event was recorded.
    assert await _audit("tenant.retention_policy_set") == []


@pytest.mark.asyncio
async def test_authorization_matrix(api):
    client, ids, tokens = api
    body = {"expected_version": 0, "telemetry_days": 60}
    # Read: any member; a non-member gets 404 (no existence oracle).
    assert (await client.get(_url(ids["a"]), headers=_auth(tokens["reader"]))).status_code == 200
    assert (await client.get(_url(ids["a"]), headers=_auth(tokens["outsider"]))).status_code == 404
    assert (await client.get(_url(ids["b"]), headers=_auth(tokens["admin"]))).status_code == 404
    # Write: global admin AND client_admin.
    assert (await client.put(_url(ids["a"]), json=body,
                             headers=_auth(tokens["reader"]))).status_code == 403
    assert (await client.put(_url(ids["a"]), json=body,
                             headers=_auth(tokens["elevated_reader"]))).status_code == 403
    assert (await client.put(_url(ids["a"]), json=body,
                             headers=_auth(tokens["weak_admin"]))).status_code == 403
    assert (await client.put(_url(ids["b"]), json=body,
                             headers=_auth(tokens["admin"]))).status_code == 404
    assert (await client.put(_url(ids["b"]), json=body,
                             headers=_auth(tokens["outsider"]))).status_code == 404
    assert (await client.request("DELETE", _url(ids["b"]), json={"expected_version": 1},
                                 headers=_auth(tokens["admin"]))).status_code == 404
    # A platform admin crosses tenants, but an unknown client is still 404.
    platform = await client.put(_url(ids["b"]), json=body, headers=_auth(tokens["platform"]))
    assert platform.status_code == 200, platform.text
    assert (await client.get(_url("no-such-client"),
                             headers=_auth(tokens["platform"]))).status_code == 404
    assert (await client.put(_url("no-such-client"), json=body,
                             headers=_auth(tokens["platform"]))).status_code == 404
    # Tenant A was never modified by any of the refused calls.
    async with AsyncSessionLocal() as db:
        assert await db.get(TenantRetentionPolicy, ids["a"]) is None
    # Unauthenticated.
    assert (await client.get(_url(ids["a"]))).status_code == 401


@pytest.mark.asyncio
async def test_change_requires_fresh_step_up_when_enrolled(api, monkeypatch):
    client, ids, tokens = api

    async def enrolled(_db, _operator_id):
        return True

    monkeypatch.setattr(mfa, "has_active_credential", enrolled)
    monkeypatch.setattr(mfa, "enforcement_mode", lambda: "required")
    resp = await client.put(
        _url(ids["a"]), json={"expected_version": 0, "telemetry_days": 60},
        headers=_auth(tokens["admin"]),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "step_up_required"
    async with AsyncSessionLocal() as db:
        assert await db.get(TenantRetentionPolicy, ids["a"]) is None


@pytest.mark.asyncio
async def test_clear_without_policy_is_404(api):
    client, ids, tokens = api
    resp = await client.request(
        "DELETE", _url(ids["a"]), json={"expected_version": 1}, headers=_auth(tokens["admin"])
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "retention_policy_not_found"


@pytest.mark.asyncio
async def test_storage_status_counts_overriding_tenants(api):
    client, ids, tokens = api
    await client.put(_url(ids["a"]), json={"expected_version": 0, "alert_days": 90},
                     headers=_auth(tokens["admin"]))
    status = await client.get("/storage/status", headers=_auth(tokens["admin"]))
    assert status.status_code == 200, status.text
    policy = status.json()["retention_policy"]
    assert policy["tenant_policies_overridden"] == 1
    assert policy["alert_retention_days"] == 0
