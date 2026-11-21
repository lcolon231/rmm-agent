# SPDX-License-Identifier: AGPL-3.0-only
"""The request-scoped tenant access module (issue #327), tested directly.

Each case drives :class:`app.api.tenant_access.TenantAccess` on a real SQLite
session -- no HTTP -- and observes only its interface: which status a
principal gets for a resource, which row comes back, and which audit row is
written with which ``organization_id``.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_tenant_access.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from dataclasses import dataclass  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy import select  # noqa: E402
from starlette.requests import Request  # noqa: E402

from app.api.tenant_access import TenantAccess  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    Alert,
    AlertState,
    AuditEvent,
    CheckResultStatus,
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
)


@dataclass
class World:
    db: object
    client_a: Client
    client_b: Client
    site_a: Site
    agent_a: Agent
    alert_a: Alert
    dangling_agent: Agent


def _request(*, user_agent: str | None = "pytest-ua", ip: str = "203.0.113.7") -> Request:
    headers = [] if user_agent is None else [(b"user-agent", user_agent.encode())]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": headers,
            "client": (ip, 5555),
        }
    )


@pytest_asyncio.fixture
async def world():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        client_a = Client(name="Alpha")
        client_b = Client(name="Bravo")
        db.add_all([client_a, client_b])
        await db.flush()
        site_a = Site(client_id=client_a.id, name="A-HQ")
        db.add(site_a)
        await db.flush()
        agent_a = Agent(site_id=site_a.id, token_hash="a", hostname="A-1", os="windows")
        dangling = Agent(site_id="no-such-site", token_hash="d", hostname="D-1", os="windows")
        db.add_all([agent_a, dangling])
        await db.flush()
        alert_a = Alert(
            agent_id=agent_a.id, policy_id="policy-1", policy_revision_id="rev-1",
            check_key="cpu", state=AlertState.open,
            last_result_status=CheckResultStatus.critical,
        )
        db.add(alert_a)
        await db.flush()
        yield World(db, client_a, client_b, site_a, agent_a, alert_a, dangling)
    await engine.dispose()


async def _operator(db, *, role: ClientRole | None = None, client: Client | None = None,
                    platform_admin: bool = False) -> Operator:
    operator = Operator(
        email=f"op-{id(object())}@nodelink.test",
        password_hash="x",
        role=OperatorRole.admin,
        is_platform_admin=platform_admin,
    )
    db.add(operator)
    await db.flush()
    if role is not None:
        db.add(OperatorClientMembership(
            operator_id=operator.id, client_id=client.id, role=role,
            granted_by="test", reason="test",
        ))
        await db.flush()
    return operator


def _access(world: World, operator: Operator, *, tier: ClientRole | None = None,
            request: Request | None = None) -> TenantAccess:
    return TenantAccess(
        operator=operator, db=world.db, request=request or _request(), tier=tier
    )


async def _status(awaitable) -> int:
    try:
        await awaitable
    except HTTPException as exc:
        return exc.status_code
    return 200


# --------------------------------------------------------------------------- #
# Agent loader
# --------------------------------------------------------------------------- #
async def test_agent_without_membership_is_404(world):
    operator = await _operator(world.db)
    access = _access(world, operator)
    with pytest.raises(HTTPException) as exc:
        await access.agent(world.agent_a.id)
    assert exc.value.status_code == 404
    assert exc.value.detail == "Agent not found"


_R, _O, _A = ClientRole.client_readonly, ClientRole.client_operator, ClientRole.client_admin


@pytest.mark.parametrize(
    ("held", "tier", "expected"),
    [
        (_R, None, 200), (_R, _O, 403), (_R, _A, 403),
        (_O, None, 200), (_O, _O, 200), (_O, _A, 403),
        (_A, None, 200), (_A, _O, 200), (_A, _A, 200),
    ],
)
async def test_agent_tier_matrix(world, held, tier, expected):
    operator = await _operator(world.db, role=held, client=world.client_a)
    access = _access(world, operator, tier=tier)
    assert await _status(access.agent(world.agent_a.id)) == expected


async def test_agent_returns_the_loaded_row(world):
    operator = await _operator(world.db, role=_R, client=world.client_a)
    agent = await _access(world, operator).agent(world.agent_a.id)
    assert agent.id == world.agent_a.id


async def test_membership_in_another_client_is_404_not_403(world):
    operator = await _operator(world.db, role=_A, client=world.client_b)
    assert await _status(_access(world, operator, tier=_O).agent(world.agent_a.id)) == 404


async def test_platform_admin_passes_every_tier(world):
    operator = await _operator(world.db, platform_admin=True)
    assert await _status(_access(world, operator, tier=_A).agent(world.agent_a.id)) == 200


async def test_override_tier_beats_route_tier(world):
    # client_operator may quarantine (route tier) but not revoke (override).
    operator = await _operator(world.db, role=_O, client=world.client_a)
    access = _access(world, operator, tier=_O)
    assert await _status(access.agent(world.agent_a.id)) == 200
    assert await _status(access.agent(world.agent_a.id, tier=_A)) == 403


async def test_missing_and_foreign_agents_have_identical_404s(world):
    operator = await _operator(world.db, role=_A, client=world.client_b)
    access = _access(world, operator)
    with pytest.raises(HTTPException) as missing:
        await access.agent("no-such-agent")
    with pytest.raises(HTTPException) as foreign:
        await access.agent(world.agent_a.id)
    assert (missing.value.status_code, missing.value.detail) == (
        foreign.value.status_code, foreign.value.detail,
    ) == (404, "Agent not found")


@pytest.mark.parametrize("tier", [None, _O, _A])
async def test_agent_with_dangling_site_is_404_even_for_platform_admin(world, tier):
    operator = await _operator(world.db, platform_admin=True)
    access = _access(world, operator, tier=tier)
    assert await _status(access.agent(world.dangling_agent.id)) == 404


async def test_coded_not_found_detail_is_preserved(world):
    operator = await _operator(world.db)
    with pytest.raises(HTTPException) as exc:
        await _access(world, operator).agent(
            world.agent_a.id, not_found={"code": "agent_not_found"}
        )
    assert exc.value.detail == {"code": "agent_not_found"}


async def test_api_token_principal_is_confined_and_capped(world):
    """A token (#72) for client A, capped at client_readonly, owned by an admin."""
    operator = await _operator(world.db, role=_A, client=world.client_a)
    operator.api_token_client_id = world.client_a.id
    operator.api_token_client_role = _R
    operator.api_token_owner_platform_admin = False
    assert await _status(_access(world, operator).agent(world.agent_a.id)) == 200
    assert await _status(_access(world, operator, tier=_O).agent(world.agent_a.id)) == 403

    other_site = Site(client_id=world.client_b.id, name="B-HQ")
    world.db.add(other_site)
    await world.db.flush()
    other = Agent(site_id=other_site.id, token_hash="b", hostname="B-1", os="windows")
    world.db.add(other)
    await world.db.flush()
    world.db.add(OperatorClientMembership(
        operator_id=operator.id, client_id=world.client_b.id, role=_A,
        granted_by="test", reason="test",
    ))
    await world.db.flush()
    # A membership in B does not help: the token is bound to A.
    assert await _status(_access(world, operator).agent(other.id)) == 404


# --------------------------------------------------------------------------- #
# Resolved tenant
# --------------------------------------------------------------------------- #
async def test_resolved_client_is_none_before_any_loader(world):
    operator = await _operator(world.db, platform_admin=True)
    assert _access(world, operator).client_id is None


async def test_loader_caches_the_resolved_client(world):
    operator = await _operator(world.db, role=_R, client=world.client_a)
    access = _access(world, operator)
    await access.agent(world.agent_a.id)
    assert access.client_id == world.client_a.id


async def test_denied_loader_resolves_no_client(world):
    operator = await _operator(world.db)
    access = _access(world, operator)
    await _status(access.agent(world.agent_a.id))
    assert access.client_id is None


# --------------------------------------------------------------------------- #
# Client, site and alert loaders
# --------------------------------------------------------------------------- #
async def test_client_loader_gates_and_resolves(world):
    operator = await _operator(world.db, role=_R, client=world.client_a)
    access = _access(world, operator, tier=None)
    assert (await access.client(world.client_a.id)).id == world.client_a.id
    assert access.client_id == world.client_a.id
    with pytest.raises(HTTPException) as exc:
        await access.client(world.client_b.id)
    assert (exc.value.status_code, exc.value.detail) == (404, "Client not found")
    assert await _status(access.client(world.client_a.id, tier=_O)) == 403
    assert await _status(access.client("no-such-client")) == 404


async def test_site_loader_gates_and_resolves(world):
    operator = await _operator(world.db, role=_O, client=world.client_a)
    access = _access(world, operator, tier=_O)
    assert (await access.site(world.site_a.id)).id == world.site_a.id
    assert access.client_id == world.client_a.id
    assert await _status(access.site(world.site_a.id, tier=_A)) == 403
    with pytest.raises(HTTPException) as exc:
        await access.site("no-such-site")
    assert (exc.value.status_code, exc.value.detail) == (404, "Site not found")


async def test_alert_loader_resolves_through_its_agent(world):
    operator = await _operator(world.db, role=_R, client=world.client_a)
    access = _access(world, operator)
    assert (await access.alert(world.alert_a.id)).id == world.alert_a.id
    assert access.client_id == world.client_a.id
    assert await _status(access.alert(world.alert_a.id, tier=_O)) == 403


async def test_alert_loader_is_404_for_foreign_missing_or_orphaned(world):
    stranger = await _operator(world.db, role=_A, client=world.client_b)
    with pytest.raises(HTTPException) as exc:
        await _access(world, stranger).alert(world.alert_a.id)
    assert (exc.value.status_code, exc.value.detail) == (404, "Alert not found")
    assert await _status(_access(world, stranger).alert("no-such-alert")) == 404

    admin = await _operator(world.db, platform_admin=True)
    orphan = Alert(
        agent_id="no-such-agent", policy_id="policy-1", policy_revision_id="rev-1",
        check_key="disk", state=AlertState.open,
        last_result_status=CheckResultStatus.critical,
    )
    world.db.add(orphan)
    await world.db.flush()
    assert await _status(_access(world, admin).alert(orphan.id)) == 404


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
_DETAIL = {"previous_trust_state": "active", "trust_state": "quarantined", "reason": "r"}


async def test_record_fills_request_context_and_inferred_tenant(world):
    operator = await _operator(world.db, role=_O, client=world.client_a)
    access = _access(world, operator, tier=_O)
    agent = await access.agent(world.agent_a.id)
    event = await access.record("agent.quarantined", _DETAIL, agent_id=agent.id)

    stored = await world.db.scalar(select(AuditEvent).where(AuditEvent.id == event.id))
    assert stored.action == "agent.quarantined"
    assert stored.actor == operator.email
    assert stored.actor_user_id == operator.id
    assert stored.agent_id == world.agent_a.id
    assert stored.source_ip == "203.0.113.7"
    assert stored.user_agent == "pytest-ua"
    assert stored.organization_id == world.client_a.id
    # The detail still passes the central redaction policy: free text is digested.
    assert stored.detail["trust_state"] == "quarantined"
    assert "reason" not in stored.detail and stored.detail["reason_bytes"] == 1


async def test_record_truncates_user_agent_and_drops_an_empty_one(world):
    operator = await _operator(world.db, platform_admin=True)
    long_ua = _access(world, operator, request=_request(user_agent="x" * 900))
    no_ua = _access(world, operator, request=_request(user_agent=None))
    assert (await long_ua.record("agent.quarantined", _DETAIL)).user_agent == "x" * 500
    assert (await no_ua.record("agent.quarantined", _DETAIL)).user_agent is None


async def test_record_without_a_resolved_tenant_has_no_organization(world):
    operator = await _operator(world.db, platform_admin=True)
    event = await _access(world, operator).record("agent.quarantined", _DETAIL)
    assert event.organization_id is None


async def test_record_explicit_organization_overrides_inference(world):
    operator = await _operator(world.db, platform_admin=True)
    access = _access(world, operator)
    await access.agent(world.agent_a.id)
    event = await access.record(
        "agent.quarantined", _DETAIL, organization_id=world.client_b.id
    )
    assert event.organization_id == world.client_b.id
    explicit_none = await access.record(
        "agent.quarantined", _DETAIL, organization_id=None
    )
    assert explicit_none.organization_id is None


async def test_two_tenants_in_one_request_require_an_explicit_organization(world):
    """Inference never guesses between tenants (e.g. moving a site)."""
    operator = await _operator(world.db, platform_admin=True)
    access = _access(world, operator)
    await access.agent(world.agent_a.id)
    await access.client(world.client_b.id)
    assert access.client_id is None
    with pytest.raises(RuntimeError):
        await access.record("agent.quarantined", _DETAIL)
    event = await access.record(
        "agent.quarantined", _DETAIL, organization_id=world.client_a.id
    )
    assert event.organization_id == world.client_a.id


async def test_same_tenant_twice_stays_resolved(world):
    operator = await _operator(world.db, platform_admin=True)
    access = _access(world, operator)
    await access.agent(world.agent_a.id)
    await access.site(world.site_a.id)
    assert access.client_id == world.client_a.id
