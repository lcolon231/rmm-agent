# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for ``app.core.tenant_scope`` (issue #285).

The tenant boundary (#66) is otherwise only exercised through HTTP. These tests
call the helpers directly: the filter builders are compiled to SQL and the
WHERE clause asserted, and the async gates run against a tiny in-memory fake
session so every branch is reachable without a database.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_tenant_scope.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from app.core import tenant_scope  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
)

ROLES = [ClientRole.client_readonly, ClientRole.client_operator, ClientRole.client_admin]


def _sql(expr) -> str:
    return " ".join(
        str(expr.compile(compile_kwargs={"literal_binds": True})).split()
    )


def _operator(*, platform_admin: bool = False, op_id: str = "op-1") -> Operator:
    return Operator(
        id=op_id,
        email=f"{op_id}@nodelink.test",
        password_hash="x",
        role=OperatorRole.operator,
        is_platform_admin=platform_admin,
    )


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeSession:
    """Just enough of ``AsyncSession`` for the tenant helpers.

    ``memberships`` maps ``(operator_id, client_id)`` to a role; ``sites`` maps a
    site id to its client id. ``execute`` answers the single membership lookup
    the module issues by reading the bound parameters of the compiled query.
    """

    def __init__(self, memberships=None, sites=None):
        self.memberships = memberships or {}
        self.sites = sites or {}
        self.executed = 0

    async def execute(self, statement):
        self.executed += 1
        params = statement.compile().params
        operator_id = next(v for k, v in params.items() if k.startswith("operator_id"))
        client_id = next(v for k, v in params.items() if k.startswith("client_id"))
        role = self.memberships.get((operator_id, client_id))
        if role is None:
            return _Result(None)
        return _Result(
            OperatorClientMembership(
                operator_id=operator_id, client_id=client_id, role=role
            )
        )

    async def get(self, model, key):
        assert model is Site
        client_id = self.sites.get(key)
        if client_id is None:
            return None
        return Site(id=key, client_id=client_id, name=f"site-{key}")


# --------------------------------------------------------------------------- #
# client_role_permits
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("held", ROLES)
@pytest.mark.parametrize("minimum", ROLES)
def test_client_role_permits_is_rank_ordered(held, minimum):
    assert tenant_scope.client_role_permits(held, minimum) is (
        ROLES.index(held) >= ROLES.index(minimum)
    )


def test_client_role_rank_covers_every_role():
    # A new ClientRole without a rank would KeyError at authorization time.
    assert set(tenant_scope._CLIENT_ROLE_RANK) == set(ClientRole)


# --------------------------------------------------------------------------- #
# Filter builders: compile and assert the WHERE clause
# --------------------------------------------------------------------------- #
def test_client_id_filter_platform_admin_is_match_all():
    assert _sql(tenant_scope.client_id_filter(_operator(platform_admin=True), Client.id)) == "true"


def test_client_id_filter_restricts_to_membership_subquery():
    sql = _sql(tenant_scope.client_id_filter(_operator(op_id="op-42"), Site.client_id))
    assert sql == (
        "sites.client_id IN (SELECT operator_client_memberships.client_id "
        "FROM operator_client_memberships "
        "WHERE operator_client_memberships.operator_id = 'op-42')"
    )


def test_agent_client_filter_platform_admin_is_match_all():
    assert _sql(tenant_scope.agent_client_filter(_operator(platform_admin=True))) == "true"


def test_agent_client_filter_lifts_through_site_to_client():
    sql = _sql(tenant_scope.agent_client_filter(_operator(op_id="op-7")))
    assert sql == (
        "agents.site_id IN (SELECT sites.id FROM sites "
        "WHERE sites.client_id IN (SELECT operator_client_memberships.client_id "
        "FROM operator_client_memberships "
        "WHERE operator_client_memberships.operator_id = 'op-7'))"
    )


def test_non_admin_filters_never_compile_to_match_all():
    operator = _operator()
    for expr in (
        tenant_scope.client_id_filter(operator, Client.id),
        tenant_scope.agent_client_filter(operator),
    ):
        sql = _sql(expr)
        assert sql not in {"true", "1", "1 = 1"}
        assert "operator_client_memberships.operator_id = 'op-1'" in sql


# --------------------------------------------------------------------------- #
# Membership resolution and visibility
# --------------------------------------------------------------------------- #
async def test_resolve_membership_returns_row_or_none():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_operator})
    operator = _operator()
    found = await tenant_scope.resolve_membership(operator, "c-1", db)
    assert found is not None and found.role == ClientRole.client_operator
    assert await tenant_scope.resolve_membership(operator, "c-2", db) is None


async def test_is_client_visible_admin_bypasses_lookup():
    db = FakeSession()
    assert await tenant_scope.is_client_visible(_operator(platform_admin=True), "c-x", db)
    assert db.executed == 0


async def test_is_client_visible_requires_membership():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_readonly})
    operator = _operator()
    assert await tenant_scope.is_client_visible(operator, "c-1", db) is True
    assert await tenant_scope.is_client_visible(operator, "c-2", db) is False


async def test_assert_client_visible_passes_for_member():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_readonly})
    await tenant_scope.assert_client_visible(_operator(), "c-1", db)


@pytest.mark.parametrize("client_id", ["foreign", None])
async def test_assert_client_visible_404s_foreign_or_missing_client(client_id):
    db = FakeSession({("op-1", "c-1"): ClientRole.client_admin})
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_visible(_operator(), client_id, db)
    assert caught.value.status_code == 404
    assert caught.value.detail == "Not found"


async def test_assert_client_visible_none_client_404s_even_for_platform_admin():
    # None names no client; there is nothing for an admin to see either.
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_visible(
            _operator(platform_admin=True), None, FakeSession()
        )
    assert caught.value.status_code == 404


async def test_assert_client_visible_passes_coded_detail_through():
    detail = {"code": "agent_not_found"}
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_visible(
            _operator(), "c-9", FakeSession(), detail=detail
        )
    assert caught.value.detail == detail


# --------------------------------------------------------------------------- #
# assert_client_action: 404 (not visible) vs 403 (visible, role too low)
# --------------------------------------------------------------------------- #
async def test_assert_client_action_platform_admin_passes_without_lookup():
    db = FakeSession()
    await tenant_scope.assert_client_action(
        _operator(platform_admin=True), None, db, minimum=ClientRole.client_admin
    )
    assert db.executed == 0


@pytest.mark.parametrize("held", ROLES)
@pytest.mark.parametrize("minimum", ROLES)
async def test_assert_client_action_role_matrix(held, minimum):
    db = FakeSession({("op-1", "c-1"): held})
    if ROLES.index(held) >= ROLES.index(minimum):
        await tenant_scope.assert_client_action(_operator(), "c-1", db, minimum=minimum)
        return
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_action(_operator(), "c-1", db, minimum=minimum)
    assert caught.value.status_code == 403
    assert caught.value.detail == f"Requires client role '{minimum.value}' or higher"


async def test_assert_client_action_foreign_client_is_404_not_403():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_admin})
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_action(
            _operator(), "c-2", db, minimum=ClientRole.client_readonly,
            detail={"code": "x"},
        )
    assert caught.value.status_code == 404
    assert caught.value.detail == {"code": "x"}


async def test_assert_client_action_none_client_is_404_without_lookup():
    db = FakeSession()
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_client_action(
            _operator(), None, db, minimum=ClientRole.client_readonly
        )
    assert caught.value.status_code == 404
    assert db.executed == 0


# --------------------------------------------------------------------------- #
# Agent gates, including the orphan-agent default deny
# --------------------------------------------------------------------------- #
def _agent(site_id: str = "s-1") -> Agent:
    return Agent(id="a-1", site_id=site_id, token_hash="h")


async def test_agent_client_id_resolves_through_site():
    db = FakeSession(sites={"s-1": "c-1"})
    assert await tenant_scope.agent_client_id(_agent(), db) == "c-1"
    assert await tenant_scope.agent_client_id(_agent("s-missing"), db) is None


async def test_assert_agent_visible_read_gate():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_readonly}, {"s-1": "c-1", "s-2": "c-2"})
    await tenant_scope.assert_agent_visible(_operator(), _agent("s-1"), db)
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_agent_visible(_operator(), _agent("s-2"), db)
    assert caught.value.status_code == 404


async def test_assert_agent_visible_action_gate():
    db = FakeSession({("op-1", "c-1"): ClientRole.client_readonly}, {"s-1": "c-1"})
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_agent_visible(
            _operator(), _agent(), db, minimum=ClientRole.client_operator
        )
    assert caught.value.status_code == 403
    await tenant_scope.assert_agent_visible(
        _operator(), _agent(), db, minimum=ClientRole.client_readonly
    )


@pytest.mark.parametrize("minimum", [None, ClientRole.client_readonly])
async def test_orphan_agent_is_404_never_a_match_all(minimum):
    """An agent whose site (and so client) is gone resolves to no client.

    That must fail closed as 404 -- not be treated as "no restriction" -- even
    for an operator who holds memberships elsewhere.
    """
    db = FakeSession({("op-1", "c-1"): ClientRole.client_admin}, sites={})
    with pytest.raises(HTTPException) as caught:
        await tenant_scope.assert_agent_visible(
            _operator(), _agent("s-orphan"), db, minimum=minimum
        )
    assert caught.value.status_code == 404
    # No membership query was issued against a None client id.
    assert db.executed == 0
