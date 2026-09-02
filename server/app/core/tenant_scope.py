# SPDX-License-Identifier: AGPL-3.0-only
"""The one place tenancy is decided (issue #66).

A *tenant* is an existing ``Client``. An operator may see and act on a client
only through an :class:`OperatorClientMembership`, or by being a platform admin
-- the single principal that crosses the tenant boundary. Everything else is
**default deny**: a query that forgets to AND in the tenant filter returns
nothing, not everything.

Two failure shapes, deliberately different:

* **Not visible** -> ``404``. A resource in another tenant (or one that does not
  exist) must be indistinguishable, so a foreign tenant cannot be used as an
  existence oracle. This mirrors ``_require_owner`` in
  :mod:`app.api.meshcentral`.
* **Visible but role too low** -> ``403``. Reserved for a resource the operator
  *can* see but whose per-client role does not permit the action.

The client role (``client_readonly`` < ``client_operator`` < ``client_admin``)
mirrors the global ``OperatorRole`` tiers, scoped to one client. It is an
*additional, outer* gate: ``authorize_command`` and ``script_execution_scope``
still narrow command targets *within* a client the operator already belongs to.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import Select, select, true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models.models import (
    Agent,
    ClientRole,
    Operator,
    OperatorClientMembership,
    Site,
)

# Client-role privilege ordering. A higher role satisfies any requirement at or
# below it, exactly like ``_ROLE_RANK`` for the global role in ``deps.py``.
_CLIENT_ROLE_RANK = {
    ClientRole.client_readonly: 0,
    ClientRole.client_operator: 1,
    ClientRole.client_admin: 2,
}


def client_role_permits(role: ClientRole, minimum: ClientRole) -> bool:
    """Whether a membership ``role`` satisfies a required ``minimum`` tier."""
    return _CLIENT_ROLE_RANK[role] >= _CLIENT_ROLE_RANK[minimum]


def _membership_client_ids(operator: Operator) -> Select:
    """Sub-select of the client ids this operator holds a membership for.

    Used as an ``IN`` subquery so the boundary is a single condition AND-ed into
    the caller's query -- no pre-fetch, no round trip, and always consistent
    with the database. With no memberships the set is empty and the outer query
    returns nothing.
    """
    return select(OperatorClientMembership.client_id).where(
        OperatorClientMembership.operator_id == operator.id
    )


def client_id_filter(operator: Operator, column: ColumnElement) -> ColumnElement:
    """Tenant condition to AND into a read whose row exposes a ``client_id``.

    ``column`` is the client-id column of the scoped table (e.g. ``Client.id``,
    ``Site.client_id``). A platform admin's filter is the always-true clause;
    everyone else is restricted to their membership clients.
    """
    if operator.is_platform_admin:
        return true()
    return column.in_(_membership_client_ids(operator))


def agent_client_filter(operator: Operator) -> ColumnElement:
    """:func:`client_id_filter` lifted to ``Agent`` via ``site -> client``.

    AND this into any query selecting agents (or rows keyed by ``agent_id`` that
    join to ``Agent``) so an operator only ever sees agents in their tenants.
    """
    if operator.is_platform_admin:
        return true()
    return Agent.site_id.in_(
        select(Site.id).where(
            Site.client_id.in_(_membership_client_ids(operator))
        )
    )


async def resolve_membership(
    operator: Operator, client_id: str, db: AsyncSession
) -> OperatorClientMembership | None:
    """The operator's membership for ``client_id``, or ``None``.

    Returns ``None`` for a platform admin too -- callers that need admin bypass
    should check :attr:`Operator.is_platform_admin` first (the assert helpers
    below already do).
    """
    return (
        await db.execute(
            select(OperatorClientMembership).where(
                OperatorClientMembership.operator_id == operator.id,
                OperatorClientMembership.client_id == client_id,
            )
        )
    ).scalar_one_or_none()


async def is_client_visible(
    operator: Operator, client_id: str, db: AsyncSession
) -> bool:
    """Whether the operator may see ``client_id`` at all (any membership)."""
    if operator.is_platform_admin:
        return True
    return await resolve_membership(operator, client_id, db) is not None


async def assert_client_visible(
    operator: Operator,
    client_id: str | None,
    db: AsyncSession,
    *,
    detail: str | dict = "Not found",
) -> None:
    """Fail closed with ``404`` unless the operator may see ``client_id``.

    ``detail`` is passed through to the ``HTTPException`` unchanged, so a caller
    whose API contract uses coded errors may hand in ``{"code": ...}`` instead
    of prose.

    Call after resolving a target resource to its client. A cross-tenant client
    id -- or ``None``, which no membership can match -- is indistinguishable
    from a resource that does not exist.
    """
    if client_id is not None and await is_client_visible(operator, client_id, db):
        return
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


async def assert_client_action(
    operator: Operator,
    client_id: str | None,
    db: AsyncSession,
    *,
    minimum: ClientRole,
    detail: str | dict = "Not found",
) -> None:
    """Authorize a mutating/dispatch action against ``client_id``.

    ``404`` if the client is not visible (anti-oracle, same as
    :func:`assert_client_visible`); ``403`` if it is visible but the operator's
    per-client role is below ``minimum``. A platform admin passes both.
    """
    if operator.is_platform_admin:
        return
    membership = (
        await resolve_membership(operator, client_id, db)
        if client_id is not None
        else None
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    if not client_role_permits(membership.role, minimum):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires client role '{minimum.value}' or higher",
        )


async def agent_client_id(agent: Agent, db: AsyncSession) -> str | None:
    """Resolve an agent to its owning client via ``agent.site_id -> site``.

    ``None`` if the site is missing -- treated as invisible by the asserts, so a
    dangling agent fails closed rather than leaking across tenants.
    """
    site = await db.get(Site, agent.site_id)
    return site.client_id if site is not None else None


async def assert_agent_visible(
    operator: Operator,
    agent: Agent,
    db: AsyncSession,
    *,
    minimum: ClientRole | None = None,
    detail: str | dict = "Not found",
) -> None:
    """Tenant gate for an agent-keyed handler after it has loaded the agent.

    With ``minimum=None`` this is a read gate (``404`` if the agent's client is
    not visible). With a ``minimum`` client role it additionally enforces the
    action tier (``403`` if visible but under-privileged).
    """
    client_id = await agent_client_id(agent, db)
    if minimum is None:
        await assert_client_visible(operator, client_id, db, detail=detail)
    else:
        await assert_client_action(
            operator, client_id, db, minimum=minimum, detail=detail
        )
