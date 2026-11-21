# SPDX-License-Identifier: AGPL-3.0-only
"""Request-scoped tenant access (issue #327).

:mod:`app.core.tenant_scope` decides tenancy; this module is how a by-id
handler *applies* it. A handler declares its global role and default client
tier once, in its signature::

    access: TenantAccess = Depends(tenant_access(OperatorRole.operator,
                                                 ClientRole.client_operator))

and then asks for the resource it needs::

    agent = await access.agent(agent_id)

which returns the loaded, authorized row or raises the documented failure:
``404`` if the row is missing or in another tenant (anti-oracle, identical
bodies), ``403`` if visible but under-tier. The resource's owning client is
cached on the access object, and :meth:`TenantAccess.record` writes audit
events with actor, source IP, user agent and that client as
``organization_id`` -- so tenant attribution holds by construction instead of
by each handler's author remembering it.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit, tenant_scope
from app.core.clientip import client_ip, user_agent
from app.core.database import get_db
from app.models.models import (
    Agent,
    Alert,
    AuditEvent,
    Client,
    ClientRole,
    Operator,
    OperatorRole,
    Site,
)

NotFound = str | dict

# Marker for "use the tier the route declared". ``None`` is a real tier value
# meaning "visibility only", so it cannot double as the default.
_ROUTE_TIER = object()
# Marker for "attribute the event to the resolved tenant".
_INFER = object()
# The request authorized resources in two different tenants, so no single
# client can be inferred for its audit events.
_AMBIGUOUS = object()


class TenantAccess:
    """One request's tenant gate, resolved tenant, and audit context."""

    def __init__(
        self,
        *,
        operator: Operator,
        db: AsyncSession,
        request: Request | None,
        tier: ClientRole | None,
    ) -> None:
        self._operator = operator
        self._db = db
        self._request = request
        self._tier = tier
        self._client_id: str | None | object = None

    @property
    def operator(self) -> Operator:
        return self._operator

    @property
    def client_id(self) -> str | None:
        """The client the authorized resource belongs to, once one is loaded.

        ``None`` before any loader succeeds, and when the request authorized
        resources in more than one tenant.
        """
        return None if self._client_id is _AMBIGUOUS else self._client_id

    async def authorize_client(
        self,
        client_id: str | None,
        *,
        tier: ClientRole | None | object = _ROUTE_TIER,
        not_found: NotFound = "Not found",
    ) -> None:
        """Gate on a client id the handler resolved itself.

        ``None`` (a dangling parent) is never visible, so it fails closed as
        ``404`` like a cross-tenant client -- for a platform admin too, whom
        ``assert_client_action`` would otherwise wave through before looking
        at the client.
        """
        if client_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found)
        minimum = self._tier if tier is _ROUTE_TIER else tier
        if minimum is None:
            await tenant_scope.assert_client_visible(
                self._operator, client_id, self._db, detail=not_found
            )
        else:
            await tenant_scope.assert_client_action(
                self._operator, client_id, self._db,
                minimum=minimum, detail=not_found,
            )
        if self._client_id is None:
            self._client_id = client_id
        elif self._client_id != client_id:
            self._client_id = _AMBIGUOUS

    async def _load(self, model, key: str, not_found: NotFound):
        row = await self._db.get(model, key)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found)
        return row

    async def client(
        self,
        client_id: str,
        *,
        tier: ClientRole | None | object = _ROUTE_TIER,
        not_found: NotFound = "Client not found",
    ) -> Client:
        client = await self._load(Client, client_id, not_found)
        await self.authorize_client(client.id, tier=tier, not_found=not_found)
        return client

    async def site(
        self,
        site_id: str,
        *,
        tier: ClientRole | None | object = _ROUTE_TIER,
        not_found: NotFound = "Site not found",
    ) -> Site:
        site = await self._load(Site, site_id, not_found)
        await self.authorize_client(site.client_id, tier=tier, not_found=not_found)
        return site

    async def agent(
        self,
        agent_id: str,
        *,
        tier: ClientRole | None | object = _ROUTE_TIER,
        not_found: NotFound = "Agent not found",
    ) -> Agent:
        agent = await self._load(Agent, agent_id, not_found)
        client_id = await tenant_scope.agent_client_id(agent, self._db)
        await self.authorize_client(client_id, tier=tier, not_found=not_found)
        return agent

    async def alert(
        self,
        alert_id: str,
        *,
        tier: ClientRole | None | object = _ROUTE_TIER,
        not_found: NotFound = "Alert not found",
    ) -> Alert:
        """An alert belongs to its agent's client; an orphaned alert is a 404."""
        alert = await self._load(Alert, alert_id, not_found)
        await self.agent(alert.agent_id, tier=tier, not_found=not_found)
        return alert

    async def record(
        self,
        action: str,
        detail: dict | None = None,
        *,
        agent_id: str | None = None,
        organization_id: str | None | object = _INFER,
        **subjects: str | None,
    ) -> AuditEvent:
        """Append an audit event attributed to this request.

        Actor, actor id, source IP and user agent come from the request; the
        ``organization_id`` is the resolved tenant (``None`` when nothing
        tenant-owned was loaded, e.g. a deployment-wide setting). Pass
        ``organization_id`` explicitly only for the rare request that spans
        two tenants -- inference refuses to pick one. ``subjects`` forwards
        the remaining :func:`app.core.audit.record` subject ids unchanged.
        """
        if organization_id is _INFER:
            if self._client_id is _AMBIGUOUS:
                raise RuntimeError(
                    f"audit '{action}' spans two tenants; pass organization_id"
                )
            organization_id = self._client_id
        request = self._request
        return await audit.record(
            self._db,
            action=action,
            actor=self._operator.email,
            actor_user_id=self._operator.id,
            agent_id=agent_id,
            organization_id=organization_id,
            source_ip=client_ip(request) if request is not None else None,
            user_agent=user_agent(request) if request is not None else None,
            detail=detail,
            **subjects,
        )


_MARKER = "__nodelink_tenant_access__"


def tenant_access(
    minimum: OperatorRole, tier: ClientRole | None = None
) -> Callable[..., Awaitable[TenantAccess]]:
    """Build the dependency for a by-id route.

    ``minimum`` is the global role floor (it replaces ``require_role``, so a
    handler does not declare both); ``tier`` is the route's default client
    role, ``None`` for a read that needs visibility only. Loaders may still
    raise the tier for one call, e.g. ``client_admin`` for revoke.
    """
    role_gate = require_role(minimum)

    async def dependency(
        request: Request,
        operator: Operator = Depends(role_gate),
        db: AsyncSession = Depends(get_db),
    ) -> TenantAccess:
        return TenantAccess(operator=operator, db=db, request=request, tier=tier)

    setattr(dependency, _MARKER, True)
    return dependency


def is_tenant_access_dependency(call: object) -> bool:
    """Whether ``call`` was built by :func:`tenant_access` (route-table guard)."""
    return getattr(call, _MARKER, False) is True
