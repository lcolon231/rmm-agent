# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped API tokens for the versioned public API (issue #72).

A token is an opaque bearer, ``nlk_<secret>``, stored only as its SHA-256. It
authenticates *as its owning operator*, but always as a narrowed principal:

* **One tenant.** The principal sees only the token's client, even when the
  owner is a member of more, and never crosses the tenant boundary even when
  the owner is a platform admin.
* **Role ceilings.** The global role and the per-client role are each capped
  at the token's ceiling; the token can never exceed its owner.
* **Public routes only.** A token is refused (``401``) on any route outside
  :mod:`app.core.public_api`, so a token can never reach operator, session,
  MFA, membership, or token management.
* **Bounded lifetime.** Expiry is mandatory. Revocation, the owner's
  ``token_generation`` (logout-all, membership grant/revoke, disable), and
  losing the bound membership each end it on the next request.

The narrowed principal is a *transient* copy of the ``Operator`` row, never the
persistent instance: the capped role and cleared platform-admin flag exist
only in memory, and a transient object accidentally attached to the session
fails closed (an INSERT conflict) instead of writing the caps back.
"""
from __future__ import annotations

import contextvars
import math
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import public_api
from app.core.config import settings
from app.core.ratelimit import LoginRateLimiter
from app.core.security import hash_token
from app.models.models import (
    ApiToken,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
)

TOKEN_PREFIX = "nlk_"
_SECRET_BYTES = 32
_LAST_USED_RESOLUTION = timedelta(minutes=1)

_ROLE_RANK = {
    OperatorRole.readonly: 0,
    OperatorRole.operator: 1,
    OperatorRole.admin: 2,
}
_CLIENT_ROLE_RANK = {
    ClientRole.client_readonly: 0,
    ClientRole.client_operator: 1,
    ClientRole.client_admin: 2,
}

#: The API token behind the current request, for audit attribution. Set by
#: authentication, read by :func:`app.core.audit.record`.
current_token_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "nodelink_api_token_id", default=None
)

# Per-token request budgets (sliding 60 s window, per process -- the same
# honesty caveat as the login limiter: move to a shared store before scaling
# out).
request_limiter = LoginRateLimiter(
    max_failures=settings.public_api_rate_limit_per_minute, window_seconds=60
)
mutating_limiter = LoginRateLimiter(
    max_failures=settings.public_api_mutating_rate_limit_per_minute, window_seconds=60
)

_UNAUTHORIZED = "Invalid or expired token"


def is_api_token(bearer: str) -> bool:
    return bearer.startswith(TOKEN_PREFIX)


@dataclass(frozen=True)
class MintedToken:
    token: ApiToken
    plaintext: str


def mint(
    *,
    operator: Operator,
    client_id: str,
    name: str,
    role_ceiling: OperatorRole,
    client_role_ceiling: ClientRole,
    expires_at: datetime,
    now: datetime,
) -> MintedToken:
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(_SECRET_BYTES)
    token = ApiToken(
        operator_id=operator.id,
        client_id=client_id,
        name=name,
        prefix=plaintext[: len(TOKEN_PREFIX) + 6],
        token_hash=hash_token(plaintext),
        role_ceiling=role_ceiling.value,
        client_role_ceiling=client_role_ceiling.value,
        operator_token_generation=operator.token_generation,
        created_at=now,
        expires_at=expires_at,
    )
    return MintedToken(token=token, plaintext=plaintext)


def min_role(a: OperatorRole, b: OperatorRole) -> OperatorRole:
    return a if _ROLE_RANK[a] <= _ROLE_RANK[b] else b


def min_client_role(a: ClientRole, b: ClientRole) -> ClientRole:
    return a if _CLIENT_ROLE_RANK[a] <= _CLIENT_ROLE_RANK[b] else b


def role_exceeds(role: OperatorRole, ceiling: OperatorRole) -> bool:
    return _ROLE_RANK[role] > _ROLE_RANK[ceiling]


def client_role_exceeds(role: ClientRole, ceiling: ClientRole) -> bool:
    return _CLIENT_ROLE_RANK[role] > _CLIENT_ROLE_RANK[ceiling]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def is_active(token: ApiToken, now: datetime) -> bool:
    return token.revoked_at is None and _as_utc(token.expires_at) > now


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_UNAUTHORIZED)


def _narrowed_principal(operator: Operator, token: ApiToken) -> Operator:
    """A transient, capped copy of ``operator`` for this request only."""
    values = {
        attr.key: getattr(operator, attr.key)
        for attr in sa_inspect(Operator).column_attrs
    }
    values["role"] = min_role(operator.role, OperatorRole(token.role_ceiling))
    values["is_platform_admin"] = False
    principal = Operator(**values)
    # Transient markers, read by deps.py and tenant_scope.py.
    principal.api_token = token
    principal.api_token_client_id = token.client_id
    principal.api_token_client_role = ClientRole(token.client_role_ceiling)
    # A platform-admin owner reaches the bound client without a membership;
    # the token is still confined to that one client.
    principal.api_token_owner_platform_admin = bool(operator.is_platform_admin)
    principal.session_amr = frozenset()
    principal.session_step_up_at = None
    principal.session_record = None
    return principal


def _rate_limit(token: ApiToken, *, mutating: bool) -> None:
    for limiter, applies in ((request_limiter, True), (mutating_limiter, mutating)):
        if not applies:
            continue
        retry_after = limiter.retry_after(token.id)
        if retry_after is not None:
            seconds = max(1, math.ceil(retry_after))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "rate_limited",
                    "message": "API token request budget exhausted; retry later.",
                },
                headers={
                    "Retry-After": str(seconds),
                    "RateLimit-Limit": str(limiter.max_failures),
                    "RateLimit-Remaining": "0",
                    "RateLimit-Reset": str(seconds),
                },
            )
    for limiter, applies in ((request_limiter, True), (mutating_limiter, mutating)):
        if applies:
            limiter.record_failure(token.id)


async def authenticate(
    db: AsyncSession,
    bearer: str,
    *,
    method: str,
    route_path: str | None,
) -> Operator:
    """Resolve an ``nlk_`` bearer to its narrowed principal, or fail closed.

    Every refusal is the same opaque ``401`` so a caller cannot tell an
    unknown token from a revoked, expired, orphaned, or out-of-scope one.
    """
    token = (
        await db.execute(select(ApiToken).where(ApiToken.token_hash == hash_token(bearer)))
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if token is None or not is_active(token, now):
        raise _unauthorized()
    route = public_api.lookup(method, route_path)
    if route is None:
        raise _unauthorized()
    operator = await db.get(Operator, token.operator_id)
    if (
        operator is None
        or operator.disabled
        or operator.token_generation != token.operator_token_generation
    ):
        raise _unauthorized()
    membership = (
        await db.execute(
            select(OperatorClientMembership).where(
                OperatorClientMembership.operator_id == operator.id,
                OperatorClientMembership.client_id == token.client_id,
            )
        )
    ).scalar_one_or_none()
    # A platform admin may mint a token for any client; everyone else must
    # still hold the membership the token was bound to.
    if membership is None and not operator.is_platform_admin:
        raise _unauthorized()

    _rate_limit(token, mutating=route.mutating)

    last_used = _as_utc(token.last_used_at)
    if last_used is None or now - last_used >= _LAST_USED_RESOLUTION:
        token.last_used_at = now
    current_token_id.set(token.id)
    return _narrowed_principal(operator, token)


def token_principal(operator: Operator) -> ApiToken | None:
    """The API token behind a principal, or ``None`` for a JWT session."""
    return getattr(operator, "api_token", None)
