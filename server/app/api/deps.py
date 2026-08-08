# SPDX-License-Identifier: AGPL-3.0-only
"""Shared API dependencies."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token, hash_token
from app.models.models import Agent, AgentTrustState, Operator, OperatorRole


def _as_utc(value: datetime | None) -> datetime | None:
    """Read a stored timestamp as timezone-aware UTC (SQLite returns naive)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def get_current_agent(
    authorization: str | None = Header(default=None, description="Bearer <agent_token>"),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """Resolve the agent from its bearer token.

    We look the agent up by the *hash* of the presented token — the plaintext
    never touches the database. A credential is accepted on either of two slots
    (issue #125): the current token until ``credential_expires_at``, or the
    just-superseded token during its bounded rotation overlap
    (``previous_token_expires_at``). The overlap slot is what makes renewal
    loss-safe — a dropped renewal response leaves the agent still authenticated
    on the old credential so it can simply retry.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )

    presented = hash_token(token)
    result = await db.execute(
        select(Agent).where(
            or_(
                Agent.token_hash == presented,
                Agent.previous_token_hash == presented,
            )
        )
    )
    agent = result.scalar_one_or_none()

    # Decide validity in a single constant-shaped path: an unknown token, a
    # revoked identity, an expired current credential, and a lapsed overlap
    # credential all yield the same 401 — no oracle for a stolen credential to
    # learn *why* it was refused. ``credential_matched`` is a transient marker
    # (never persisted) the renewal handler reads to keep the overlap loss-safe.
    now = datetime.now(timezone.utc)
    matched: str | None = None
    if agent is not None and agent.trust_state != AgentTrustState.revoked:
        if agent.token_hash == presented:
            expires_at = _as_utc(agent.credential_expires_at)
            if expires_at is None or expires_at > now:
                matched = "current"
        elif agent.previous_token_hash == presented:
            overlap_until = _as_utc(agent.previous_token_expires_at)
            if overlap_until is not None and overlap_until > now:
                matched = "overlap"

    if agent is None or matched is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token"
        )
    agent.credential_matched = matched
    return agent


# --------------------------------------------------------------------------- #
# Operator authentication (authN) and authorization (authZ)
# --------------------------------------------------------------------------- #
async def get_current_operator(
    authorization: str | None = Header(default=None, description="Bearer <operator_jwt>"),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """AuthN: resolve the operator from a JWT bearer token.

    This proves *who* the caller is. It does not decide what they may do — that
    is authorization, handled by require_role below.

    The header is declared Optional so that a *missing* token produces a 401
    (an auth failure we raise) rather than FastAPI's 422 request-validation
    error. A missing credential is "unauthenticated", not "malformed request".
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )

    claims = decode_access_token(token)  # None if signature/exp invalid
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    operator = await db.get(Operator, claims.get("sub"))
    if operator is None or operator.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Operator not found or disabled"
        )
    # A token minted under an older generation has been revoked (logout-all /
    # suspected leak). Same detail as other token failures — no oracle.
    if claims.get("gen", 0) != operator.token_generation:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    return operator


# Privilege ordering: a higher role satisfies any requirement at or below it.
_ROLE_RANK = {
    OperatorRole.readonly: 0,
    OperatorRole.operator: 1,
    OperatorRole.admin: 2,
}


def require_role(minimum: OperatorRole):
    """AuthZ: build a dependency that requires at least `minimum` privilege.

    Usage:  Depends(require_role(OperatorRole.operator))

    Returns the operator so handlers can record who acted. Note this depends on
    get_current_operator, so authN always runs first: identity, then permission.
    """
    async def checker(
        operator: Operator = Depends(get_current_operator),
    ) -> Operator:
        if _ROLE_RANK[operator.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum.value}' or higher",
            )
        return operator

    return checker
