"""Shared API dependencies."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token, hash_token
from app.models.models import Agent, Operator, OperatorRole


async def get_current_agent(
    authorization: str | None = Header(default=None, description="Bearer <agent_token>"),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """Resolve the agent from its bearer token.

    We look the agent up by the *hash* of the presented token — the plaintext
    never touches the database.
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

    result = await db.execute(
        select(Agent).where(Agent.token_hash == hash_token(token))
    )
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token"
        )
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

    operator_id = decode_access_token(token)  # None if signature/exp invalid
    if operator_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    operator = await db.get(Operator, operator_id)
    if operator is None or operator.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Operator not found or disabled"
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
