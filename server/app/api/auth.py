# SPDX-License-Identifier: AGPL-3.0-only
"""Authentication endpoints: login and operator management.

Login is the one place a caller is allowed in without already holding a token.
Everything else in the app requires the token this endpoint issues.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit
from app.core.database import get_db
from app.core.ratelimit import login_limiter
from app.core.security import (
    create_access_token,
    dummy_verify,
    hash_password,
    verify_password,
)
from app.models.models import Operator, OperatorRole
from app.schemas.schemas import (
    LoginRequest,
    OperatorCreate,
    OperatorOut,
    TokenResponse,
)

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Exchange email + password for a signed JWT.

    Security notes:
      - We return the SAME 401 whether the email is unknown or the password is
        wrong, so an attacker cannot tell which emails are registered.
      - When the email is unknown we still run a dummy hash verification, so the
        response time doesn't reveal account existence via a timing side-channel.
      - Failed attempts are rate-limited per (client IP, email): once the window
        fills, further attempts get 429 with Retry-After. Keying on the pair
        slows brute force without letting a remote attacker lock the real user
        out from a different address.
    """
    client_ip = request.client.host if request.client else "unknown"
    limit_key = f"{client_ip}:{body.email}"
    retry_after = login_limiter.retry_after(limit_key)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts; try again later",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    result = await db.execute(select(Operator).where(Operator.email == body.email))
    operator = result.scalar_one_or_none()

    if operator is None:
        dummy_verify()  # keep timing constant
        login_limiter.record_failure(limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    if operator.disabled or not verify_password(body.password, operator.password_hash):
        login_limiter.record_failure(limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    login_limiter.clear(limit_key)
    # The token's subject is the operator id. The token is signed, not
    # encrypted — it carries no secret, just a claim the server can verify.
    # The generation claim ties it to the operator's current token version.
    token = create_access_token(subject=operator.id, generation=operator.token_generation)
    return TokenResponse(access_token=token)


@router.post("/auth/operators", response_model=OperatorOut, status_code=201)
async def create_operator(
    body: OperatorCreate,
    _admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Create a new operator. Admin-only.

    The first admin can't be made this way (chicken-and-egg) — bootstrap it with
    scripts/create_admin.py.
    """
    exists = await db.execute(select(Operator).where(Operator.email == body.email))
    if exists.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    operator = Operator(
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(operator)
    await db.flush()
    return operator


@router.get("/auth/me", response_model=OperatorOut)
async def whoami(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
):
    """Return the calling operator — handy for the dashboard to know its role."""
    return operator


@router.post("/auth/revoke-tokens", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_own_tokens(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
    db: AsyncSession = Depends(get_db),
):
    """Invalidate every token issued to the calling operator, including the one
    used for this request ("log out everywhere"). Log in again for a new one."""
    operator.token_generation += 1
    await audit.record(
        db,
        action="operator.tokens_revoked",
        actor=operator.email,
        detail={"operator_id": operator.id, "by": "self"},
    )


@router.post(
    "/auth/operators/{operator_id}/revoke-tokens",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_operator_tokens(
    operator_id: str,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Admin: invalidate every token issued to another operator (leaked laptop,
    offboarding). The account itself stays enabled — pair with `disabled` to
    lock it entirely."""
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    target.token_generation += 1
    await audit.record(
        db,
        action="operator.tokens_revoked",
        actor=admin.email,
        detail={"operator_id": target.id, "by": "admin"},
    )
