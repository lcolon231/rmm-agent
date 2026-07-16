"""Authentication endpoints: login and operator management.

Login is the one place a caller is allowed in without already holding a token.
Everything else in the app requires the token this endpoint issues.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
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
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Exchange email + password for a signed JWT.

    Security notes:
      - We return the SAME 401 whether the email is unknown or the password is
        wrong, so an attacker cannot tell which emails are registered.
      - When the email is unknown we still run a dummy hash verification, so the
        response time doesn't reveal account existence via a timing side-channel.
    """
    result = await db.execute(select(Operator).where(Operator.email == body.email))
    operator = result.scalar_one_or_none()

    if operator is None:
        dummy_verify()  # keep timing constant
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    if operator.disabled or not verify_password(body.password, operator.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    # The token's subject is the operator id. The token is signed, not
    # encrypted — it carries no secret, just a claim the server can verify.
    token = create_access_token(subject=operator.id)
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
