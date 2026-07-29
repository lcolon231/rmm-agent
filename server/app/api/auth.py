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
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.ratelimit import login_limiter
from app.core.security import (
    create_access_token,
    dummy_verify,
    hash_password,
    verify_password,
)
from app.models.models import (
    Agent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
    Site,
)
from app.schemas.schemas import (
    LoginRequest,
    OperatorCreate,
    OperatorOut,
    OperatorRoleChange,
    OperatorStatusChange,
    ScriptExecutionPermissionChange,
    ScriptExecutionPermissionRevoke,
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
    limit_key = f"{client_ip(request)}:{body.email}"
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
    request: Request,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
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
    await audit.record(
        db,
        action="operator.created",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            "operator_role": operator.role.value,
            "email": operator.email,
        },
    )
    return operator


@router.get("/auth/me", response_model=OperatorOut)
async def whoami(
    operator: Operator = Depends(require_role(OperatorRole.readonly)),
):
    """Return the calling operator — handy for the dashboard to know its role."""
    return operator


@router.get("/auth/operators", response_model=list[OperatorOut])
async def list_operators(
    _admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """List operator identities and their current script permission. Admin-only."""
    result = await db.execute(select(Operator).order_by(Operator.email, Operator.id))
    return list(result.scalars().all())


async def _operator_or_404(db: AsyncSession, operator_id: str) -> Operator:
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    return target


async def _require_another_active_admin(
    db: AsyncSession,
    target: Operator,
) -> None:
    """Lock the active-admin set before removing one member from it."""
    if target.role != OperatorRole.admin or target.disabled:
        return
    active_admin_ids = list(
        (
            await db.execute(
                select(Operator.id)
                .where(
                    Operator.role == OperatorRole.admin,
                    Operator.disabled.is_(False),
                )
                .order_by(Operator.id)
                .with_for_update()
            )
        ).scalars()
    )
    if len(active_admin_ids) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "last_active_admin_required"},
        )


@router.put("/auth/operators/{operator_id}/role", response_model=OperatorOut)
async def change_operator_role(
    operator_id: str,
    body: OperatorRoleChange,
    request: Request,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Change a global operator role and invalidate every existing session."""
    target = await _operator_or_404(db, operator_id)
    if target.role == body.role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "operator_role_unchanged"},
        )
    if body.role != OperatorRole.admin:
        await _require_another_active_admin(db, target)

    previous_role = target.role
    script_permission_revoked = (
        body.role == OperatorRole.readonly
        and target.script_execution_scope is not None
    )
    target.role = body.role
    if body.role == OperatorRole.readonly:
        target.script_execution_scope = None
        target.script_execution_scope_id = None
    target.token_generation += 1
    await audit.record(
        db,
        action="operator.role_changed",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": target.id,
            "previous_role": previous_role.value,
            "new_role": target.role.value,
            "script_permission_revoked": script_permission_revoked,
            "reason": body.reason,
        },
    )
    return target


@router.put("/auth/operators/{operator_id}/disabled", response_model=OperatorOut)
async def change_operator_disabled_state(
    operator_id: str,
    body: OperatorStatusChange,
    request: Request,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Disable or re-enable an operator and invalidate all issued sessions."""
    target = await _operator_or_404(db, operator_id)
    if target.disabled == body.disabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "operator_state_unchanged"},
        )
    if body.disabled:
        await _require_another_active_admin(db, target)

    previous_disabled = target.disabled
    target.disabled = body.disabled
    target.token_generation += 1
    await audit.record(
        db,
        action="operator.status_changed",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": target.id,
            "previous_disabled": previous_disabled,
            "new_disabled": target.disabled,
            "reason": body.reason,
        },
    )
    return target


async def _validate_script_permission_scope(
    db: AsyncSession,
    body: ScriptExecutionPermissionChange,
) -> None:
    if body.scope == ScriptExecutionScope.global_:
        return
    target = (
        await db.get(Site, body.scope_id)
        if body.scope == ScriptExecutionScope.site
        else await db.get(Agent, body.scope_id)
    )
    if target is None:
        kind = "Site" if body.scope == ScriptExecutionScope.site else "Agent"
        raise HTTPException(status_code=404, detail=f"{kind} not found")


@router.put(
    "/auth/operators/{operator_id}/script-permission",
    response_model=OperatorOut,
)
async def set_script_execution_permission(
    operator_id: str,
    body: ScriptExecutionPermissionChange,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Explicitly grant one global, site, or agent arbitrary-script scope."""
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    if target.role == OperatorRole.readonly:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "script_permission_role_ineligible"},
        )
    await _validate_script_permission_scope(db, body)

    previous_scope = target.script_execution_scope
    previous_scope_id = target.script_execution_scope_id
    target.script_execution_scope = body.scope
    target.script_execution_scope_id = body.scope_id
    await audit.record(
        db,
        action="operator.script_permission_changed",
        actor=admin.email,
        agent_id=(
            body.scope_id
            if body.scope == ScriptExecutionScope.agent
            else None
        ),
        detail={
            "operator_id": target.id,
            "operator_role": target.role.value,
            "previous_scope": (
                previous_scope.value if previous_scope is not None else None
            ),
            "previous_scope_id": previous_scope_id,
            "new_scope": body.scope.value,
            "new_scope_id": body.scope_id,
            "reason": body.reason,
        },
    )
    return target


@router.post(
    "/auth/operators/{operator_id}/script-permission/revoke",
    response_model=OperatorOut,
)
async def revoke_script_execution_permission(
    operator_id: str,
    body: ScriptExecutionPermissionRevoke,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Return an operator to the default-deny arbitrary-script state."""
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    if target.script_execution_scope is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "script_permission_not_granted"},
        )

    previous_scope = target.script_execution_scope
    previous_scope_id = target.script_execution_scope_id
    target.script_execution_scope = None
    target.script_execution_scope_id = None
    await audit.record(
        db,
        action="operator.script_permission_revoked",
        actor=admin.email,
        agent_id=(
            previous_scope_id
            if previous_scope == ScriptExecutionScope.agent
            else None
        ),
        detail={
            "operator_id": target.id,
            "operator_role": target.role.value,
            "previous_scope": previous_scope.value,
            "previous_scope_id": previous_scope_id,
            "reason": body.reason,
        },
    )
    return target


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
