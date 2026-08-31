# SPDX-License-Identifier: AGPL-3.0-only
"""Shared API dependencies."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import mfa
from app.core.database import get_db
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_MFA_PENDING,
    decode_access_token,
    hash_token,
    token_amr,
    token_step_up_at,
    token_type,
)
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
def _bearer_claims(authorization: str | None) -> dict:
    """Extract and verify the JWT claims from an Authorization header.

    The header is declared Optional by callers so that a *missing* token
    produces a 401 (an auth failure we raise) rather than FastAPI's 422
    request-validation error. A missing credential is "unauthenticated", not
    "malformed request".
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
    return claims


async def _operator_for_claims(db: AsyncSession, claims: dict) -> Operator:
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
    # Transient markers (never persisted), mirroring Agent.credential_matched:
    # they carry how this session authenticated to the authorization helpers
    # below, so an MFA decision never has to re-parse the token.
    operator.session_amr = token_amr(claims)
    operator.session_step_up_at = token_step_up_at(claims)
    return operator


async def get_current_operator(
    authorization: str | None = Header(default=None, description="Bearer <operator_jwt>"),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """AuthN: resolve the operator from a full-access JWT bearer token.

    This proves *who* the caller is. It does not decide what they may do — that
    is authorization, handled by require_role below.

    This is also the single choke point that refuses the half-authenticated
    ``mfa_pending`` token (issue #67). Every operator-facing route in the app
    resolves identity through here, so rejecting the restricted type once means
    a correct password with no second factor buys access to nothing but the MFA
    completion endpoints, which resolve it deliberately and separately.
    """
    claims = _bearer_claims(authorization)
    if token_type(claims) != TOKEN_TYPE_ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return await _operator_for_claims(db, claims)


async def get_mfa_pending_operator(
    authorization: str | None = Header(default=None, description="Bearer <mfa_token>"),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """Resolve the operator behind a restricted, post-password MFA token.

    Accepts *only* the restricted type. A full access token is refused here on
    purpose: an already-complete session has no business replaying the login
    ceremony, and allowing it would create a second path to mint a session that
    skips the checks the login endpoint performs.
    """
    claims = _bearer_claims(authorization)
    if token_type(claims) != TOKEN_TYPE_MFA_PENDING:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return await _operator_for_claims(db, claims)


def _session_amr(operator: Operator) -> frozenset[str]:
    return getattr(operator, "session_amr", None) or frozenset()


async def require_step_up(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """AuthZ: require a recent proof of possession of a registered authenticator.

    Applied to the operations whose abuse would let a stolen session entrench
    itself or widen its reach: changing another operator's role or status,
    revoking someone's sessions, resetting someone's MFA, and reconfiguring the
    caller's own factors.

    The gate is *vacuous for operators who have no second factor to present*.
    That is not a loophole, it is the compatibility contract: a deployment that
    has not adopted MFA behaves exactly as it did before, and an operator part
    way through enrolment is never locked out of the account management they
    already had. The moment an operator holds an active credential, the gate
    becomes real for them, with no configuration change required.

    A recovery-code session never satisfies this, however recently it
    authenticated — see :func:`app.core.mfa.step_up_is_fresh`.
    """
    # ``off`` disables the gate outright, and it has to: with MFA off no
    # ceremony can be started, so a gate that still demanded one would be
    # unsatisfiable and would lock every enrolled administrator out of operator
    # management. Rollback must actually restore the previous behaviour.
    if mfa.enforcement_mode() == mfa.ENFORCEMENT_OFF:
        return operator
    if not await mfa.has_active_credential(db, operator.id):
        return operator
    if mfa.step_up_is_fresh(
        _session_amr(operator), getattr(operator, "session_step_up_at", None)
    ):
        return operator
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "code": "step_up_required",
            "message": (
                "Re-authenticate with your security key to perform this operation."
            ),
        },
    )


async def require_mfa_verified(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """AuthZ: require that the session presented *some* second factor at login.

    Weaker than :func:`require_step_up` by design, and used for the one
    operation that must stay reachable after device loss: enrolling a
    replacement authenticator. A recovery code satisfies this, which is what
    makes the codes worth having; it does not satisfy step-up, which is what
    stops them from being a full account takeover.
    """
    if mfa.enforcement_mode() == mfa.ENFORCEMENT_OFF:
        return operator
    if not await mfa.has_active_credential(db, operator.id):
        return operator
    if mfa.session_is_mfa_verified(_session_amr(operator)):
        return operator
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "code": "mfa_verification_required",
            "message": "Complete multi-factor authentication to perform this operation.",
        },
    )


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


async def require_platform_admin(
    operator: Operator = Depends(get_current_operator),
) -> Operator:
    """AuthZ: the deployment-wide superuser gate (issue #66).

    Platform admin is the only principal that crosses the tenant boundary and
    the only one that may grant/revoke client memberships or toggle the flag
    itself. It is independent of the global role: a global ``admin`` is not a
    platform admin unless explicitly flagged (the 0037 migration promotes
    pre-tenancy admins once, on upgrade). Fails closed with 403.
    """
    if not operator.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires platform administrator",
        )
    return operator
