# SPDX-License-Identifier: AGPL-3.0-only
"""Session inventory, revocation, refresh, and break-glass access (issue #69).

Two surfaces, separated because they answer different questions:

* **Sessions** -- "where am I signed in, and how do I end one of those?" Scoped
  to the caller by default; a platform admin can inspect and end anyone's.
* **Break-glass** -- the deliberate emergency bypass, its provisioning, and the
  review queue that keeps its use accountable.

Break-glass activation is the one unauthenticated write endpoint in this file,
and that is not an oversight: requiring a session to reach the escape hatch for
"nobody can obtain a session" would be circular. It is bounded instead by a
tight per-IP rate limit, a mandatory reason, a short session lifetime, and an
audit trail no successful activation can avoid.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_operator,
    require_platform_admin,
    require_step_up,
)
from app.core import audit, break_glass, sessions
from app.core.clientip import client_ip
from app.core.config import settings
from app.core.database import get_db
from app.core.security import AMR_BREAK_GLASS, AMR_PASSWORD, create_access_token
from app.models.models import (
    BreakGlassAccount,
    BreakGlassActivation,
    Operator,
    OperatorSession,
    OperatorSessionEndReason,
)
from app.schemas.admin_sessions import (
    BreakGlassAccountOut,
    BreakGlassActivateRequest,
    BreakGlassActivationOut,
    BreakGlassCreate,
    BreakGlassCredentialOut,
    BreakGlassDisable,
    BreakGlassReview,
    BreakGlassRotate,
    BreakGlassStatusOut,
    SessionOut,
    SessionRefreshOut,
    SessionRevoke,
    SessionRevokeResult,
)

router = APIRouter(tags=["sessions"])


def _user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent", "")[:500] or None


def _view(session: OperatorSession, *, current_id: str | None) -> SessionOut:
    out = SessionOut.model_validate(session)
    return out.model_copy(
        update={
            "end_reason": session.end_reason.value if session.end_reason else None,
            "is_current": session.id == current_id,
        }
    )


def _current_session_id(operator: Operator) -> str | None:
    record = getattr(operator, "session_record", None)
    return record.id if record is not None else None


# --------------------------------------------------------------------------- #
# Session inventory
# --------------------------------------------------------------------------- #
@router.get("/auth/sessions", response_model=list[SessionOut])
async def list_own_sessions(
    include_ended: bool = False,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """List the caller's own sessions.

    Scoped to the caller with no operator_id parameter, so there is no route
    here by which one operator can enumerate another's devices.
    """
    rows = await sessions.list_for_operator(
        db, operator.id, include_ended=include_ended
    )
    current = _current_session_id(operator)
    return [_view(row, current_id=current) for row in rows]


@router.post("/auth/sessions/{session_id}/revoke", response_model=SessionRevokeResult)
async def revoke_own_session(
    session_id: str,
    body: SessionRevoke,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """End one of the caller's own sessions.

    Not step-up gated, unlike most security-relevant mutations: ending your own
    session only ever *reduces* access, and someone who suspects a compromise
    must be able to act immediately rather than first find their security key.
    """
    session = await db.get(OperatorSession, session_id)
    if session is None or session.operator_id != operator.id:
        # Another operator's session and a nonexistent one are indistinguishable.
        raise HTTPException(status_code=404, detail="Session not found")

    revoked = await sessions.revoke(db, session, by_admin=False, ended_by=operator.id)
    if revoked:
        await audit.record(
            db,
            action="operator.session_revoked",
            actor=operator.email,
            actor_user_id=operator.id,
            source_ip=client_ip(request),
            user_agent=_user_agent(request),
            detail={
                "operator_id": operator.id,
                "session_id": session.id,
                "by": "self",
                "reason": body.reason,
                "session_count": 1,
            },
        )
    return SessionRevokeResult(revoked=1 if revoked else 0)


@router.post("/auth/sessions/revoke-others", response_model=SessionRevokeResult)
async def revoke_other_own_sessions(
    body: SessionRevoke,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """End every session except the one making this request.

    The common move after "I think someone has my laptop": sign everything else
    out while keeping the session being used to do the clean-up. A legacy
    session with no server-side row is not covered here -- use the
    token-generation bump on ``/auth/revoke-tokens`` for that.
    """
    current = _current_session_id(operator)
    count = await sessions.revoke_all_for_operator(
        db,
        operator.id,
        reason=OperatorSessionEndReason.revoked_by_self,
        ended_by=operator.id,
        except_session_id=current,
    )
    await audit.record(
        db,
        action="operator.session_revoked",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "operator_id": operator.id,
            "session_id": current,
            "by": "self_others",
            "reason": body.reason,
            "session_count": count,
        },
    )
    return SessionRevokeResult(revoked=count)


@router.post("/auth/session/refresh", response_model=SessionRefreshOut)
async def refresh_session(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """Mint a fresh access token for the caller's existing session.

    This is what makes the two lifetimes mean different things. Without it the
    JWT expiry would be the only ceiling and the absolute lifetime would be
    decorative. Refresh moves the *token's* expiry; it can never move
    ``absolute_expires_at``, so a session still ends on schedule no matter how
    often it is renewed.

    Every check that guards an ordinary request has already run in
    ``get_current_operator`` -- revocation, idle, absolute -- so reaching this
    handler is itself proof the session is still live.
    """
    session = getattr(operator, "session_record", None)
    if session is None:
        # A legacy, unmanaged session has nothing to refresh; re-authenticating
        # is what upgrades it to a managed one.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "session_not_managed"},
        )

    amr = tuple(sorted(getattr(operator, "session_amr", None) or {AMR_PASSWORD}))
    step_up_at = getattr(operator, "session_step_up_at", None)
    token = create_access_token(
        subject=operator.id,
        generation=operator.token_generation,
        amr=amr,
        step_up_at=step_up_at,
        session_id=session.id,
    )
    return SessionRefreshOut(
        access_token=token, absolute_expires_at=session.absolute_expires_at
    )


# --------------------------------------------------------------------------- #
# Administrative session oversight
# --------------------------------------------------------------------------- #
@router.get(
    "/auth/operators/{operator_id}/sessions", response_model=list[SessionOut]
)
async def list_operator_sessions(
    operator_id: str,
    include_ended: bool = False,
    _admin: Operator = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Inspect another operator's sessions. Platform-admin only."""
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")
    rows = await sessions.list_for_operator(db, operator_id, include_ended=include_ended)
    return [_view(row, current_id=None) for row in rows]


@router.post(
    "/auth/operators/{operator_id}/sessions/revoke",
    response_model=SessionRevokeResult,
)
async def revoke_operator_sessions(
    operator_id: str,
    body: SessionRevoke,
    request: Request,
    admin: Operator = Depends(require_platform_admin),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """End every live session for another operator. Platform-admin only.

    Step-up gated (issue #67): mass session revocation is a denial-of-service
    lever against the people best placed to notice an intrusion. Unlike the
    ``token_generation`` bump on ``/auth/operators/{id}/revoke-tokens``, this
    leaves the generation alone, so it ends the sessions this deployment can
    see without invalidating credentials the operator may still need.
    """
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")

    count = await sessions.revoke_all_for_operator(
        db,
        operator_id,
        reason=OperatorSessionEndReason.revoked_by_admin,
        ended_by=admin.id,
    )
    await audit.record(
        db,
        action="operator.session_revoked",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "operator_id": target.id,
            "session_id": None,
            "by": "admin",
            "reason": body.reason,
            "session_count": count,
        },
    )
    return SessionRevokeResult(revoked=count)


# --------------------------------------------------------------------------- #
# Break-glass provisioning
# --------------------------------------------------------------------------- #
def _refuse_break_glass_session(operator: Operator) -> None:
    """Refuse an emergency session the ability to provision emergency access.

    Break-glass exists to restore administrative capability, so a break-glass
    session is deliberately allowed to *act*. What it must not do is entrench:
    minting or rotating credentials from inside an emergency session would let
    one stolen envelope quietly become a permanent, self-renewing foothold that
    outlives both the incident and the credential that started it.

    The ordinary step-up gate cannot express this, because step-up is vacuous
    for an operator holding no authenticator -- and a break-glass identity holds
    none by construction. So the rule is stated directly here rather than
    inferred, and it fails closed on the signed `amr` claim.
    """
    if AMR_BREAK_GLASS in (getattr(operator, "session_amr", None) or frozenset()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "break_glass_cannot_provision",
                "message": (
                    "An emergency session cannot create or rotate break-glass "
                    "credentials. Restore normal administrative access first."
                ),
            },
        )


def _require_break_glass_enabled() -> None:
    try:
        break_glass.ensure_enabled()
    except break_glass.BreakGlassDisabled as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "break_glass_disabled", "message": str(exc)},
        ) from exc


@router.get("/auth/break-glass", response_model=list[BreakGlassAccountOut])
async def list_break_glass_accounts(
    _admin: Operator = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """List provisioned emergency credentials. Platform-admin only.

    Returns fingerprints, never credentials: the plaintext exists once, at
    creation or rotation, and is not recoverable afterwards by anyone.
    """
    from sqlalchemy import select

    rows = (
        await db.execute(
            select(BreakGlassAccount).order_by(
                BreakGlassAccount.created_at, BreakGlassAccount.id
            )
        )
    ).scalars().all()
    return list(rows)


@router.get("/auth/break-glass/status", response_model=BreakGlassStatusOut)
async def break_glass_status(
    _admin: Operator = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Summary for the dashboard banner, including the open-review count."""
    from sqlalchemy import func, select

    account_count = int(
        (
            await db.execute(select(func.count()).select_from(BreakGlassAccount))
        ).scalar_one()
    )
    return BreakGlassStatusOut(
        enabled=settings.break_glass_enabled,
        account_count=account_count,
        unreviewed_activations=await break_glass.unreviewed_count(db),
    )


@router.post(
    "/auth/break-glass",
    response_model=BreakGlassCredentialOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_break_glass_account(
    body: BreakGlassCreate,
    request: Request,
    admin: Operator = Depends(require_platform_admin),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Provision an emergency credential. Platform-admin and step-up gated.

    The credential is in the response body and nowhere else: not in the audit
    chain, not in a log, not retrievable later. Print it, seal it, and record
    the fingerprint against the envelope.
    """
    _refuse_break_glass_session(admin)
    _require_break_glass_enabled()
    try:
        account, credential = await break_glass.create_account(
            db, label=body.label, created_by_email=admin.email
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "break_glass_label_taken"},
        ) from exc

    await audit.record(
        db,
        action="break_glass.account_created",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "account_id": account.id,
            "operator_id": account.operator_id,
            "label": account.label,
            "credential_fingerprint": account.credential_fingerprint,
            "reason": body.reason,
        },
    )
    return BreakGlassCredentialOut(
        account=BreakGlassAccountOut.model_validate(account), credential=credential
    )


@router.post(
    "/auth/break-glass/{account_id}/rotate", response_model=BreakGlassCredentialOut
)
async def rotate_break_glass_credential(
    account_id: str,
    body: BreakGlassRotate,
    request: Request,
    admin: Operator = Depends(require_platform_admin),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Issue a new credential; the previous one stops working immediately."""
    _refuse_break_glass_session(admin)
    _require_break_glass_enabled()
    account = await _account_or_404(db, account_id)
    previous_fingerprint = account.credential_fingerprint
    credential = await break_glass.rotate_credential(db, account)
    await audit.record(
        db,
        action="break_glass.credential_rotated",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "account_id": account.id,
            "label": account.label,
            "previous_fingerprint": previous_fingerprint,
            "credential_fingerprint": account.credential_fingerprint,
            "reason": body.reason,
        },
    )
    return BreakGlassCredentialOut(
        account=BreakGlassAccountOut.model_validate(account), credential=credential
    )


@router.put(
    "/auth/break-glass/{account_id}/disabled", response_model=BreakGlassAccountOut
)
async def set_break_glass_disabled(
    account_id: str,
    body: BreakGlassDisable,
    request: Request,
    admin: Operator = Depends(require_platform_admin),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Disable or re-enable an emergency credential without losing its history."""
    _refuse_break_glass_session(admin)
    account = await _account_or_404(db, account_id)
    if (account.disabled_at is not None) == body.disabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "break_glass_state_unchanged"},
        )
    await break_glass.set_disabled(
        db, account, disabled=body.disabled, reason=body.reason
    )
    await audit.record(
        db,
        action="break_glass.account_state_changed",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "account_id": account.id,
            "label": account.label,
            "disabled": body.disabled,
            "reason": body.reason,
        },
    )
    return account


async def _account_or_404(db: AsyncSession, account_id: str) -> BreakGlassAccount:
    account = await db.get(BreakGlassAccount, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Break-glass account not found")
    return account


# --------------------------------------------------------------------------- #
# Break-glass activation (unauthenticated by necessity)
# --------------------------------------------------------------------------- #
@router.post("/auth/break-glass/activate", response_model=SessionRefreshOut)
async def activate_break_glass(
    body: BreakGlassActivateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Exchange an emergency credential for a short-lived session.

    Unauthenticated on purpose. This is the escape hatch for the case where
    nobody can obtain a session, so requiring one here would be circular, and
    requiring a second factor would reintroduce the exact failure the hatch
    exists to survive.

    What bounds it instead: a tight per-IP rate limit, a mandatory reason, a
    session lifetime measured in one hour rather than eight, a marked session
    row, an audit event, and a review record that stays open until a human
    closes it. A failed attempt and an unknown credential are indistinguishable
    and equally rate-limited, so this endpoint is not an oracle for guessing
    which envelopes exist.
    """
    _require_break_glass_enabled()
    source_ip = client_ip(request)
    retry_after = break_glass.activation_limiter.retry_after(source_ip)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts; try again later",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    result = await break_glass.activate(
        db,
        credential=body.credential,
        reason=body.reason,
        source_ip=source_ip,
        user_agent=_user_agent(request),
    )
    if result is None:
        break_glass.activation_limiter.record_failure(source_ip)
        await audit.record(
            db,
            action="break_glass.activation_failed",
            actor="break-glass",
            source_ip=source_ip,
            user_agent=_user_agent(request),
            detail={"reason": "invalid_credential"},
        )
        # Commit so the refused attempt is recorded even though the request
        # fails: an attacker probing envelopes must leave a trail.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Break-glass activation failed",
        )

    break_glass.activation_limiter.clear(source_ip)
    session = await sessions.create(
        db,
        result.operator,
        auth_methods=(AMR_BREAK_GLASS,),
        source_ip=source_ip,
        user_agent=_user_agent(request),
        is_break_glass=True,
    )
    result.activation.session_id = session.id
    await audit.record(
        db,
        action="break_glass.activated",
        actor=result.account.label,
        actor_user_id=result.operator.id,
        source_ip=source_ip,
        user_agent=_user_agent(request),
        detail={
            "account_id": result.account.id,
            "activation_id": result.activation.id,
            "operator_id": result.operator.id,
            "session_id": session.id,
            "label": result.account.label,
            "credential_fingerprint": result.account.credential_fingerprint,
            "reason": body.reason,
        },
    )
    token = create_access_token(
        subject=result.operator.id,
        generation=result.operator.token_generation,
        amr=(AMR_BREAK_GLASS,),
        session_id=session.id,
    )
    return SessionRefreshOut(
        access_token=token, absolute_expires_at=session.absolute_expires_at
    )


# --------------------------------------------------------------------------- #
# Break-glass review
# --------------------------------------------------------------------------- #
@router.get(
    "/auth/break-glass/activations", response_model=list[BreakGlassActivationOut]
)
async def list_break_glass_activations(
    unreviewed_only: bool = False,
    _admin: Operator = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """The activation history, and the queue of what still needs sign-off."""
    return await break_glass.list_activations(db, unreviewed_only=unreviewed_only)


@router.post(
    "/auth/break-glass/activations/{activation_id}/review",
    response_model=BreakGlassActivationOut,
)
async def review_break_glass_activation(
    activation_id: str,
    body: BreakGlassReview,
    request: Request,
    admin: Operator = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Sign off one activation as investigated.

    Not step-up gated: reviewing records an opinion, it grants nothing. Making
    the accountable act harder than the privileged one would only discourage
    the review from happening.
    """
    activation = await db.get(BreakGlassActivation, activation_id)
    if activation is None:
        raise HTTPException(status_code=404, detail="Activation not found")

    closed = await break_glass.review(
        db, activation, reviewed_by_email=admin.email, note=body.note
    )
    if not closed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "activation_already_reviewed"},
        )
    await audit.record(
        db,
        action="break_glass.activation_reviewed",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=_user_agent(request),
        detail={
            "activation_id": activation.id,
            "account_id": activation.account_id,
            "note": body.note,
        },
    )
    return activation
