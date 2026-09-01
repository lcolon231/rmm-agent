# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-factor authentication endpoints (issue #67).

Four surfaces live here, separated because they are reachable with different
credentials and that separation is the security boundary:

* **Login completion** (``/auth/mfa/login/*``) — reachable only with the
  restricted post-password token. Turns a half-authenticated state into a
  session, or refuses.
* **Enrolment** (``/auth/mfa/credentials``) — reachable with a full session, or
  with the restricted token when policy requires an operator to enrol before
  they may do anything else.
* **Device management** (rename, revoke, recovery codes) — reachable with a full
  session that has recently proven possession of a registered authenticator.
* **Administrative reset** (``/auth/operators/{id}/mfa/reset``) — the device-loss
  escape hatch, admin-only and step-up gated.

Every failure returns a generic message and audits a coded reason. The code
names the rule that refused the ceremony; it never echoes the value that failed
it, and it never distinguishes "no such credential" from "wrong signature",
because that distinction is exactly what an attacker probing a stolen password
would want.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    _bearer_claims,
    _operator_for_claims,
    get_current_operator,
    get_mfa_pending_operator,
    require_role,
    require_step_up,
)
from app.core import audit, mfa, sessions
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.security import (
    AMR_PASSWORD,
    AMR_RECOVERY_CODE,
    AMR_WEBAUTHN,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_MFA_PENDING,
    create_access_token,
    token_type,
)
from app.core.webauthn import (
    MAX_CREDENTIAL_ID_BYTES,
    SUPPORTED_ALGORITHMS,
    WebAuthnError,
    b64url_decode,
    b64url_encode,
    verify_assertion,
    verify_registration,
)
from app.models.models import (
    Operator,
    OperatorRole,
    WebAuthnChallengePurpose,
    WebAuthnCredential,
)
from app.schemas.mfa import (
    AssertionVerification,
    AuthenticationOptionsOut,
    CredentialRename,
    CredentialRevoke,
    LoginResponse,
    MfaReset,
    MfaResetOut,
    MfaStatusOut,
    PublicKeyCredentialDescriptor,
    RecoveryCodesOut,
    RecoveryCodeVerification,
    RegistrationOptionsOut,
    RegistrationVerification,
    WebAuthnCredentialOut,
)

router = APIRouter(tags=["mfa"])

# One message for every ceremony failure. The coded reason goes to the audit
# log, where a reviewer can see it; the caller learns only that it did not work.
_GENERIC_FAILURE = "Multi-factor authentication failed"


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _ceremony_timeout_ms() -> int:
    from app.core.config import settings

    return settings.mfa_challenge_ttl_seconds * 1000


def _require_enabled() -> mfa.RelyingParty:
    """Resolve the relying party, refusing every ceremony when MFA is off.

    ``off`` is the rollback position, and rollback has to mean something: with
    it set, no new credential can be registered and no ceremony can be
    completed, so the feature cannot half-re-enable itself through a stale tab.
    """
    if mfa.enforcement_mode() == mfa.ENFORCEMENT_OFF:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "mfa_disabled"},
        )
    try:
        return mfa.relying_party()
    except mfa.MfaConfigurationError as exc:
        # Fail closed and loudly: an unresolvable relying party means we cannot
        # state the scope a credential would be bound to, and guessing it would
        # silently produce credentials that stop working later.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "mfa_not_configured", "message": str(exc)},
        ) from exc


def _rate_limit_key(request: Request, operator: Operator) -> str:
    return f"{client_ip(request)}:{operator.id}"


def _enforce_rate_limit(request: Request, operator: Operator) -> None:
    retry_after = mfa.mfa_limiter.retry_after(_rate_limit_key(request, operator))
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts; try again later",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )


async def _audit_failure(
    db: AsyncSession,
    request: Request,
    operator: Operator,
    *,
    method: str,
    reason: str,
) -> None:
    await audit.record(
        db,
        action="mfa.authentication_failed",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={"operator_id": operator.id, "method": method, "reason": reason},
    )


def _ceremony_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_FAILURE
    )


def _decode_field(value: str, code: str) -> bytes:
    try:
        return b64url_decode(value)
    except WebAuthnError as exc:
        raise WebAuthnError(code) from exc


async def _credential_descriptors(
    db: AsyncSession, operator_id: str
) -> list[PublicKeyCredentialDescriptor]:
    return [
        PublicKeyCredentialDescriptor(
            id=credential.credential_id,
            transports=(
                credential.transports.split(",") if credential.transports else None
            ),
        )
        for credential in await mfa.active_credentials(db, operator_id)
    ]


# --------------------------------------------------------------------------- #
# Enrolment authentication
# --------------------------------------------------------------------------- #
async def get_enrollment_operator(
    authorization: str | None = Header(default=None, description="Bearer <token>"),
    db: AsyncSession = Depends(get_db),
) -> Operator:
    """Resolve the operator allowed to register a new authenticator.

    Enrolment is the one operation that must be reachable from both sides of the
    MFA boundary, and the three accepted states are each there for a reason:

    1. **Full session, not yet enrolled.** Bootstrap. Nothing stronger than a
       password exists yet, so nothing stronger can be demanded.
    2. **Full session that presented a second factor.** Adding a device to an
       already-protected account. A password-only session is refused here, so a
       stolen session cannot quietly plant an attacker's own authenticator.
    3. **Restricted post-password token, when policy requires enrolment.** The
       operator is obliged to enrol and has no session yet; refusing them would
       make the requirement impossible to satisfy.
    """
    claims = _bearer_claims(authorization)
    kind = token_type(claims)
    if kind not in (TOKEN_TYPE_ACCESS, TOKEN_TYPE_MFA_PENDING):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    operator = await _operator_for_claims(db, claims)
    enrolled = await mfa.has_active_credential(db, operator.id)

    if kind == TOKEN_TYPE_MFA_PENDING:
        # The restricted token is only an enrolment credential while the
        # operator is in the state that made it one. An already-enrolled
        # operator must finish their login instead, or the restricted token
        # would be a standing bypass of the second factor.
        if enrolled or not mfa.enrollment_is_required(operator):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        return operator

    if (
        enrolled
        and mfa.enforcement_mode() != mfa.ENFORCEMENT_OFF
        and not mfa.session_is_mfa_verified(
            getattr(operator, "session_amr", None) or frozenset()
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "mfa_verification_required",
                "message": (
                    "Complete multi-factor authentication before registering "
                    "another authenticator."
                ),
            },
        )
    return operator


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #
@router.get("/auth/mfa/status", response_model=MfaStatusOut)
async def mfa_status(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """Report the calling operator's MFA state and this session's capability."""
    credentials = await mfa.active_credentials(db, operator.id)
    amr = getattr(operator, "session_amr", None) or frozenset()
    return MfaStatusOut(
        enforcement=mfa.enforcement_mode(),
        enrollment_required=mfa.enrollment_is_required(operator),
        enrolled=bool(credentials),
        credential_count=len(credentials),
        recovery_codes_remaining=await mfa.unused_recovery_code_count(db, operator.id),
        step_up_satisfied=(
            not credentials
            or mfa.step_up_is_fresh(
                amr, getattr(operator, "session_step_up_at", None)
            )
        ),
        session_methods=sorted(amr),
        credentials=[
            WebAuthnCredentialOut.model_validate(credential)
            for credential in credentials
        ],
    )


@router.get("/auth/mfa/credentials", response_model=list[WebAuthnCredentialOut])
async def list_credentials(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """List the calling operator's registered authenticators.

    Scoped to the caller with no operator_id parameter: there is no route here
    by which one operator can enumerate another's devices.
    """
    return await mfa.active_credentials(db, operator.id)


# --------------------------------------------------------------------------- #
# Enrolment
# --------------------------------------------------------------------------- #
@router.post("/auth/mfa/credentials/options", response_model=RegistrationOptionsOut)
async def registration_options(
    operator: Operator = Depends(get_enrollment_operator),
    db: AsyncSession = Depends(get_db),
):
    """Begin registration: mint a challenge and describe what to create."""
    relying_party = _require_enabled()
    from app.core.config import settings

    if (
        await mfa.active_credential_count(db, operator.id)
        >= settings.mfa_max_credentials_per_operator
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "credential_limit_reached"},
        )

    _, raw_challenge = await mfa.issue_challenge(
        db,
        operator_id=operator.id,
        purpose=WebAuthnChallengePurpose.registration,
        rp_id=relying_party.rp_id,
    )
    return RegistrationOptionsOut(
        rp={"id": relying_party.rp_id, "name": relying_party.rp_name},
        user={
            # The user handle is the operator's opaque id, never their email.
            # It is stored on the authenticator and may be shown by it, so it
            # must not carry anything an authenticator disclosure would leak.
            "id": b64url_encode(operator.id.encode("utf-8")),
            "name": operator.email,
            "displayName": operator.email,
        },
        challenge=b64url_encode(raw_challenge),
        pubKeyCredParams=[
            {"type": "public-key", "alg": algorithm}
            for algorithm in SUPPORTED_ALGORITHMS
        ],
        timeout=_ceremony_timeout_ms(),
        excludeCredentials=await _credential_descriptors(db, operator.id),
        authenticatorSelection={
            "residentKey": "preferred",
            "userVerification": (
                "required" if settings.mfa_require_user_verification else "preferred"
            ),
        },
        attestation="none",
    )


@router.post(
    "/auth/mfa/credentials",
    response_model=WebAuthnCredentialOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_credential(
    body: RegistrationVerification,
    request: Request,
    operator: Operator = Depends(get_enrollment_operator),
    db: AsyncSession = Depends(get_db),
):
    """Complete registration and store the new authenticator."""
    relying_party = _require_enabled()
    from app.core.config import settings

    _enforce_rate_limit(request, operator)

    challenge = await mfa.consume_challenge(
        db,
        operator_id=operator.id,
        purpose=WebAuthnChallengePurpose.registration,
    )
    if challenge is None:
        mfa.mfa_limiter.record_failure(_rate_limit_key(request, operator))
        await _audit_failure(
            db, request, operator, method="registration", reason="challenge_not_found"
        )
        # Commit before raising: get_db rolls the session back on an exception,
        # which would discard both the audit event and — more importantly — the
        # record that this challenge was spent, handing a replay a second try.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "challenge_expired"},
        )

    try:
        result = verify_registration(
            client_data_json=_decode_field(body.client_data_json, "malformed_client_data"),
            attestation_object=_decode_field(
                body.attestation_object, "malformed_attestation_object"
            ),
            expected_challenge=b64url_decode(challenge.challenge),
            expected_origins=relying_party.origins,
            # The RP ID recorded when the challenge was minted, not the current
            # configuration: a ceremony is judged against the scope it started
            # under.
            expected_rp_id=challenge.rp_id,
            require_user_verification=settings.mfa_require_user_verification,
        )
    except WebAuthnError as exc:
        mfa.mfa_limiter.record_failure(_rate_limit_key(request, operator))
        await _audit_failure(
            db, request, operator, method="registration", reason=exc.code
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail={"code": exc.code}
        ) from exc

    if len(result.credential_id) > MAX_CREDENTIAL_ID_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_credential_id"},
        )

    # Re-check the ceiling after the ceremony too: options and completion are
    # separate requests, so two ceremonies started in parallel would otherwise
    # both pass the check made at options time.
    if (
        await mfa.active_credential_count(db, operator.id)
        >= settings.mfa_max_credentials_per_operator
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "credential_limit_reached"},
        )

    credential = WebAuthnCredential(
        operator_id=operator.id,
        credential_id=b64url_encode(result.credential_id),
        public_key_cose=b64url_encode(result.public_key_cose),
        algorithm=result.algorithm,
        sign_count=result.sign_count,
        aaguid=result.aaguid.hex(),
        name=body.name,
        transports=(",".join(body.transports)[:120] if body.transports else None),
        attestation_format=result.attestation_format,
        backup_eligible=result.backup_eligible,
        backup_state=result.backup_state,
    )
    db.add(credential)
    try:
        await db.flush()
    except IntegrityError as exc:
        # The unique constraint on credential_id is what stops the same
        # authenticator from being bound to two identities.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "credential_already_registered"},
        ) from exc

    mfa.mfa_limiter.clear(_rate_limit_key(request, operator))
    await audit.record(
        db,
        action="mfa.credential_registered",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            # The credential row id, not the WebAuthn credential ID: stable,
            # non-enumerable, and the thing every other event here refers to.
            "credential_id": credential.id,
            "name": credential.name,
            "algorithm": credential.algorithm,
            "aaguid": credential.aaguid,
            "attestation_format": credential.attestation_format,
            "backup_eligible": credential.backup_eligible,
        },
    )
    return credential


@router.put(
    "/auth/mfa/credentials/{credential_id}", response_model=WebAuthnCredentialOut
)
async def rename_credential(
    credential_id: str,
    body: CredentialRename,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Rename one of the caller's own authenticators."""
    credential = await _own_credential_or_404(db, operator, credential_id)
    previous_name = credential.name
    if previous_name == body.name:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "credential_name_unchanged"},
        )
    credential.name = body.name
    await audit.record(
        db,
        action="mfa.credential_renamed",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            "credential_id": credential.id,
            "previous_name": previous_name,
            "new_name": credential.name,
        },
    )
    return credential


@router.post(
    "/auth/mfa/credentials/{credential_id}/revoke",
    response_model=WebAuthnCredentialOut,
)
async def revoke_credential(
    credential_id: str,
    body: CredentialRevoke,
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Revoke one of the caller's own authenticators (lost or retired device)."""
    credential = await _own_credential_or_404(db, operator, credential_id)

    # Removing the last factor from an operator policy obliges to hold one would
    # leave them non-compliant and, on their next login, holding only a
    # restricted enrolment session. Refusing here — with a code the dashboard
    # can explain — is kinder and keeps the policy true at all times.
    if (
        mfa.enrollment_is_required(operator)
        and await mfa.active_credential_count(db, operator.id) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "last_mfa_credential_required"},
        )

    credential.revoked_at = datetime.now(timezone.utc)
    credential.revoked_reason = "operator_revoked"
    await audit.record(
        db,
        action="mfa.credential_revoked",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            "credential_id": credential.id,
            "name": credential.name,
            "reason": body.reason,
            "by": "self",
        },
    )
    return credential


async def _own_credential_or_404(
    db: AsyncSession, operator: Operator, credential_id: str
) -> WebAuthnCredential:
    """Resolve a credential that belongs to the caller, or 404.

    The ownership predicate and the not-revoked predicate are both part of the
    lookup, so another operator's credential and an already-revoked one are
    indistinguishable from a nonexistent one.
    """
    credential = await db.get(WebAuthnCredential, credential_id)
    if (
        credential is None
        or credential.operator_id != operator.id
        or credential.revoked_at is not None
    ):
        raise HTTPException(status_code=404, detail="Credential not found")
    return credential


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #
@router.post("/auth/mfa/recovery-codes", response_model=RecoveryCodesOut)
async def generate_recovery_codes(
    request: Request,
    operator: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Mint a fresh batch of recovery codes, invalidating any previous batch.

    The response body is the only place these codes ever exist outside the
    operator's own records. They are not audited, not logged, and cannot be
    retrieved again — a second call mints a new batch and destroys this one.
    """
    _require_enabled()
    if not await mfa.has_active_credential(db, operator.id):
        # Recovery codes recover *from* something. Handing them out before any
        # authenticator exists would just create a password-plus-paper factor
        # with none of the phishing resistance that justifies the feature.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "enrollment_required"},
        )

    batch_id, codes = await mfa.replace_recovery_codes(db, operator)
    await audit.record(
        db,
        action="mfa.recovery_codes_generated",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            "batch_id": batch_id,
            "code_count": len(codes),
        },
    )
    return RecoveryCodesOut(
        codes=codes, generated_at=operator.mfa_recovery_codes_generated_at
    )


# --------------------------------------------------------------------------- #
# Login completion
# --------------------------------------------------------------------------- #
@router.post("/auth/mfa/login/options", response_model=AuthenticationOptionsOut)
async def login_options(
    operator: Operator = Depends(get_mfa_pending_operator),
    db: AsyncSession = Depends(get_db),
):
    """Begin the second-factor step of a login."""
    return await _assertion_options(
        db, operator, purpose=WebAuthnChallengePurpose.authentication
    )


@router.post("/auth/mfa/step-up/options", response_model=AuthenticationOptionsOut)
async def step_up_options(
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """Begin a step-up re-assertion for an already-authenticated session."""
    return await _assertion_options(
        db, operator, purpose=WebAuthnChallengePurpose.step_up
    )


async def _assertion_options(
    db: AsyncSession, operator: Operator, *, purpose: WebAuthnChallengePurpose
) -> AuthenticationOptionsOut:
    relying_party = _require_enabled()
    from app.core.config import settings

    descriptors = await _credential_descriptors(db, operator.id)
    if not descriptors:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "enrollment_required"},
        )

    _, raw_challenge = await mfa.issue_challenge(
        db,
        operator_id=operator.id,
        purpose=purpose,
        rp_id=relying_party.rp_id,
    )
    return AuthenticationOptionsOut(
        challenge=b64url_encode(raw_challenge),
        rpId=relying_party.rp_id,
        timeout=_ceremony_timeout_ms(),
        allowCredentials=descriptors,
        userVerification=(
            "required" if settings.mfa_require_user_verification else "preferred"
        ),
    )


async def _verify_assertion_for(
    db: AsyncSession,
    request: Request,
    operator: Operator,
    body: AssertionVerification,
    *,
    purpose: WebAuthnChallengePurpose,
    method: str,
) -> WebAuthnCredential:
    """Shared assertion path for login completion and step-up.

    Both ceremonies prove the same thing about the same credential; only the
    challenge purpose and what the caller does with the result differ. Keeping
    one implementation means a fix to the replay, counter, or rate-limit
    handling cannot land in one path and be forgotten in the other.
    """
    relying_party = _require_enabled()
    from app.core.config import settings

    _enforce_rate_limit(request, operator)
    limit_key = _rate_limit_key(request, operator)

    async def fail(reason: str, code_status: int = status.HTTP_401_UNAUTHORIZED):
        mfa.mfa_limiter.record_failure(limit_key)
        await _audit_failure(db, request, operator, method=method, reason=reason)
        await db.commit()
        raise HTTPException(status_code=code_status, detail=_GENERIC_FAILURE)

    challenge = await mfa.consume_challenge(
        db, operator_id=operator.id, purpose=purpose
    )
    if challenge is None:
        # Covers no challenge, an expired one, and — critically — a replay of an
        # assertion whose challenge was already spent.
        await fail("challenge_not_found")

    credential = None
    for candidate in await mfa.active_credentials(db, operator.id):
        if candidate.credential_id == body.credential_id:
            credential = candidate
            break
    if credential is None:
        # Same generic outcome as a bad signature: a caller holding a stolen
        # password must not learn which credential IDs are real.
        await fail("unknown_credential")

    try:
        result = verify_assertion(
            client_data_json=_decode_field(
                body.client_data_json, "malformed_client_data"
            ),
            authenticator_data=_decode_field(
                body.authenticator_data, "malformed_authenticator_data"
            ),
            signature=_decode_field(body.signature, "malformed_signature"),
            expected_challenge=b64url_decode(challenge.challenge),
            expected_origins=relying_party.origins,
            expected_rp_id=challenge.rp_id,
            credential_public_key_cose=b64url_decode(credential.public_key_cose),
            stored_sign_count=credential.sign_count,
            require_user_verification=settings.mfa_require_user_verification,
        )
    except WebAuthnError as exc:
        await fail(exc.code)

    credential.sign_count = result.sign_count
    credential.last_used_at = datetime.now(timezone.utc)
    credential.backup_state = result.backup_state
    mfa.mfa_limiter.clear(limit_key)
    return credential


@router.post("/auth/mfa/login/verify", response_model=LoginResponse)
async def complete_login_with_webauthn(
    body: AssertionVerification,
    request: Request,
    operator: Operator = Depends(get_mfa_pending_operator),
    db: AsyncSession = Depends(get_db),
):
    """Finish a login by presenting a registered authenticator."""
    credential = await _verify_assertion_for(
        db,
        request,
        operator,
        body,
        purpose=WebAuthnChallengePurpose.authentication,
        method="webauthn",
    )
    now = datetime.now(timezone.utc)
    await audit.record(
        db,
        action="mfa.authentication_succeeded",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": operator.id,
            "credential_id": credential.id,
            "method": "webauthn",
            "purpose": "login",
        },
    )
    # A fresh assertion *is* a step-up, so the session starts able to perform
    # sensitive operations without immediately asserting again.
    session = await sessions.create(
        db,
        operator,
        auth_methods=(AMR_PASSWORD, AMR_WEBAUTHN),
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    token = create_access_token(
        subject=operator.id,
        generation=operator.token_generation,
        amr=(AMR_PASSWORD, AMR_WEBAUTHN),
        step_up_at=now,
        session_id=session.id,
    )
    return LoginResponse(access_token=token)


@router.post("/auth/mfa/login/recovery-code", response_model=LoginResponse)
async def complete_login_with_recovery_code(
    body: RecoveryCodeVerification,
    request: Request,
    operator: Operator = Depends(get_mfa_pending_operator),
    db: AsyncSession = Depends(get_db),
):
    """Finish a login with a single-use recovery code (device loss).

    The resulting session is deliberately weaker than a WebAuthn one: it carries
    no step-up, so it can enrol a replacement authenticator but cannot revoke
    devices, mint new recovery codes, or touch another operator's account.
    """
    _require_enabled()
    _enforce_rate_limit(request, operator)
    limit_key = _rate_limit_key(request, operator)

    used = await mfa.consume_recovery_code(
        db, operator_id=operator.id, presented=body.code
    )
    if used is None:
        mfa.mfa_limiter.record_failure(limit_key)
        await _audit_failure(
            db, request, operator, method="recovery_code", reason="invalid_code"
        )
        await db.commit()
        raise _ceremony_failed()

    mfa.mfa_limiter.clear(limit_key)
    remaining = await mfa.unused_recovery_code_count(db, operator.id)
    await audit.record(
        db,
        action="mfa.recovery_code_used",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={"operator_id": operator.id, "codes_remaining": remaining},
    )
    session = await sessions.create(
        db,
        operator,
        auth_methods=(AMR_PASSWORD, AMR_RECOVERY_CODE),
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    token = create_access_token(
        subject=operator.id,
        generation=operator.token_generation,
        amr=(AMR_PASSWORD, AMR_RECOVERY_CODE),
        session_id=session.id,
    )
    return LoginResponse(access_token=token)


@router.post("/auth/mfa/step-up/verify", response_model=LoginResponse)
async def complete_step_up(
    body: AssertionVerification,
    request: Request,
    operator: Operator = Depends(get_current_operator),
    db: AsyncSession = Depends(get_db),
):
    """Re-assert an authenticator and receive a session that satisfies step-up.

    Returns a *new* token rather than mutating the old one, because the step-up
    fact lives in the signed claims. The previous token stays valid until it
    expires; it simply cannot perform step-up-gated operations.
    """
    credential = await _verify_assertion_for(
        db,
        request,
        operator,
        body,
        purpose=WebAuthnChallengePurpose.step_up,
        method="step_up",
    )
    now = datetime.now(timezone.utc)
    await audit.record(
        db,
        action="mfa.step_up_succeeded",
        actor=operator.email,
        actor_user_id=operator.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={"operator_id": operator.id, "credential_id": credential.id},
    )
    amr = set(getattr(operator, "session_amr", None) or set())
    amr.update({AMR_PASSWORD, AMR_WEBAUTHN})
    # Re-asserting strengthens the session the caller already holds; it must not
    # open a second one, or every step-up would leave a stale entry in the
    # operator's own inventory.
    existing = getattr(operator, "session_record", None)
    token = create_access_token(
        subject=operator.id,
        generation=operator.token_generation,
        amr=tuple(sorted(amr)),
        step_up_at=now,
        session_id=existing.id if existing is not None else None,
    )
    return LoginResponse(access_token=token)


# --------------------------------------------------------------------------- #
# Administrative reset
# --------------------------------------------------------------------------- #
@router.post("/auth/operators/{operator_id}/mfa/reset", response_model=MfaResetOut)
async def reset_operator_mfa(
    operator_id: str,
    body: MfaReset,
    request: Request,
    admin: Operator = Depends(require_role(OperatorRole.admin)),
    _step_up: Operator = Depends(require_step_up),
    db: AsyncSession = Depends(get_db),
):
    """Clear every second factor for an operator who lost their devices.

    This is the most dangerous operation in the module — it demotes an account
    to password-only — so it carries the most conditions: admin role, a step-up
    on the *administrator's* own session, a mandatory reason, and an audit event
    naming who did it to whom. Existing sessions for the target are revoked too,
    because the point of a reset is to establish a known state, and a session
    minted before it is not part of that state.
    """
    _require_enabled()
    target = await db.get(Operator, operator_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Operator not found")

    credentials_revoked, codes_invalidated = await mfa.revoke_all_factors(
        db, target, reason="admin_reset"
    )
    target.token_generation += 1
    await audit.record(
        db,
        action="mfa.reset",
        actor=admin.email,
        actor_user_id=admin.id,
        source_ip=client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500] or None,
        detail={
            "operator_id": target.id,
            "credentials_revoked": credentials_revoked,
            "recovery_codes_invalidated": codes_invalidated,
            "reason": body.reason,
            "by": "admin",
        },
    )
    return MfaResetOut(
        operator_id=target.id,
        credentials_revoked=credentials_revoked,
        recovery_codes_invalidated=codes_invalidated,
    )
