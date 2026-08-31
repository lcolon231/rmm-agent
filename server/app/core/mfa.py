# SPDX-License-Identifier: AGPL-3.0-only
"""MFA policy, challenge lifecycle, and recovery codes (issue #67).

``app.core.webauthn`` decides whether a set of bytes is a valid ceremony.
This module decides everything that depends on *state*: which relying-party
identity a ceremony must be scoped to, whether a challenge is still spendable,
whether a given operator is required to hold a second factor, and what a session
is permitted to do given how it authenticated.

Three properties are worth stating outright, because they are the ones a
reviewer should check rather than take on trust.

**Replay protection is a database decision, not a cryptographic one.** A signed
assertion is valid forever unless something remembers that it was already spent.
:func:`consume_challenge` is that something: it atomically claims the row, so
exactly one of two concurrent replays can win.

**Enforcement fails closed on the state it can see.** An operator who holds an
active credential must use it — that is decided from the credential rows, not
from a flag someone could forget to set. Policy configuration can only *widen*
the set of operators who must enrol; it can never excuse an enrolled operator
from their second factor.

**Recovery is a way back in, not a way up.** A recovery code proves possession of
something the operator wrote down. It restores access and permits enrolling a
replacement authenticator, but it never satisfies step-up, so it cannot be used
to revoke devices, mint new recovery codes, or change another operator's
account. An attacker who steals the printed codes gets the account's read/write
surface, not the ability to lock the real owner out of it.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import bcrypt
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.ratelimit import LoginRateLimiter
from app.core.security import (
    AMR_RECOVERY_CODE,
    AMR_WEBAUTHN,
)
from app.core.webauthn import b64url_encode, generate_challenge
from app.models.models import (
    MfaRecoveryCode,
    Operator,
    OperatorRole,
    WebAuthnChallenge,
    WebAuthnChallengePurpose,
    WebAuthnCredential,
)

# Enforcement positions, in increasing strictness. See config.py for what each
# one is for during a rollout.
ENFORCEMENT_OFF = "off"
ENFORCEMENT_OPTIONAL = "optional"
ENFORCEMENT_REQUIRED = "required"
_ENFORCEMENT_VALUES = (ENFORCEMENT_OFF, ENFORCEMENT_OPTIONAL, ENFORCEMENT_REQUIRED)

# Mirrors app.api.deps._ROLE_RANK. Duplicated rather than imported because deps
# imports this module; the two are asserted equal by the test suite.
_ROLE_RANK = {
    OperatorRole.readonly: 0,
    OperatorRole.operator: 1,
    OperatorRole.admin: 2,
}

#: Recovery codes are shown once and typed by a human, so they use an
#: unambiguous alphabet: no 0/O, no 1/I/L. 20 characters from a 32-symbol
#: alphabet is 100 bits of entropy, which is far beyond brute-forceable even
#: without the rate limit that also guards them.
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_RECOVERY_GROUP_SIZE = 5
_RECOVERY_GROUPS = 4

#: Second-factor attempts are rate limited separately from passwords: the two
#: guard different secrets, and letting failed assertions consume the password
#: budget would let an attacker lock out a victim's password attempts.
mfa_limiter = LoginRateLimiter(
    max_failures=settings.mfa_max_failures,
    window_seconds=settings.mfa_window_seconds,
)


class MfaConfigurationError(RuntimeError):
    """The relying-party identity cannot be resolved from configuration."""


@dataclass(frozen=True)
class RelyingParty:
    """The WebAuthn scope every ceremony on this deployment is bound to."""

    rp_id: str
    rp_name: str
    origins: frozenset[str]


# --------------------------------------------------------------------------- #
# Relying-party configuration
# --------------------------------------------------------------------------- #
def relying_party(config: Settings = settings) -> RelyingParty:
    """Resolve the RP ID, display name, and accepted origins.

    ``config`` defaults to the process settings but is injectable so the
    production-startup validator can check the instance it was handed rather
    than the global singleton -- otherwise it would validate the wrong object
    and pass a deployment it had never actually examined.

    Derivation from ``public_base_url`` is the default because a deployment that
    already declares its public URL has, in effect, already declared its RP ID,
    and two independently-configured values would eventually disagree — at which
    point every credential silently stops working. An explicit ``mfa_rp_id`` is
    still supported for the parent-domain case.

    Raises :class:`MfaConfigurationError` when neither is available, which is
    what makes a misconfigured deployment refuse to run MFA ceremonies rather
    than run them under a guessed scope.
    """
    configured_id = (config.mfa_rp_id or "").strip().lower()
    base_url = (config.public_base_url or "").strip()

    rp_id = configured_id
    derived_origin: str | None = None
    if base_url:
        parsed = urlparse(base_url)
        if parsed.hostname:
            derived_origin = f"{parsed.scheme}://{parsed.netloc}"
            if not rp_id:
                rp_id = parsed.hostname.lower()

    if not rp_id:
        raise MfaConfigurationError(
            "WebAuthn requires a relying-party ID. Set PUBLIC_BASE_URL (preferred) "
            "or MFA_RP_ID."
        )

    configured_origins = [
        origin.strip().rstrip("/")
        for origin in (config.mfa_allowed_origins or "").split(",")
        if origin.strip()
    ]
    origins = set(configured_origins)
    if derived_origin:
        origins.add(derived_origin.rstrip("/"))
    if not origins:
        raise MfaConfigurationError(
            "WebAuthn requires at least one accepted origin. Set PUBLIC_BASE_URL "
            "(preferred) or MFA_ALLOWED_ORIGINS."
        )

    return RelyingParty(
        rp_id=rp_id,
        rp_name=(config.mfa_rp_name or config.app_name),
        origins=frozenset(origins),
    )


def enforcement_mode(config: Settings = settings) -> str:
    """Return the configured enforcement position, failing closed on garbage.

    An unrecognised value resolves to ``optional`` rather than ``off``: a typo in
    a deployment variable must not silently disable a security control for
    operators who have already enrolled.
    """
    value = (config.mfa_enforcement or "").strip().lower()
    return value if value in _ENFORCEMENT_VALUES else ENFORCEMENT_OPTIONAL


def _required_minimum_role(config: Settings = settings) -> OperatorRole:
    value = (config.mfa_required_minimum_role or "").strip().lower()
    try:
        return OperatorRole(value)
    except ValueError:
        # Same fail-closed reasoning: an unreadable value narrows to the
        # strictest sensible default rather than exempting everyone.
        return OperatorRole.admin


def enrollment_is_required(operator: Operator) -> bool:
    """Whether policy obliges this operator to hold a second factor."""
    if enforcement_mode() != ENFORCEMENT_REQUIRED:
        return False
    return _ROLE_RANK[operator.role] >= _ROLE_RANK[_required_minimum_role()]


# --------------------------------------------------------------------------- #
# Credential queries
# --------------------------------------------------------------------------- #
async def active_credentials(
    db: AsyncSession, operator_id: str
) -> list[WebAuthnCredential]:
    """Every credential that may currently authenticate this operator."""
    result = await db.execute(
        select(WebAuthnCredential)
        .where(
            WebAuthnCredential.operator_id == operator_id,
            WebAuthnCredential.revoked_at.is_(None),
        )
        .order_by(WebAuthnCredential.created_at, WebAuthnCredential.id)
    )
    return list(result.scalars().all())


async def active_credential_count(db: AsyncSession, operator_id: str) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(WebAuthnCredential)
        .where(
            WebAuthnCredential.operator_id == operator_id,
            WebAuthnCredential.revoked_at.is_(None),
        )
    )
    return int(result.scalar_one())


async def has_active_credential(db: AsyncSession, operator_id: str) -> bool:
    return await active_credential_count(db, operator_id) > 0


async def unused_recovery_code_count(db: AsyncSession, operator_id: str) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.operator_id == operator_id,
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    return int(result.scalar_one())


# --------------------------------------------------------------------------- #
# Login decision
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LoginDecision:
    """What a correct password entitles this operator to, before any factor."""

    #: A second factor must be presented before a usable session is issued.
    second_factor_required: bool
    #: The operator must enrol an authenticator before doing anything else.
    enrollment_required: bool
    #: Methods the operator may complete the login with.
    methods: tuple[str, ...]


async def decide_login(db: AsyncSession, operator: Operator) -> LoginDecision:
    """Decide the post-password state for an authenticated operator.

    The ordering matters and is deliberate:

    1. If enforcement is ``off``, MFA does not participate at all. This is the
       documented rollback position and must behave exactly like the previous
       build, including for operators who have credentials on file.
    2. Otherwise, an operator who *has* an active credential must use it. This
       is decided from data, not policy, so it cannot be turned off by a
       configuration mistake short of the explicit ``off`` position above.
    3. Otherwise, an operator whom policy *requires* to enrol gets a restricted
       session that can only enrol. Refusing the login outright would strand
       them with no way to comply.
    """
    if enforcement_mode() == ENFORCEMENT_OFF:
        return LoginDecision(False, False, ())

    if await has_active_credential(db, operator.id):
        methods = ["webauthn"]
        if await unused_recovery_code_count(db, operator.id) > 0:
            methods.append("recovery_code")
        return LoginDecision(True, False, tuple(methods))

    if enrollment_is_required(operator):
        return LoginDecision(True, True, ("enrollment",))

    return LoginDecision(False, False, ())


# --------------------------------------------------------------------------- #
# Session capability
# --------------------------------------------------------------------------- #
def session_is_mfa_verified(amr: frozenset[str]) -> bool:
    """Whether the session presented any second factor at login."""
    return bool(amr & {AMR_WEBAUTHN, AMR_RECOVERY_CODE})


def step_up_is_fresh(amr: frozenset[str], step_up_at: datetime | None) -> bool:
    """Whether the session recently proved possession of an authenticator.

    Only a WebAuthn assertion counts. A recovery code is explicitly excluded:
    it is a written-down bearer secret, so allowing it to satisfy step-up would
    make the strongest gate in the system only as strong as the weakest one.
    """
    if AMR_WEBAUTHN not in amr or step_up_at is None:
        return False
    max_age = timedelta(seconds=settings.mfa_step_up_max_age_seconds)
    return datetime.now(timezone.utc) - step_up_at <= max_age


# --------------------------------------------------------------------------- #
# Challenges
# --------------------------------------------------------------------------- #
async def issue_challenge(
    db: AsyncSession,
    *,
    operator_id: str,
    purpose: WebAuthnChallengePurpose,
    rp_id: str,
) -> tuple[WebAuthnChallenge, bytes]:
    """Mint, persist, and return a single-use challenge and its raw bytes.

    Any outstanding challenge for the same operator and purpose is retired
    first. Without that, starting a ceremony twice would leave two spendable
    challenges, and abandoning one would leave a valid credential-shaped secret
    lying around for its whole TTL.
    """
    now = datetime.now(timezone.utc)
    await db.execute(
        update(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.operator_id == operator_id,
            WebAuthnChallenge.purpose == purpose,
            WebAuthnChallenge.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )

    raw = generate_challenge()
    challenge = WebAuthnChallenge(
        operator_id=operator_id,
        purpose=purpose,
        challenge=b64url_encode(raw),
        rp_id=rp_id,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.mfa_challenge_ttl_seconds),
    )
    db.add(challenge)
    await db.flush()
    return challenge, raw


async def consume_challenge(
    db: AsyncSession,
    *,
    operator_id: str,
    purpose: WebAuthnChallengePurpose,
) -> WebAuthnChallenge | None:
    """Atomically claim the operator's outstanding challenge for `purpose`.

    The UPDATE is the whole point: it moves an unconsumed, unexpired row to
    consumed in one statement, so two concurrent replays of the same assertion
    cannot both find it spendable. Returning the row (rather than a boolean)
    hands the caller the challenge bytes and the RP ID that were in force when
    it was minted, so verification is checked against the ceremony's own scope
    rather than whatever configuration says right now.
    """
    now = datetime.now(timezone.utc)
    candidate = (
        await db.execute(
            select(WebAuthnChallenge.id)
            .where(
                WebAuthnChallenge.operator_id == operator_id,
                WebAuthnChallenge.purpose == purpose,
                WebAuthnChallenge.consumed_at.is_(None),
                WebAuthnChallenge.expires_at > now,
            )
            .order_by(WebAuthnChallenge.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if candidate is None:
        return None

    claimed = await db.execute(
        update(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.id == candidate,
            WebAuthnChallenge.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )
    if claimed.rowcount != 1:
        # Another request claimed it between the SELECT and the UPDATE. That is
        # exactly the replay this function exists to stop.
        return None
    return await db.get(WebAuthnChallenge, candidate)


async def purge_expired_challenges(db: AsyncSession, *, limit: int = 1000) -> int:
    """Delete spent and expired challenge rows. Returns how many were removed.

    Challenges carry no accountability value once they cannot be spent — the
    audit chain already records every ceremony — so unlike audit data they are
    deleted rather than retained.
    """
    now = datetime.now(timezone.utc)
    stale = (
        await db.execute(
            select(WebAuthnChallenge.id)
            .where(WebAuthnChallenge.expires_at <= now)
            .limit(limit)
        )
    ).scalars().all()
    if not stale:
        return 0
    from sqlalchemy import delete

    await db.execute(
        delete(WebAuthnChallenge).where(WebAuthnChallenge.id.in_(list(stale)))
    )
    return len(stale)


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #
def _format_recovery_code() -> str:
    groups = [
        "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_SIZE))
        for _ in range(_RECOVERY_GROUPS)
    ]
    return "-".join(groups)


def normalize_recovery_code(value: str) -> str:
    """Normalise user-typed input to the stored form.

    Humans retype these from paper, so case and separators are forgiven. Nothing
    else is: the alphabet excludes look-alike characters precisely so we do not
    have to guess what someone meant.
    """
    return "".join(
        character
        for character in value.strip().upper()
        if character in _RECOVERY_ALPHABET
    )


def _hash_recovery_code(code: str) -> str:
    # bcrypt, not a bare SHA-256. A recovery code is a human-held secret with a
    # human-scale format, so it gets password-grade storage even though its
    # entropy is high — the cost is paid once per recovery, never in a hot path.
    return bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def _verify_recovery_code(code: str, code_hash: str) -> bool:
    try:
        return bcrypt.checkpw(code.encode("utf-8"), code_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


async def replace_recovery_codes(
    db: AsyncSession, operator: Operator
) -> tuple[str, list[str]]:
    """Mint a fresh batch, invalidating the previous one. Returns (batch_id, codes).

    The plaintext codes are returned exactly once, to exactly one caller, and are
    never stored, logged, or auditable. Deleting the old batch rather than
    marking it superseded is intentional: an unused code from a retired batch is
    a live credential, and the only safe state for it is "gone".
    """
    from sqlalchemy import delete

    await db.execute(
        delete(MfaRecoveryCode).where(MfaRecoveryCode.operator_id == operator.id)
    )

    batch_id = secrets.token_hex(16)
    now = datetime.now(timezone.utc)
    codes = [_format_recovery_code() for _ in range(settings.mfa_recovery_code_count)]
    for code in codes:
        db.add(
            MfaRecoveryCode(
                operator_id=operator.id,
                batch_id=batch_id,
                code_hash=_hash_recovery_code(normalize_recovery_code(code)),
                created_at=now,
            )
        )
    operator.mfa_recovery_codes_generated_at = now
    await db.flush()
    return batch_id, codes


async def consume_recovery_code(
    db: AsyncSession, *, operator_id: str, presented: str
) -> MfaRecoveryCode | None:
    """Spend one unused recovery code, or return None.

    Codes are bcrypt-hashed with per-row salts, so there is no digest to look up
    — every unused row must be checked. That is bounded by
    ``mfa_recovery_code_count`` (10 by default) and further bounded by the rate
    limiter the caller applies, so the linear scan is not a denial-of-service
    lever. The row is claimed with a conditional UPDATE for the same reason
    challenges are: two concurrent presentations of one code must not both win.
    """
    normalized = normalize_recovery_code(presented)
    if not normalized:
        return None

    rows = (
        await db.execute(
            select(MfaRecoveryCode)
            .where(
                MfaRecoveryCode.operator_id == operator_id,
                MfaRecoveryCode.used_at.is_(None),
            )
            .order_by(MfaRecoveryCode.created_at, MfaRecoveryCode.id)
        )
    ).scalars().all()

    for row in rows:
        if not _verify_recovery_code(normalized, row.code_hash):
            continue
        now = datetime.now(timezone.utc)
        claimed = await db.execute(
            update(MfaRecoveryCode)
            .where(MfaRecoveryCode.id == row.id, MfaRecoveryCode.used_at.is_(None))
            .values(used_at=now)
        )
        if claimed.rowcount != 1:
            return None
        row.used_at = now
        return row
    return None


async def revoke_all_factors(
    db: AsyncSession, operator: Operator, *, reason: str
) -> tuple[int, int]:
    """Clear every second factor for an operator. Returns (credentials, codes).

    This is the device-loss escape hatch. It deliberately removes recovery codes
    as well as authenticators: leaving codes behind after an administrator has
    reset an account would mean the reset did not actually establish a known
    state, which is the only thing that makes the reset trustworthy as evidence.
    """
    from sqlalchemy import delete

    now = datetime.now(timezone.utc)
    revoked = await db.execute(
        update(WebAuthnCredential)
        .where(
            WebAuthnCredential.operator_id == operator.id,
            WebAuthnCredential.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoked_reason=reason)
    )
    codes = await db.execute(
        delete(MfaRecoveryCode).where(MfaRecoveryCode.operator_id == operator.id)
    )
    await db.execute(
        delete(WebAuthnChallenge).where(WebAuthnChallenge.operator_id == operator.id)
    )
    operator.mfa_recovery_codes_generated_at = None
    return int(revoked.rowcount or 0), int(codes.rowcount or 0)
