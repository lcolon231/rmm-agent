# SPDX-License-Identifier: AGPL-3.0-only
"""Break-glass emergency access (issue #69).

Every other authentication control in this system is designed to fail closed.
That is correct, and it creates a problem this module exists to solve: the
controls can fail closed *on the operator*. An administrator whose only
authenticator is lost, a federation outage, a misconfigured relying-party ID --
each leaves a deployment that manages an entire fleet with nobody able to sign
in to fix it.

A break-glass credential is the deliberate exception. It is a single
high-entropy secret that works with nothing else: no second factor, no email,
no hardware. That is precisely what makes it useful in an emergency and
precisely what makes it dangerous, so the design does not pretend otherwise.
Instead of bounding it with another factor -- which would reintroduce the
failure it exists to survive -- it is bounded three other ways:

* **Blast radius by time.** An activation opens a session with its own, much
  shorter absolute lifetime (``break_glass_session_lifetime_seconds``).
* **Blast radius by noise.** Activation is never quiet. It writes an audit
  event, marks the session, and opens a review row that stays open until a
  human closes it, so "was every emergency access accounted for?" is answered
  from data rather than memory.
* **Blast radius by provisioning.** Credentials are minted deliberately by a
  platform admin, shown once, and bound to a dedicated operator row whose
  password hash is unusable -- so the identity can never be reached by ordinary
  password login, and disabling break-glass never disturbs a real person's
  account.

What this module does *not* do is hide the trade-off. A stolen sealed envelope
is a full compromise of the deployment. Rotation, disablement, and the review
queue are the operational answers; the documentation says so plainly.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.ratelimit import LoginRateLimiter
from app.models.models import (
    BreakGlassAccount,
    BreakGlassActivation,
    Operator,
    OperatorRole,
)

#: Credential shape. A visible prefix makes a leaked value obvious in a paste or
#: a log line, and tells an operator what they are holding. The secret half is
#: 32 bytes of URL-safe randomness (~256 bits).
CREDENTIAL_PREFIX = "nlbg_"
_SECRET_BYTES = 32

#: Break-glass activation is unauthenticated by necessity -- requiring a session
#: to reach the escape hatch for "nobody can get a session" would be circular --
#: so it gets its own limiter, tighter than login. Keyed on source IP alone,
#: because unlike login there is no user-supplied identity to pair it with.
activation_limiter = LoginRateLimiter(
    max_failures=settings.break_glass_max_attempts,
    window_seconds=settings.break_glass_window_seconds,
)

#: A password hash no password can produce, so the dedicated break-glass
#: operator row can never be reached through ``/auth/login``. bcrypt verification
#: of any candidate against this string fails, and it is not a valid bcrypt hash
#: to begin with, so ``verify_password`` returns False on the ValueError path.
UNUSABLE_PASSWORD_HASH = "!break-glass-no-password-login!"


class BreakGlassDisabled(RuntimeError):
    """Break-glass is switched off for this deployment."""


@dataclass(frozen=True)
class ActivationResult:
    account: BreakGlassAccount
    operator: Operator
    activation: BreakGlassActivation


def generate_credential() -> str:
    return CREDENTIAL_PREFIX + secrets.token_urlsafe(_SECRET_BYTES)


def fingerprint(credential: str) -> str:
    """Non-authenticating identifier safe to show to administrators.

    Domain-separated from the stored verifier so that displaying a fingerprint
    can never help anyone derive the credential or the bcrypt hash -- the same
    reasoning as ``security.credential_fingerprint`` for agent tokens.
    """
    digest = hashlib.sha256(
        f"nodelink-break-glass-fingerprint:{credential}".encode("utf-8")
    ).hexdigest()
    return digest[:32]


def _hash(credential: str) -> str:
    return bcrypt.hashpw(credential.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def _verify(credential: str, credential_hash: str) -> bool:
    try:
        return bcrypt.checkpw(credential.encode("utf-8"), credential_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def ensure_enabled(config: Settings = settings) -> None:
    if not config.break_glass_enabled:
        raise BreakGlassDisabled(
            "Break-glass access is disabled for this deployment "
            "(BREAK_GLASS_ENABLED=false)."
        )


# --------------------------------------------------------------------------- #
# Provisioning
# --------------------------------------------------------------------------- #
async def create_account(
    db: AsyncSession,
    *,
    label: str,
    created_by_email: str | None,
    role: OperatorRole = OperatorRole.admin,
    is_platform_admin: bool = True,
) -> tuple[BreakGlassAccount, str]:
    """Provision a break-glass identity. Returns the account and its credential.

    The plaintext credential is returned exactly once, to exactly one caller,
    and is never stored, logged, or auditable. The dedicated operator row is
    created here rather than reusing an existing person's account so that the
    emergency identity has no other way in and no other purpose.
    """
    credential = generate_credential()
    operator = Operator(
        email=f"break-glass+{secrets.token_hex(8)}@nodelink.invalid",
        password_hash=UNUSABLE_PASSWORD_HASH,
        role=role,
        is_platform_admin=is_platform_admin,
    )
    db.add(operator)
    await db.flush()

    account = BreakGlassAccount(
        operator_id=operator.id,
        label=label,
        credential_hash=_hash(credential),
        credential_fingerprint=fingerprint(credential),
        created_by_email=created_by_email,
    )
    db.add(account)
    await db.flush()
    return account, credential


async def rotate_credential(db: AsyncSession, account: BreakGlassAccount) -> str:
    """Replace the credential. The previous value stops working immediately.

    Rotation is the response to a suspected envelope compromise and to routine
    hygiene alike, so it is deliberately cheap and does not disturb the account
    identity, its history, or its review records.
    """
    credential = generate_credential()
    account.credential_hash = _hash(credential)
    account.credential_fingerprint = fingerprint(credential)
    account.rotated_at = datetime.now(timezone.utc)
    await db.flush()
    return credential


async def set_disabled(
    db: AsyncSession,
    account: BreakGlassAccount,
    *,
    disabled: bool,
    reason: str | None,
) -> None:
    """Disable or re-enable an account without deleting its history."""
    account.disabled_at = datetime.now(timezone.utc) if disabled else None
    account.disabled_reason = (reason or "")[:200] if disabled else None
    # The identity itself is disabled in lock-step, so a disabled envelope
    # cannot authenticate even if a future code path forgets to check the
    # account row. Loaded explicitly rather than through `account.operator`:
    # a lazy relationship load inside async code raises MissingGreenlet.
    operator = await db.get(Operator, account.operator_id)
    if operator is not None:
        operator.disabled = disabled
    await db.flush()


# --------------------------------------------------------------------------- #
# Activation
# --------------------------------------------------------------------------- #
async def activate(
    db: AsyncSession,
    *,
    credential: str,
    reason: str,
    source_ip: str | None,
    user_agent: str | None,
) -> ActivationResult | None:
    """Verify a credential and record the activation, or return None.

    Credentials are bcrypt-hashed with per-row salts, so there is no digest to
    look up and every enabled account must be checked. That scan is bounded by
    the number of break-glass accounts a deployment provisions -- a handful, by
    construction -- and further bounded by the rate limiter the caller applies,
    so it is not a denial-of-service lever. It also means verification cost does
    not depend on which envelope was opened.

    Returns None for an unknown credential, a disabled account, and a malformed
    value alike. The caller renders all three identically.
    """
    if not credential.startswith(CREDENTIAL_PREFIX):
        # Cheap structural reject. Not a security boundary -- the bcrypt check
        # below is -- but it avoids hashing obvious noise.
        return None

    accounts = list(
        (
            await db.execute(
                select(BreakGlassAccount)
                .where(BreakGlassAccount.disabled_at.is_(None))
                .order_by(BreakGlassAccount.created_at, BreakGlassAccount.id)
            )
        ).scalars()
    )

    matched: BreakGlassAccount | None = None
    for account in accounts:
        if _verify(credential, account.credential_hash):
            matched = account
            break
    if matched is None:
        return None

    operator = await db.get(Operator, matched.operator_id)
    if operator is None or operator.disabled:
        return None

    now = datetime.now(timezone.utc)
    matched.last_activated_at = now
    matched.activation_count += 1
    activation = BreakGlassActivation(
        account_id=matched.id,
        activated_at=now,
        source_ip=source_ip,
        user_agent=(user_agent or "")[:500] or None,
        reason=reason,
    )
    db.add(activation)
    await db.flush()
    return ActivationResult(account=matched, operator=operator, activation=activation)


# --------------------------------------------------------------------------- #
# Review
# --------------------------------------------------------------------------- #
async def unreviewed_count(db: AsyncSession) -> int:
    """How many activations still await a human sign-off."""
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(BreakGlassActivation)
                .where(BreakGlassActivation.reviewed_at.is_(None))
            )
        ).scalar_one()
    )


async def list_activations(
    db: AsyncSession, *, unreviewed_only: bool = False, limit: int = 100
) -> list[BreakGlassActivation]:
    query = select(BreakGlassActivation)
    if unreviewed_only:
        query = query.where(BreakGlassActivation.reviewed_at.is_(None))
    query = query.order_by(BreakGlassActivation.activated_at.desc()).limit(limit)
    return list((await db.execute(query)).scalars().all())


async def review(
    db: AsyncSession,
    activation: BreakGlassActivation,
    *,
    reviewed_by_email: str,
    note: str,
) -> bool:
    """Close one activation. Returns False if it was already reviewed.

    Re-reviewing is refused rather than silently overwritten: the first
    sign-off is the accountable one, and letting a later reviewer replace it
    would make the record less trustworthy, not more.
    """
    if activation.reviewed_at is not None:
        return False
    activation.reviewed_at = datetime.now(timezone.utc)
    activation.reviewed_by_email = reviewed_by_email
    activation.review_note = note
    await db.flush()
    return True
