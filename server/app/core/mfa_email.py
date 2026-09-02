# SPDX-License-Identifier: AGPL-3.0-only
"""Email one-time-code second factor (issue #226).

``app.core.mfa`` owns the phishing-resistant factor and the policy that decides
who must hold one. This module owns the *weaker* factor that exists for the
operators who cannot: a numeric code mailed to the operator's own login address.

Four decisions here are deliberate, and a reviewer should check them rather than
take them on trust.

**This factor is not phishing-resistant, and the code says so.** WebAuthn binds
an assertion to an origin; the authenticator will not sign for a look-alike
domain. A mailed code has no such binding -- an operator lured to a convincing
page will read it out and type it in, and the attacker replays it inside the
validity window. Everything below is shaped by that fact: the factor is off by
default, it never satisfies step-up, and under the recommended policy it is
offered only to operators who hold no authenticator at all, so enabling it
cannot quietly downgrade an account that is already properly protected.

**The destination is not a choice.** Codes go to ``Operator.email`` and nowhere
else. An operator cannot nominate a different mailbox, so an attacker holding
only a password cannot point the factor at an inbox they control -- they need
the corporate mailbox too. The verified address is snapshotted on the factor so
that a later email change is *detectable*: once the snapshot stops matching, the
factor is no longer proven and stops counting.

**Sending is inline, not queued.** The alert pipeline in
``app.core.email_notifications`` is durable and retrying, which is right for a
message that still matters ten minutes late. A login code is the opposite: it is
single-use and expires in minutes, so a retry that lands after expiry is not a
recovery, it is a second live code sitting in a mailbox. This path therefore
sends once, synchronously, with a bounded timeout, and surfaces failure to the
caller instead of promising delivery it cannot confirm. It reuses that module's
provider boundary, so there is still exactly one place that talks to Resend.

**Six digits are safe only because of the counters around them.** 10^6 is not
much on its own. It is bounded by ``mfa_email_code_max_attempts`` per code, by
the send limiter that governs how many codes can exist per window, and by the
verification limiter shared with the rest of MFA. Raising the code's lifetime or
relaxing either limit without lengthening the code breaks that argument.
"""
from __future__ import annotations

import html
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import bcrypt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.email_notifications import (
    OutboundEmail,
    ProviderError,
    build_transactional_provider,
    mask_recipient,
)
from app.core.ratelimit import LoginRateLimiter
from app.models.models import (
    MfaEmailCode,
    MfaEmailCodePurpose,
    MfaEmailFactor,
    Operator,
)

# Policy positions. See config.py for what each one is for, and docs/MFA.md for
# the trade-off each one accepts.
POLICY_OFF = "off"
POLICY_FALLBACK_ONLY = "fallback_only"
POLICY_ALWAYS = "always"
_POLICY_VALUES = (POLICY_OFF, POLICY_FALLBACK_ONLY, POLICY_ALWAYS)

#: How far back a spent code is still recognised as *that* code rather than as
#: an unknown one. Bounded so the replay scan cannot grow without limit; the
#: window only has to outlast the code's own lifetime for a replay of a
#: just-used code to be reported as a replay.
_REPLAY_LOOKBACK_MULTIPLIER = 3

#: Sending is limited separately from verifying. They are different abuses --
#: flooding a mailbox versus guessing a code -- and a shared budget would let
#: either one exhaust the other's headroom.
email_send_limiter = LoginRateLimiter(
    max_failures=settings.mfa_email_send_max_per_window,
    window_seconds=settings.mfa_email_send_window_seconds,
)


class EmailDeliveryUnavailable(RuntimeError):
    """The provider could not be used, or refused the message.

    Carries a safe code only. Provider response bodies never reach the caller,
    the audit trail, or the operator.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
def policy_mode(config: Settings = settings) -> str:
    """The configured position, defaulting to ``off`` on anything unrecognised.

    An unparseable policy falls closed rather than open: a typo in this variable
    must not be the reason a deployment silently accepts a weaker factor.
    """
    value = (config.mfa_email_code_policy or "").strip().lower()
    return value if value in _POLICY_VALUES else POLICY_OFF


def factor_enabled(config: Settings = settings) -> bool:
    """Whether the email factor participates at all on this deployment."""
    return policy_mode(config) != POLICY_OFF


# --------------------------------------------------------------------------- #
# The factor itself
# --------------------------------------------------------------------------- #
def normalize_address(value: str) -> str:
    return (value or "").strip().lower()


async def get_factor(db: AsyncSession, operator_id: str) -> MfaEmailFactor | None:
    """The operator's factor row, verified or not. None if they have none."""
    return (
        await db.execute(
            select(MfaEmailFactor).where(MfaEmailFactor.operator_id == operator_id)
        )
    ).scalar_one_or_none()


def factor_is_usable(factor: MfaEmailFactor | None, operator: Operator) -> bool:
    """Whether this row is a factor *right now*.

    Two conditions, both necessary. It must have been verified -- an enrolment
    in progress is not a factor. And its snapshot must still match the
    operator's login address: if the account's email was changed after
    verification, nobody has proven control of the new mailbox, and continuing
    to mail codes there would be authorizing an address on no evidence.
    """
    if factor is None or factor.verified_at is None:
        return False
    return normalize_address(factor.address) == normalize_address(operator.email)


async def has_usable_factor(db: AsyncSession, operator: Operator) -> bool:
    return factor_is_usable(await get_factor(db, operator.id), operator)


async def begin_enrollment(db: AsyncSession, operator: Operator) -> MfaEmailFactor:
    """Create or reset the operator's factor row, unverified.

    Re-enrolling an existing factor deliberately clears ``verified_at`` first:
    until the new address is proven, the operator has no email factor at all.
    Leaving the old verification in place while a new address is pending would
    mean a window where an unproven address is already trusted.
    """
    factor = await get_factor(db, operator.id)
    now = datetime.now(timezone.utc)
    if factor is None:
        factor = MfaEmailFactor(
            operator_id=operator.id,
            address=normalize_address(operator.email),
            verified_at=None,
            created_at=now,
        )
        db.add(factor)
    else:
        factor.address = normalize_address(operator.email)
        factor.verified_at = None
    await db.flush()
    return factor


async def remove_factor(db: AsyncSession, operator: Operator) -> bool:
    """Delete the factor and invalidate every outstanding code. True if present.

    Unlike code rows, the factor itself is deleted rather than tombstoned: an
    address that is no longer a factor should leave nothing behind that a later
    bug could read as one.
    """
    factor = await get_factor(db, operator.id)
    await invalidate_codes(db, operator.id)
    if factor is None:
        return False
    await db.delete(factor)
    await db.flush()
    return True


# --------------------------------------------------------------------------- #
# Codes
# --------------------------------------------------------------------------- #
def _generate_code(config: Settings = settings) -> str:
    length = max(6, min(12, config.mfa_email_code_length))
    # secrets.randbelow over a zero-padded decimal: uniform across the whole
    # space including codes with leading zeros, which a naive randrange over
    # 100000..999999 would silently exclude and thereby shrink the space.
    return f"{secrets.randbelow(10 ** length):0{length}d}"


def normalize_code(value: str) -> str:
    """Strip whatever a mail client or a human put around the digits."""
    return "".join(character for character in (value or "") if character.isdigit())


def _hash_code(code: str) -> str:
    # bcrypt, matching recovery codes: a short, human-typed secret gets
    # password-grade storage. The cost is paid once per verification, never in a
    # hot path, and a leaked table must not yield a live code to an offline
    # search of a 10^6 space -- which a bare SHA-256 would.
    return bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def _verify_code(code: str, code_hash: str) -> bool:
    try:
        return bcrypt.checkpw(code.encode("utf-8"), code_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


async def invalidate_codes(
    db: AsyncSession,
    operator_id: str,
    *,
    purpose: MfaEmailCodePurpose | None = None,
) -> int:
    """Supersede every live code for this operator. Returns how many.

    Superseding rather than deleting keeps the row available to the replay scan,
    so presenting an invalidated code is still distinguishable from presenting
    one that never existed.
    """
    now = datetime.now(timezone.utc)
    conditions = [
        MfaEmailCode.operator_id == operator_id,
        MfaEmailCode.consumed_at.is_(None),
        MfaEmailCode.superseded_at.is_(None),
    ]
    if purpose is not None:
        conditions.append(MfaEmailCode.purpose == purpose)
    result = await db.execute(
        update(MfaEmailCode).where(*conditions).values(superseded_at=now)
    )
    return int(result.rowcount or 0)


async def issue_code(
    db: AsyncSession,
    operator: Operator,
    *,
    purpose: MfaEmailCodePurpose,
    config: Settings = settings,
) -> tuple[str, MfaEmailCode]:
    """Mint one code, invalidating any previous live code. Returns (plaintext, row).

    The plaintext is returned to exactly one caller, which mails it and drops
    it. It is never stored, logged, audited, or returned by any API.
    """
    await invalidate_codes(db, operator.id)
    now = datetime.now(timezone.utc)
    code = _generate_code(config)
    row = MfaEmailCode(
        operator_id=operator.id,
        purpose=purpose,
        code_hash=_hash_code(code),
        address=normalize_address(operator.email),
        attempts=0,
        created_at=now,
        expires_at=now + timedelta(seconds=config.mfa_email_code_ttl_seconds),
    )
    db.add(row)
    await db.flush()
    return code, row


@dataclass(frozen=True)
class ConsumeResult:
    """Why a presented code was or was not accepted.

    ``reason`` is for the audit trail and never for the caller: every failure is
    reported to the client as the same generic message, so a wrong code, an
    expired one, and a replay are indistinguishable from outside.
    """

    ok: bool
    reason: str


async def consume_code(
    db: AsyncSession,
    operator: Operator,
    *,
    presented: str,
    purpose: MfaEmailCodePurpose,
    config: Settings = settings,
) -> ConsumeResult:
    """Spend the operator's live code for ``purpose``, or explain the refusal.

    The row is claimed with a conditional UPDATE, exactly as WebAuthn challenges
    and recovery codes are: two concurrent presentations of one correct code
    must not both win, and only the database can arbitrate that.
    """
    normalized = normalize_code(presented)
    now = datetime.now(timezone.utc)

    live = (
        await db.execute(
            select(MfaEmailCode)
            .where(
                MfaEmailCode.operator_id == operator.id,
                MfaEmailCode.purpose == purpose,
                MfaEmailCode.consumed_at.is_(None),
                MfaEmailCode.superseded_at.is_(None),
            )
            .order_by(MfaEmailCode.created_at.desc())
        )
    ).scalars().all()

    for row in live:
        if row.expires_at.tzinfo is None:
            expires_at = row.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at = row.expires_at
        if expires_at <= now:
            row.superseded_at = now
            continue
        # An attempt is charged before the comparison, so an attacker cannot
        # avoid the counter by disconnecting on a wrong guess.
        row.attempts += 1
        exhausted = row.attempts >= config.mfa_email_code_max_attempts
        matched = bool(normalized) and _verify_code(normalized, row.code_hash)
        if not matched:
            if exhausted:
                row.superseded_at = now
                await db.flush()
                return ConsumeResult(False, "attempts_exhausted")
            await db.flush()
            return ConsumeResult(False, "invalid_code")
        # The address is re-checked at spend time, not only at send time: an
        # email change between the two must invalidate the code rather than
        # complete a login against a mailbox that is no longer the operator's.
        if normalize_address(row.address) != normalize_address(operator.email):
            row.superseded_at = now
            await db.flush()
            return ConsumeResult(False, "address_changed")
        claimed = await db.execute(
            update(MfaEmailCode)
            .where(
                MfaEmailCode.id == row.id,
                MfaEmailCode.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )
        if claimed.rowcount != 1:
            return ConsumeResult(False, "already_consumed")
        row.consumed_at = now
        return ConsumeResult(True, "accepted")

    # Nothing live matched. Distinguish a replay of a code this operator really
    # was issued from a value that was never a code, because the two mean very
    # different things to whoever reads the audit trail.
    if normalized:
        lookback = now - timedelta(
            seconds=config.mfa_email_code_ttl_seconds * _REPLAY_LOOKBACK_MULTIPLIER
        )
        spent = (
            await db.execute(
                select(MfaEmailCode)
                .where(
                    MfaEmailCode.operator_id == operator.id,
                    MfaEmailCode.purpose == purpose,
                    MfaEmailCode.created_at >= lookback,
                )
                .order_by(MfaEmailCode.created_at.desc())
                .limit(10)
            )
        ).scalars().all()
        for row in spent:
            if _verify_code(normalized, row.code_hash):
                return ConsumeResult(
                    False, "replayed" if row.consumed_at is not None else "expired"
                )
    return ConsumeResult(False, "no_live_code")


async def purge_expired_codes(db: AsyncSession, *, limit: int = 1000) -> int:
    """Delete code rows old enough that they can no longer inform a replay check."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.mfa_email_code_ttl_seconds * _REPLAY_LOOKBACK_MULTIPLIER
    )
    rows = (
        await db.execute(
            select(MfaEmailCode)
            .where(MfaEmailCode.created_at < cutoff)
            .limit(limit)
        )
    ).scalars().all()
    for row in rows:
        await db.delete(row)
    return len(rows)


# --------------------------------------------------------------------------- #
# Delivery
# --------------------------------------------------------------------------- #
def render_code_message(
    code: str,
    *,
    purpose: MfaEmailCodePurpose,
    config: Settings = settings,
) -> tuple[str, str, str]:
    """Return (subject, text, html) for one code email.

    The message states the code's lifetime and what to do if it was not
    requested, and contains no link. A one-time code mail that also carries a
    clickable URL is a phishing lure in its own right, and this factor is
    already the phishable one.
    """
    app_name = config.app_name
    minutes = max(1, round(config.mfa_email_code_ttl_seconds / 60))
    if purpose == MfaEmailCodePurpose.enrollment:
        headline = f"Confirm this address for {app_name} sign-in"
        lead = (
            "Enter this code to confirm this mailbox as your second "
            "authentication factor."
        )
    else:
        headline = f"Your {app_name} sign-in code"
        lead = "Enter this code to finish signing in."
    text = (
        f"{headline}\n\n"
        f"{lead}\n\n"
        f"    {code}\n\n"
        f"The code expires in {minutes} minutes and can be used once.\n\n"
        "If you did not request it, someone may know your password. Change it "
        "and tell your administrator.\n"
    )
    html_body = (
        f"<p>{html.escape(lead)}</p>"
        f"<p style=\"font-size:24px;font-weight:600;letter-spacing:3px\">"
        f"{html.escape(code)}</p>"
        f"<p>The code expires in {minutes} minutes and can be used once.</p>"
        "<p>If you did not request it, someone may know your password. "
        "Change it and tell your administrator.</p>"
    )
    return headline, text, html_body


async def send_code(
    code: str,
    *,
    operator: Operator,
    row: MfaEmailCode,
    purpose: MfaEmailCodePurpose,
    config: Settings = settings,
    provider=None,
) -> str:
    """Mail one code immediately. Returns the provider message id.

    Raises :class:`EmailDeliveryUnavailable` with a safe code when the provider
    is unconfigured or the send fails. The caller must surface that rather than
    reporting success: an operator who is told a code is on its way, when it is
    not, waits out the expiry and then blames their mailbox.
    """
    selected = provider if provider is not None else build_transactional_provider(config)
    if selected is None:
        raise EmailDeliveryUnavailable("email_provider_unavailable")
    subject, text_body, html_body = render_code_message(
        code, purpose=purpose, config=config
    )
    message = OutboundEmail(
        # A distinct namespace from the alert queue: an authentication code must
        # never share an idempotency key with a retried alert.
        namespace="mfa-code",
        key=row.id,
        recipient=operator.email,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )
    try:
        return await selected.send_message(message)
    except ProviderError as exc:
        raise EmailDeliveryUnavailable(exc.code) from exc


def masked_destination(operator: Operator) -> str:
    """The address, masked, for display and for the audit trail."""
    return mask_recipient(operator.email)
