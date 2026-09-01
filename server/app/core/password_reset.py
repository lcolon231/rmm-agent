# SPDX-License-Identifier: AGPL-3.0-only
"""Out-of-band operator password reset (the counterpart to ``create_admin``).

The server deliberately exposes no password-reset endpoint: there is no mail
sender to trust, no reset-token lifetime to defend, and no self-service flow an
attacker could aim at an administrator's inbox. The cost of that choice is that
a forgotten password can only be repaired by someone who already holds database
access, which is the same trust level required to mint the first operator.

That repair still has to leave the account in a *known* state, so the logic
lives here rather than in the script that calls it:

* The new hash alone is not enough. Outstanding JWTs were minted under the old
  credential, so ``token_generation`` is bumped and every live session is
  closed -- a reset that leaves someone else's session alive has not actually
  taken the account back.
* ``clear_mfa`` exists because the common reason a person cannot get in is that
  they lost the second factor as well, and a correct password is not a session
  when MFA is enforced. It is opt-in: silently demoting an account to
  password-only would turn a routine reset into a security downgrade.
* Break-glass identities are refused. Their password hash is deliberately
  unusable so the identity can never be reached by password login; handing one
  a working password would quietly undo that.
* The reset is audited like every other privileged act, with ``by: "cli"``
  marking it as out-of-band. An unaudited administrative password change is
  indistinguishable from an attacker with database access.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit, mfa, sessions
from app.core.break_glass import UNUSABLE_PASSWORD_HASH
from app.core.security import hash_password
from app.models.models import Operator, OperatorSessionEndReason

# Matches the floor enforced by scripts/create_admin.py.
MIN_PASSWORD_LENGTH = 8


class PasswordResetError(Exception):
    """The reset was refused before anything was changed."""


@dataclass(frozen=True)
class ResetOutcome:
    """What the reset actually did, for the caller to report."""

    operator_id: str
    email: str
    sessions_revoked: int
    mfa_reset: bool
    credentials_revoked: int
    recovery_codes_invalidated: int


async def reset_password(
    db: AsyncSession,
    email: str,
    *,
    new_password: str,
    clear_mfa: bool = False,
    actor: str = "cli",
) -> ResetOutcome:
    """Set ``email``'s password and invalidate everything minted under the old one.

    The caller owns the transaction; nothing here commits.
    """
    if len(new_password) < MIN_PASSWORD_LENGTH:
        raise PasswordResetError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    operator = (
        await db.execute(select(Operator).where(Operator.email == email))
    ).scalar_one_or_none()
    if operator is None:
        raise PasswordResetError(f"No operator with email {email!r}.")
    if operator.password_hash == UNUSABLE_PASSWORD_HASH:
        raise PasswordResetError(
            f"{email!r} is a break-glass identity, which has no password login. "
            "Rotate its credential instead."
        )

    operator.password_hash = hash_password(new_password)
    # Every token and session that existed a moment ago proved knowledge of the
    # *old* password. None of them survive the reset.
    operator.token_generation += 1
    sessions_revoked = await sessions.revoke_all_for_operator(
        db,
        operator.id,
        reason=OperatorSessionEndReason.revoked_by_admin,
    )

    credentials_revoked = 0
    codes_invalidated = 0
    if clear_mfa:
        credentials_revoked, codes_invalidated = await mfa.revoke_all_factors(
            db, operator, reason="admin_reset"
        )

    await audit.record(
        db,
        action="operator.password_reset",
        actor=actor,
        detail={
            "operator_id": operator.id,
            "sessions_revoked": sessions_revoked,
            "mfa_reset": clear_mfa,
            "credentials_revoked": credentials_revoked,
            "recovery_codes_invalidated": codes_invalidated,
            "by": "cli",
        },
    )
    return ResetOutcome(
        operator_id=operator.id,
        email=operator.email,
        sessions_revoked=sessions_revoked,
        mfa_reset=clear_mfa,
        credentials_revoked=credentials_revoked,
        recovery_codes_invalidated=codes_invalidated,
    )
