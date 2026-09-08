# SPDX-License-Identifier: AGPL-3.0-only
"""Reset an operator's password from the command line.

There is no self-service password reset in the product (see
``app.core.password_reset`` for why), so a locked-out administrator is
recovered here, by someone with database access.

The reset always bumps the token generation and closes every live session for
the account, so anything minted under the old password stops working
immediately.

Usage:
    python scripts/reset_password.py admin@nodelink.example
    python scripts/reset_password.py admin@nodelink.example --clear-mfa
    # prompts for the new password (hidden, twice)

Works against a database that has not reached revision 0039: the tracked-session
table simply is not there yet, so the row-closing half is skipped and reported
as such. The reset is still complete, because the token-generation bump is what
actually invalidates outstanding tokens.

``--clear-mfa`` also revokes the operator's authenticators and recovery codes.
Use it when the second factor was lost too -- with MFA enforced, a correct
password on its own will not sign anyone in. It leaves the account
password-only until it re-enrols, which is why it is not the default.
"""
import argparse
import asyncio
import getpass
import sys

# Ensure the app package is importable when run as a script.
sys.path.insert(0, ".")

from app.core.database import AsyncSessionLocal  # noqa: E402
from app.core.password_reset import (  # noqa: E402
    MIN_PASSWORD_LENGTH,
    PasswordResetError,
    reset_password,
)


async def main(email: str, password: str, clear_mfa: bool) -> None:
    async with AsyncSessionLocal() as db:
        try:
            outcome = await reset_password(
                db, email, new_password=password, clear_mfa=clear_mfa
            )
        except PasswordResetError as exc:
            print(exc)
            sys.exit(1)
        await db.commit()

    print(f"Reset password for {outcome.email}")
    if outcome.sessions_tracked:
        print(f"  sessions revoked: {outcome.sessions_revoked}")
    else:
        # Do not let a skipped step look like a completed one.
        print(
            "  sessions revoked: n/a -- this database predates revision 0039 and "
            "has no session table."
        )
        print(
            "  Existing tokens are still invalidated by the token-generation bump."
        )
    if outcome.mfa_reset:
        print(f"  authenticators revoked: {outcome.credentials_revoked}")
        print(f"  recovery codes invalidated: {outcome.recovery_codes_invalidated}")
        print("  The account is now password-only; re-enrol a second factor.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset an RMM operator's password.")
    parser.add_argument("email")
    parser.add_argument(
        "--clear-mfa",
        action="store_true",
        help=(
            "also revoke the operator's authenticators and recovery codes "
            "(use when the second factor was lost too)"
        ),
    )
    args = parser.parse_args()

    pw = getpass.getpass("New password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match.")
        sys.exit(1)
    if len(pw) < MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        sys.exit(1)

    asyncio.run(main(args.email, pw, args.clear_mfa))
