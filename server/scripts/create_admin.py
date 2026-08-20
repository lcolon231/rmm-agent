# SPDX-License-Identifier: AGPL-3.0-only
"""Create an operator from the command line.

Solves the bootstrap chicken-and-egg: the /auth/operators endpoint is admin-only,
so the very first admin has to be created out-of-band. Run this once after
setting up the database.

Under tenant-scoped authorization (issue #66), a fresh deployment is default
deny: no operator can see any client until a *platform admin* grants memberships
(or promotes another platform admin). Bootstrap that first tenant-crossing
superuser with ``--platform-admin``.

Usage:
    python scripts/create_admin.py admin@nodelink.example --role admin --platform-admin
    # prompts for a password (hidden)
"""
import argparse
import asyncio
import getpass
import sys

# Ensure the app package is importable when run as a script.
sys.path.insert(0, ".")

from sqlalchemy import select  # noqa: E402

from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


async def main(
    email: str, role: str, password: str, platform_admin: bool = False
) -> None:
    # Make sure tables exist (harmless if they already do).
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        existing = await db.execute(select(Operator).where(Operator.email == email))
        if existing.scalar_one_or_none() is not None:
            print(f"Operator {email} already exists.")
            return
        db.add(
            Operator(
                email=email,
                password_hash=hash_password(password),
                role=OperatorRole(role),
                is_platform_admin=platform_admin,
            )
        )
        await db.commit()
    suffix = " (platform admin)" if platform_admin else ""
    print(f"Created {role} operator: {email}{suffix}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create an RMM operator.")
    parser.add_argument("email")
    parser.add_argument(
        "--role",
        default="admin",
        choices=[r.value for r in OperatorRole],
        help="operator role (default: admin)",
    )
    parser.add_argument(
        "--platform-admin",
        action="store_true",
        help="grant deployment-wide platform admin (crosses the tenant boundary)",
    )
    args = parser.parse_args()

    pw = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match.")
        sys.exit(1)
    if len(pw) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    asyncio.run(main(args.email, args.role, pw, args.platform_admin))
