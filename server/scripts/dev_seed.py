# SPDX-License-Identifier: AGPL-3.0-only
"""Seed a throwaway local database for live verification (docs/LOCAL-E2E.md).

Drops and recreates every table, then adds a fixed cast of operators and two
clients so a PR's "end-to-end or manual verification" starts from the same
state every time. Refuses anything but a local SQLite database in development.

Usage (from server/, with the env from docs/LOCAL-E2E.md):
    python scripts/dev_seed.py --reset
    python scripts/dev_seed.py --reset --scenario retention

Prints the client IDs and operator emails as JSON. Every operator's password is
``NODELINK_DEV_SEED_PASSWORD`` (default ``dev-seed-pw``).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable

# Ensure the app package is importable when run as a script.
sys.path.insert(0, ".")

from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.core.config import normalize_database_url, settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    Client,
    ClientRole,
    EvidenceLegalHold,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    TenantRetentionPolicy,
)

DEFAULT_PASSWORD = "dev-seed-pw"

# persona: (global role, client role on every seeded client, platform admin)
PERSONAS: dict[str, tuple[OperatorRole, ClientRole | None, bool]] = {
    "admin": (OperatorRole.admin, ClientRole.client_admin, False),
    "admin2": (OperatorRole.admin, ClientRole.client_admin, False),
    "reader": (OperatorRole.readonly, ClientRole.client_readonly, False),
    "operator": (OperatorRole.admin, ClientRole.client_operator, False),
    "platform": (OperatorRole.admin, None, True),
}


def persona_email(name: str) -> str:
    return f"{name}@dev.test"


def refuse_reason(database_url: str, environment: str) -> str | None:
    """Why seeding must not run against this database, or ``None`` if it may.

    The seed calls ``drop_all``: a wrong answer here wipes a real database.
    """
    # Allow-list, so an unfamiliar backend or environment name fails closed.
    if make_url(normalize_database_url(database_url)).get_backend_name() != "sqlite":
        return "DATABASE_URL is not a local SQLite database"
    if environment.strip().lower() != "development":
        return f"ENVIRONMENT is {environment!r}, not 'development'"
    return None


Scenario = Callable[[AsyncSession, dict[str, Client]], Awaitable[None]]


async def _retention(db: AsyncSession, clients: dict[str, Client]) -> None:
    """#88/#311: one category per resolution source, plus a client-wide hold.

    Out-of-bounds overrides bypass API validation on purpose so the resolver
    clamps them at read time (floor and ceiling sources).
    """
    db.add(TenantRetentionPolicy(
        client_id=clients["alpha"].id,
        telemetry_days=30,                   # tenant
        alert_days=10,                       # below the default floor of 30
        inventory_history_per_section=5000,  # above the default ceiling of 1000
        version=3,
        set_by="dev-seed",
    ))
    db.add(EvidenceLegalHold(
        client_id=clients["bravo"].id, record_id=None, scope_key="*",
        status="active", reason="dev seed hold", placed_by_email="dev-seed@dev.test",
    ))


# Add a scenario per feature that needs rows beyond the base cast.
SCENARIOS: dict[str, Scenario] = {"retention": _retention}


async def seed(password: str, scenarios: list[str]) -> dict[str, object]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        clients = {"alpha": Client(name="Alpha Dev"), "bravo": Client(name="Bravo Dev")}
        operators = {
            name: Operator(
                email=persona_email(name), password_hash=hash_password(password),
                role=role, is_platform_admin=platform,
            )
            for name, (role, _client_role, platform) in PERSONAS.items()
        }
        db.add_all([*clients.values(), *operators.values()])
        await db.flush()
        for name, (_role, client_role, _platform) in PERSONAS.items():
            if client_role is None:
                continue
            for client in clients.values():
                db.add(OperatorClientMembership(
                    operator_id=operators[name].id, client_id=client.id, role=client_role,
                    granted_by="dev-seed", reason="local verification",
                ))
        for name in scenarios:
            await SCENARIOS[name](db, clients)
        await db.commit()
        result: dict[str, object] = {
            "clients": {key: client.id for key, client in clients.items()},
            "operators": {name: persona_email(name) for name in PERSONAS},
            "scenarios": scenarios,
        }
    await engine.dispose()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed a throwaway local database.")
    parser.add_argument("--reset", action="store_true", required=True,
                        help="required: drops every table before seeding")
    parser.add_argument("--scenario", action="append", default=[], choices=sorted(SCENARIOS))
    args = parser.parse_args()
    reason = refuse_reason(settings.database_url, settings.environment)
    if reason:
        print(f"Refusing to seed: {reason}", file=sys.stderr)
        return 2
    password = os.environ.get("NODELINK_DEV_SEED_PASSWORD", DEFAULT_PASSWORD)
    print(json.dumps(asyncio.run(seed(password, args.scenario)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
