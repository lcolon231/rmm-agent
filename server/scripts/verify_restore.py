# SPDX-License-Identifier: AGPL-3.0-only
"""Application-level validation of a restored NodeLink database.

Run after deploy/backup/nodelink-restore.sh against the ISOLATED restored
database. Validates what a DB-level restore cannot: that the restored rows
still form a working, tamper-evident system —

  - operators, agents, commands, enrollment tokens, and heartbeats are
    readable and counted
  - the audit hash chain verifies end to end (sequence order, no gaps)
  - every stored Merkle anchor still reproduces its root over the restored
    events

Exit code 0 means the restore is fit to promote; 1 means it is not, with the
reasons on stderr. Counts are printed so the operator can compare them
against expectations from the backup-time system.

Usage:
    python scripts/verify_restore.py --database-url postgresql+asyncpg://user@host:port/restored_db
    # optional lower bounds, e.g. from the pre-backup record:
    python scripts/verify_restore.py --database-url ... --min-operators 1 --min-agents 2
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402


async def run(database_url: str, min_counts: dict[str, int]) -> int:
    # Imported here so --help works without app config being loadable.
    from app.core import anchor as anchor_mod
    from app.core import audit as audit_mod
    from app.models.models import (
        Agent,
        AuditAnchor,
        AuditEvent,
        Command,
        EnrollmentToken,
        Heartbeat,
        Operator,
    )

    failures: list[str] = []
    engine = create_async_engine(database_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as db:
            counts = {}
            for name, model in (
                ("operators", Operator),
                ("agents", Agent),
                ("commands", Command),
                ("enrollment_tokens", EnrollmentToken),
                ("heartbeats", Heartbeat),
                ("audit_events", AuditEvent),
                ("audit_anchors", AuditAnchor),
            ):
                counts[name] = (
                    await db.execute(select(func.count()).select_from(model))
                ).scalar_one()
                print(f"verify-restore: {name} = {counts[name]}")

            for name, minimum in min_counts.items():
                if counts.get(name, 0) < minimum:
                    failures.append(
                        f"{name} count {counts.get(name, 0)} is below required minimum {minimum}"
                    )

            ok, broken = await audit_mod.verify_chain(db)
            if ok:
                print("verify-restore: audit chain intact")
            else:
                failures.append(f"audit chain broken at event {broken}")

            anchors = (
                await db.execute(select(AuditAnchor).order_by(AuditAnchor.created_at))
            ).scalars().all()
            for a in anchors:
                a_ok, reason = await anchor_mod.verify_anchor(db, a)
                if a_ok:
                    print(f"verify-restore: anchor {a.id} intact ({a.event_count} events)")
                else:
                    failures.append(f"anchor {a.id} failed: {reason}")
    finally:
        await engine.dispose()

    if failures:
        for f in failures:
            print(f"verify-restore: FAIL {f}", file=sys.stderr)
        return 1
    print("verify-restore: OK — restored database is internally consistent")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True,
                        help="async SQLAlchemy URL of the RESTORED database")
    parser.add_argument("--min-operators", type=int, default=0)
    parser.add_argument("--min-agents", type=int, default=0)
    parser.add_argument("--min-commands", type=int, default=0)
    parser.add_argument("--min-audit-events", type=int, default=0)
    args = parser.parse_args()
    minimums = {
        "operators": args.min_operators,
        "agents": args.min_agents,
        "commands": args.min_commands,
        "audit_events": args.min_audit_events,
    }
    sys.exit(asyncio.run(run(args.database_url, minimums)))


if __name__ == "__main__":
    main()
