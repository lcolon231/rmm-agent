# SPDX-License-Identifier: AGPL-3.0-only
"""Shared test helper for tenant-scoped authorization (issue #66).

Fixtures that seed clients/operators directly in the database predate the tenant
boundary and assume deployment-wide operator visibility. ``grant_all_memberships``
reproduces the one-time access-preserving backfill the `0037` migration performs
in production: every non-platform-admin operator receives a membership to every
existing client, with the client role equivalent to its global role. Call it once
after a fixture has seeded its operators and clients (before commit).

Operators that must cross the tenant boundary should instead set
``is_platform_admin=True`` when constructed (mirrors the migration promoting
pre-tenancy global admins).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Client,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
)

_ROLE_MAP = {
    OperatorRole.admin: ClientRole.client_admin,
    OperatorRole.operator: ClientRole.client_operator,
    OperatorRole.readonly: ClientRole.client_readonly,
}


async def grant_all_memberships(db: AsyncSession) -> None:
    operators = list((await db.execute(select(Operator))).scalars().all())
    client_ids = [row[0] for row in (await db.execute(select(Client.id))).all()]
    existing = {
        (row[0], row[1])
        for row in (
            await db.execute(
                select(
                    OperatorClientMembership.operator_id,
                    OperatorClientMembership.client_id,
                )
            )
        ).all()
    }
    for operator in operators:
        if operator.is_platform_admin:
            continue
        for client_id in client_ids:
            if (operator.id, client_id) in existing:
                continue
            db.add(
                OperatorClientMembership(
                    operator_id=operator.id,
                    client_id=client_id,
                    role=_ROLE_MAP[operator.role],
                    granted_by="test-seed",
                    reason="test-seed",
                )
            )
    await db.flush()
