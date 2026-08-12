# SPDX-License-Identifier: AGPL-3.0-only
"""Transactional enrollment-token redemption.

All checks that decide whether a token may enroll an endpoint live here so the
legacy and resource-oriented HTTP routes cannot drift apart.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import credential_fingerprint, generate_token, hash_token
from app.core.timeutil import ensure_utc
from app.models.models import (
    Agent,
    AgentStatus,
    EnrollmentToken,
    Operator,
    Site,
)
from app.schemas.schemas import EnrollRequest


class EnrollmentRejected(Exception):
    """Internal rejection with a non-secret reason for metrics/audit only."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class EnrollmentResult:
    agent: Agent
    enrollment_token: EnrollmentToken
    agent_token: str
    organization_id: str
    site_name: str


def _same_claim(expected: str | None, actual: str | None) -> bool:
    if not expected:
        return True
    return bool(actual) and expected.casefold() == actual.casefold()


async def redeem_enrollment_token(
    db: AsyncSession,
    *,
    body: EnrollRequest,
    source_ip: str | None,
) -> EnrollmentResult:
    """Validate and consume a token, then create its agent in this transaction.

    PostgreSQL locks the matching row. The conditional UPDATE is retained as a
    second guard and provides atomic use-limit enforcement under SQLite, whose
    ``FOR UPDATE`` is a no-op.
    """
    now = datetime.now(timezone.utc)
    digest = hash_token(body.enrollment_token)
    token = (
        await db.execute(
            select(EnrollmentToken)
            .where(EnrollmentToken.token_hash == digest)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if token is None:
        raise EnrollmentRejected("invalid")

    expiry = ensure_utc(token.expires_at)
    if token.revoked or token.revoked_at is not None:
        raise EnrollmentRejected("revoked")
    if expiry is None or expiry <= now:
        raise EnrollmentRejected("expired")
    if token.uses >= token.max_uses:
        raise EnrollmentRejected("exhausted")

    site = await db.get(Site, token.site_id)
    if site is None:
        raise EnrollmentRejected("invalid_assignment")
    if body.site and not _same_claim(site.name, body.site):
        raise EnrollmentRejected("site_restriction")
    if not _same_claim(token.hostname_restriction, body.hostname):
        raise EnrollmentRejected("hostname_restriction")
    resolved_name = (body.agent_name or body.hostname).strip()
    if not _same_claim(token.agent_name_restriction, resolved_name):
        raise EnrollmentRejected("agent_name_restriction")
    if token.environment and body.environment and not _same_claim(
        token.environment, body.environment
    ):
        raise EnrollmentRejected("environment_restriction")

    consume = await db.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.id == token.id,
            EnrollmentToken.revoked.is_(False),
            EnrollmentToken.revoked_at.is_(None),
            EnrollmentToken.expires_at > now,
            EnrollmentToken.uses < EnrollmentToken.max_uses,
        )
        .values(
            uses=EnrollmentToken.uses + 1,
            last_used_at=now,
        )
        .execution_options(synchronize_session="fetch")
    )
    if consume.rowcount != 1:
        raise EnrollmentRejected("concurrent_use")
    await db.refresh(token)

    agent_token = generate_token()
    agent = Agent(
        site_id=token.site_id,
        token_hash=hash_token(agent_token),
        credential_fingerprint=credential_fingerprint(agent_token),
        credential_issued_at=now,
        # Issue the credential with an enforced finite lifetime (issue #125); the
        # agent renews before this passes and the server rotates with a bounded
        # overlap so renewal is loss-safe.
        credential_expires_at=now
        + timedelta(seconds=settings.agent_credential_lifetime_seconds),
        name=resolved_name,
        hostname=body.hostname.strip(),
        os=(body.operating_system or body.os).strip(),
        os_version=body.os_version.strip(),
        agent_version=body.agent_version.strip(),
        architecture=body.architecture.strip(),
        environment=token.environment or body.environment,
        labels=list(token.labels or []),
        owner_user_id=token.assigned_user_id,
        enrolled_by_token_id=token.id,
        ip_address=source_ip,
        command_envelope_versions=body.supported_command_envelope_versions,
        supported_capabilities=body.supported_capabilities,
        update_channel=body.update_channel,
        status=AgentStatus.pending,
        enrolled_at=now,
    )
    db.add(agent)
    await db.flush()
    return EnrollmentResult(
        agent=agent,
        enrollment_token=token,
        agent_token=agent_token,
        organization_id=site.client_id,
        site_name=site.name,
    )
