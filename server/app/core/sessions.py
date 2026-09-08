# SPDX-License-Identifier: AGPL-3.0-only
"""Server-side operator session lifecycle (issue #69).

Sessions used to be pure JWTs. That made them cheap but opaque: the only
revocation lever was ``Operator.token_generation``, which ends *every* session
an operator has. Good enough to stop an incident, useless for investigating one
-- you could not see where an account was signed in from, and you could not
close one suspicious session without signing the person out everywhere.

This module makes a session a row. The token carries its id in the ``sid``
claim, and :func:`resolve` re-checks that row on every authenticated request.
Three properties follow, and they are the ones worth reviewing:

**Revocation is immediate and individual.** A revoked row fails the very next
request, with no waiting for a token to expire.

**Two independent ceilings bound a session.** ``absolute_expires_at`` is set at
sign-in and refresh can never move it, so renewal cannot continue forever. The
idle timeout is evaluated against ``last_seen_at``, which is what limits an
unattended browser. A session ends at whichever comes first.

**Expiry is decided on read, not by a sweeper.** A session is unusable the
moment it lapses, whether or not any background job has noticed; the sweeper
that follows only tidies rows and writes the terminal reason. A capability that
depended on a timer to become safe would be unsafe whenever the timer was late.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.models.models import (
    Operator,
    OperatorSession,
    OperatorSessionEndReason,
)

#: Bound on the stored user-agent. Attacker-influenced, display-only.
_MAX_USER_AGENT = 500


def _as_utc(value: datetime | None) -> datetime | None:
    """Read a stored timestamp as timezone-aware UTC (SQLite returns naive)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class SessionRejection:
    """Why a session was refused, as a coded, non-secret reason."""

    code: str


def idle_deadline(session: OperatorSession, config: Settings = settings) -> datetime:
    last_seen = _as_utc(session.last_seen_at) or _as_utc(session.created_at)
    return last_seen + timedelta(seconds=config.admin_session_idle_timeout_seconds)


def effective_deadline(
    session: OperatorSession, config: Settings = settings
) -> datetime:
    """The earlier of the two ceilings -- when this session actually ends."""
    absolute = _as_utc(session.absolute_expires_at)
    return min(absolute, idle_deadline(session, config))


# --------------------------------------------------------------------------- #
# Creation
# --------------------------------------------------------------------------- #
async def create(
    db: AsyncSession,
    operator: Operator,
    *,
    auth_methods: tuple[str, ...],
    source_ip: str | None,
    user_agent: str | None,
    is_break_glass: bool = False,
    config: Settings = settings,
) -> OperatorSession:
    """Open a session for ``operator`` and return the row.

    Break-glass sessions get their own, much shorter absolute lifetime: the
    credential bypasses MFA, so time is the main thing bounding its blast
    radius.
    """
    now = datetime.now(timezone.utc)
    lifetime = (
        config.break_glass_session_lifetime_seconds
        if is_break_glass
        else config.admin_session_absolute_lifetime_seconds
    )
    session = OperatorSession(
        operator_id=operator.id,
        token_generation=operator.token_generation,
        auth_methods=",".join(sorted(auth_methods))[:120],
        source_ip=source_ip,
        user_agent=(user_agent or "")[:_MAX_USER_AGENT] or None,
        is_break_glass=is_break_glass,
        created_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(seconds=lifetime),
    )
    db.add(session)
    await db.flush()
    await _enforce_concurrency_ceiling(db, operator.id, keep=session.id, config=config)
    return session


async def _enforce_concurrency_ceiling(
    db: AsyncSession, operator_id: str, *, keep: str, config: Settings
) -> None:
    """Close the oldest live sessions past the per-operator ceiling.

    Ending the oldest rather than refusing the newest is deliberate: refusing a
    sign-in because of sessions the operator may no longer control would let a
    forgotten tab lock someone out of their own account, which is a worse
    failure than closing that tab.
    """
    live = list(
        (
            await db.execute(
                select(OperatorSession.id)
                .where(
                    OperatorSession.operator_id == operator_id,
                    OperatorSession.ended_at.is_(None),
                )
                .order_by(OperatorSession.created_at.desc(), OperatorSession.id)
            )
        ).scalars()
    )
    excess = [sid for sid in live if sid != keep][config.admin_session_max_concurrent - 1 :]
    if not excess:
        return
    await db.execute(
        update(OperatorSession)
        .where(OperatorSession.id.in_(excess), OperatorSession.ended_at.is_(None))
        .values(
            ended_at=datetime.now(timezone.utc),
            end_reason=OperatorSessionEndReason.superseded,
        )
    )


# --------------------------------------------------------------------------- #
# Validation on every request
# --------------------------------------------------------------------------- #
async def resolve(
    db: AsyncSession,
    session_id: str,
    operator: Operator,
    *,
    config: Settings = settings,
) -> tuple[OperatorSession | None, SessionRejection | None]:
    """Return the live session for ``session_id``, or a coded rejection.

    Called on every authenticated request, so it is one indexed primary-key
    read plus, at most, one bounded write. Every rejection path returns a code
    rather than raising: the caller turns them all into the same opaque 401, so
    a holder of a stale token learns nothing about *why* it was refused.

    A lapsed session is marked terminal here rather than left for the sweeper,
    so the reason an operator sees in their inventory is accurate even on a
    deployment where the background task never runs.
    """
    session = await db.get(OperatorSession, session_id)
    if session is None or session.operator_id != operator.id:
        return None, SessionRejection("unknown_session")
    if session.ended_at is not None:
        return None, SessionRejection("session_ended")
    if session.token_generation != operator.token_generation:
        # A bulk revocation happened after this session was minted. Record it so
        # the inventory explains itself.
        await _end(db, session, OperatorSessionEndReason.revoked_by_admin)
        return None, SessionRejection("session_revoked")

    now = datetime.now(timezone.utc)
    if now >= _as_utc(session.absolute_expires_at):
        await _end(db, session, OperatorSessionEndReason.absolute_timeout)
        return None, SessionRejection("absolute_timeout")
    if now >= idle_deadline(session, config):
        await _end(db, session, OperatorSessionEndReason.idle_timeout)
        return None, SessionRejection("idle_timeout")

    await touch(db, session, now=now, config=config)
    return session, None


async def touch(
    db: AsyncSession,
    session: OperatorSession,
    *,
    now: datetime | None = None,
    config: Settings = settings,
) -> None:
    """Refresh ``last_seen_at``, but only when it is already stale.

    Writing on every request would turn a read-mostly auth path into a write
    per request. The skew this introduces is bounded by the write interval and
    always in the operator's favour (a session may live slightly longer than the
    idle timeout, never shorter), which is why the interval must stay well below
    the timeout.
    """
    now = now or datetime.now(timezone.utc)
    last_seen = _as_utc(session.last_seen_at) or _as_utc(session.created_at)
    interval = timedelta(
        seconds=config.admin_session_last_seen_write_interval_seconds
    )
    if now - last_seen < interval:
        return
    session.last_seen_at = now


async def _end(
    db: AsyncSession,
    session: OperatorSession,
    reason: OperatorSessionEndReason,
    *,
    ended_by: str | None = None,
) -> None:
    session.ended_at = datetime.now(timezone.utc)
    session.end_reason = reason
    session.ended_by_operator_id = ended_by
    await db.flush()


# --------------------------------------------------------------------------- #
# Inventory and revocation
# --------------------------------------------------------------------------- #
async def list_for_operator(
    db: AsyncSession, operator_id: str, *, include_ended: bool = False, limit: int = 100
) -> list[OperatorSession]:
    query = select(OperatorSession).where(OperatorSession.operator_id == operator_id)
    if not include_ended:
        query = query.where(OperatorSession.ended_at.is_(None))
    query = query.order_by(OperatorSession.created_at.desc()).limit(limit)
    return list((await db.execute(query)).scalars().all())


async def revoke(
    db: AsyncSession,
    session: OperatorSession,
    *,
    by_admin: bool,
    ended_by: str | None,
) -> bool:
    """End one session. Returns False if it had already ended.

    Idempotent by design: revoking an already-dead session is not an error
    worth surfacing, and treating it as one would make the dashboard's
    "revoke everything" button fail on a race it cannot avoid.
    """
    if session.ended_at is not None:
        return False
    await _end(
        db,
        session,
        OperatorSessionEndReason.revoked_by_admin
        if by_admin
        else OperatorSessionEndReason.revoked_by_self,
        ended_by=ended_by,
    )
    return True


async def revoke_all_for_operator(
    db: AsyncSession,
    operator_id: str,
    *,
    reason: OperatorSessionEndReason,
    ended_by: str | None = None,
    except_session_id: str | None = None,
) -> int:
    """End every live session for an operator. Returns how many were closed.

    ``except_session_id`` supports "sign out my other devices", which is the
    common case after a suspected leak: the operator keeps the session they are
    using to do the clean-up.
    """
    query = update(OperatorSession).where(
        OperatorSession.operator_id == operator_id,
        OperatorSession.ended_at.is_(None),
    )
    if except_session_id is not None:
        query = query.where(OperatorSession.id != except_session_id)
    result = await db.execute(
        query.values(
            ended_at=datetime.now(timezone.utc),
            end_reason=reason,
            ended_by_operator_id=ended_by,
        )
    )
    return int(result.rowcount or 0)


async def active_count(db: AsyncSession, operator_id: str) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(OperatorSession)
                .where(
                    OperatorSession.operator_id == operator_id,
                    OperatorSession.ended_at.is_(None),
                )
            )
        ).scalar_one()
    )


# --------------------------------------------------------------------------- #
# Maintenance
# --------------------------------------------------------------------------- #
async def expire_lapsed(db: AsyncSession, *, limit: int = 1000) -> int:
    """Mark sessions terminal once their absolute ceiling has passed.

    Purely cosmetic for security -- :func:`resolve` already refuses them -- but
    it keeps the inventory honest for an operator who is looking at it rather
    than using it.
    """
    now = datetime.now(timezone.utc)
    lapsed = list(
        (
            await db.execute(
                select(OperatorSession.id)
                .where(
                    OperatorSession.ended_at.is_(None),
                    OperatorSession.absolute_expires_at <= now,
                )
                .limit(limit)
            )
        ).scalars()
    )
    if not lapsed:
        return 0
    await db.execute(
        update(OperatorSession)
        .where(OperatorSession.id.in_(lapsed))
        .values(ended_at=now, end_reason=OperatorSessionEndReason.absolute_timeout)
    )
    return len(lapsed)


async def purge_ended(db: AsyncSession, *, older_than_days: int, limit: int = 1000) -> int:
    """Delete long-dead session rows.

    Session rows are operational inventory, not accountability evidence -- the
    audit chain already records sign-in, revocation, and break-glass activation
    -- so unlike audit data they are eventually deleted.
    """
    if older_than_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    stale = list(
        (
            await db.execute(
                select(OperatorSession.id)
                .where(
                    OperatorSession.ended_at.is_not(None),
                    OperatorSession.ended_at <= cutoff,
                )
                .limit(limit)
            )
        ).scalars()
    )
    if not stale:
        return 0
    await db.execute(delete(OperatorSession).where(OperatorSession.id.in_(stale)))
    return len(stale)
