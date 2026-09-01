# SPDX-License-Identifier: AGPL-3.0-only
"""Out-of-band operator password reset (scripts/reset_password.py).

The product has no self-service reset, so this path is the only way back into a
locked-out account -- which makes it worth testing against the property that
justifies it: after a reset the account is in a *known* state. Nothing minted
under the old password still works, the second factor is cleared only when
asked for, and the whole thing is on the audit chain.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_password_reset.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import sessions as sessions_core  # noqa: E402
from app.core.break_glass import UNUSABLE_PASSWORD_HASH  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.password_reset import (  # noqa: E402
    PasswordResetError,
    reset_password,
)
from app.core.security import AMR_PASSWORD, hash_password, verify_password  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    MfaRecoveryCode,
    Operator,
    OperatorRole,
    OperatorSession,
    OperatorSessionEndReason,
    WebAuthnCredential,
)

EMAIL = "locked-out@nodelink.test"
OLD_PASSWORD = "the-old-password"
NEW_PASSWORD = "a-brand-new-password"
BREAK_GLASS_EMAIL = "break-glass@nodelink.test"


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        session.add(
            Operator(
                email=EMAIL,
                password_hash=hash_password(OLD_PASSWORD),
                role=OperatorRole.admin,
                is_platform_admin=True,
            )
        )
        session.add(
            Operator(
                email=BREAK_GLASS_EMAIL,
                password_hash=UNUSABLE_PASSWORD_HASH,
                role=OperatorRole.admin,
                is_platform_admin=True,
            )
        )
        await session.commit()
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def _operator(db, email: str = EMAIL) -> Operator:
    return (
        await db.execute(select(Operator).where(Operator.email == email))
    ).scalars().one()


async def _enrol_mfa(db, operator: Operator) -> None:
    db.add(
        WebAuthnCredential(
            operator_id=operator.id,
            credential_id="cred-1",
            public_key_cose="cose",
            algorithm=-7,
            name="YubiKey",
        )
    )
    db.add(
        MfaRecoveryCode(
            operator_id=operator.id,
            batch_id="batch-1",
            code_hash=hash_password("recovery-code"),
        )
    )
    await db.flush()


@pytest.mark.asyncio
async def test_reset_replaces_credential_and_invalidates_everything_it_minted(db):
    operator = await _operator(db)
    generation = operator.token_generation
    await sessions_core.create(
        db, operator, auth_methods=(AMR_PASSWORD,), source_ip=None, user_agent=None
    )
    await db.flush()

    outcome = await reset_password(db, EMAIL, new_password=NEW_PASSWORD)
    await db.commit()

    operator = await _operator(db)
    assert verify_password(NEW_PASSWORD, operator.password_hash)
    # The old password is dead, and so is every token minted under it.
    assert not verify_password(OLD_PASSWORD, operator.password_hash)
    assert operator.token_generation == generation + 1

    session_row = (
        await db.execute(
            select(OperatorSession).where(OperatorSession.operator_id == operator.id)
        )
    ).scalars().one()
    assert session_row.ended_at is not None
    assert session_row.end_reason == OperatorSessionEndReason.revoked_by_admin
    assert outcome.sessions_revoked == 1

    event = (
        await db.execute(
            select(AuditEvent).where(AuditEvent.action == "operator.password_reset")
        )
    ).scalars().one()
    assert event.actor == "cli"
    assert event.detail["operator_id"] == operator.id
    assert event.detail["sessions_revoked"] == 1
    assert event.detail["mfa_reset"] is False


@pytest.mark.asyncio
async def test_second_factor_survives_unless_the_reset_asks_for_it(db):
    operator = await _operator(db)
    await _enrol_mfa(db, operator)

    outcome = await reset_password(db, EMAIL, new_password=NEW_PASSWORD)
    await db.commit()

    # A password reset is not a security downgrade: the authenticator is intact.
    credential = (
        await db.execute(select(WebAuthnCredential))
    ).scalars().one()
    assert credential.revoked_at is None
    assert (await db.execute(select(MfaRecoveryCode))).scalars().all()
    assert outcome.mfa_reset is False
    assert outcome.credentials_revoked == 0


@pytest.mark.asyncio
async def test_clear_mfa_revokes_every_factor_and_records_the_counts(db):
    operator = await _operator(db)
    await _enrol_mfa(db, operator)

    outcome = await reset_password(
        db, EMAIL, new_password=NEW_PASSWORD, clear_mfa=True
    )
    await db.commit()

    credential = (await db.execute(select(WebAuthnCredential))).scalars().one()
    assert credential.revoked_at is not None
    assert credential.revoked_reason == "admin_reset"
    # Codes go too, or the reset would not establish a known state.
    assert (await db.execute(select(MfaRecoveryCode))).scalars().all() == []
    assert (await _operator(db)).mfa_recovery_codes_generated_at is None
    assert outcome.credentials_revoked == 1
    assert outcome.recovery_codes_invalidated == 1

    event = (
        await db.execute(
            select(AuditEvent).where(AuditEvent.action == "operator.password_reset")
        )
    ).scalars().one()
    assert event.detail["mfa_reset"] is True
    assert event.detail["credentials_revoked"] == 1
    assert event.detail["recovery_codes_invalidated"] == 1


@pytest.mark.asyncio
async def test_a_break_glass_identity_cannot_be_given_a_working_password(db):
    with pytest.raises(PasswordResetError, match="break-glass"):
        await reset_password(db, BREAK_GLASS_EMAIL, new_password=NEW_PASSWORD)

    assert (await _operator(db, BREAK_GLASS_EMAIL)).password_hash == (
        UNUSABLE_PASSWORD_HASH
    )


@pytest.mark.asyncio
async def test_unknown_operator_and_short_password_are_refused_before_any_change(db):
    with pytest.raises(PasswordResetError, match="No operator"):
        await reset_password(db, "nobody@nodelink.test", new_password=NEW_PASSWORD)
    with pytest.raises(PasswordResetError, match="at least"):
        await reset_password(db, EMAIL, new_password="short")

    operator = await _operator(db)
    assert verify_password(OLD_PASSWORD, operator.password_hash)
    assert operator.token_generation == 0
    assert (await db.execute(select(AuditEvent))).scalars().all() == []


@pytest.mark.asyncio
async def test_reset_works_on_a_database_that_predates_session_tracking(db):
    """The regression this guards is not hypothetical.

    A locked-out administrator ran this against production while the schema was
    still at 0038; the tool reached for ``operator_sessions``, PostgreSQL
    aborted the transaction, and the reset that was supposed to rescue them
    failed. A recovery tool has to work on the database it finds.
    """
    from sqlalchemy import text

    # Drop the table to reproduce a pre-0039 database exactly.
    await db.execute(text("DROP TABLE IF EXISTS operator_sessions"))
    await db.commit()

    outcome = await reset_password(db, EMAIL, new_password=NEW_PASSWORD)
    await db.commit()

    # The reset is complete: the password changed and every outstanding token is
    # invalidated by the generation bump, which needs no new table.
    operator = (
        await db.execute(select(Operator).where(Operator.email == EMAIL))
    ).scalars().one()
    assert verify_password(NEW_PASSWORD, operator.password_hash)
    assert not verify_password(OLD_PASSWORD, operator.password_hash)
    assert operator.token_generation == 1

    # The skipped half is reported rather than silently counted as done.
    assert outcome.sessions_tracked is False
    assert outcome.sessions_revoked == 0


@pytest.mark.asyncio
async def test_session_rows_are_closed_when_the_table_is_present(db):
    """The other side of the same branch: on a current schema, nothing is skipped."""
    operator = (
        await db.execute(select(Operator).where(Operator.email == EMAIL))
    ).scalars().one()
    db.add(
        OperatorSession(
            operator_id=operator.id,
            token_generation=operator.token_generation,
            absolute_expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
    )
    await db.flush()

    outcome = await reset_password(db, EMAIL, new_password=NEW_PASSWORD)
    await db.commit()

    assert outcome.sessions_tracked is True
    assert outcome.sessions_revoked == 1
