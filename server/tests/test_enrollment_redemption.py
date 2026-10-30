# SPDX-License-Identifier: AGPL-3.0-only
"""Direct tests for ``redeem_enrollment_token`` rejection reasons (issue #285).

The HTTP routes collapse every rejection into one opaque error, so the reason
code is only observable here. Each test gets a private in-memory SQLite
database; nothing goes through the app.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_enrollment_redemption.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlalchemy.sql.dml import Update  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.core.enrollment import (  # noqa: E402
    EnrollmentRejected,
    _same_claim,
    redeem_enrollment_token,
)
from app.core.security import hash_token  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentStatus,
    Client,
    EnrollmentToken,
    Site,
)
from app.schemas.schemas import EnrollRequest  # noqa: E402

SECRET = "enroll-secret-value"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


async def _seed(db, *, site_name="HQ", **token_fields) -> EnrollmentToken:
    client = Client(name="Clinic")
    db.add(client)
    await db.flush()
    site = Site(client_id=client.id, name=site_name)
    db.add(site)
    await db.flush()
    fields = dict(
        site_id=site.id,
        token_hash=hash_token(SECRET),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        max_uses=1,
        uses=0,
    )
    fields.update(token_fields)
    token = EnrollmentToken(**fields)
    db.add(token)
    await db.flush()
    return token


def _body(**overrides) -> EnrollRequest:
    fields = dict(enrollment_token=SECRET, hostname="PC-01", os="windows")
    fields.update(overrides)
    return EnrollRequest(**fields)


async def _reason(db, body=None) -> str:
    with pytest.raises(EnrollmentRejected) as caught:
        await redeem_enrollment_token(db, body=body or _body(), source_ip="198.51.100.4")
    assert str(caught.value) == caught.value.reason
    return caught.value.reason


# --------------------------------------------------------------------------- #
# _same_claim
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "expected,actual,result",
    [
        (None, None, True),
        ("", "anything", True),
        (None, "anything", True),
        ("PC-01", "pc-01", True),
        ("PC-01", "PC-02", False),
        ("PC-01", None, False),
        ("PC-01", "", False),
    ],
)
def test_same_claim(expected, actual, result):
    assert _same_claim(expected, actual) is result


# --------------------------------------------------------------------------- #
# Rejection reasons
# --------------------------------------------------------------------------- #
async def test_unknown_token_is_invalid(db):
    await _seed(db)
    assert await _reason(db, _body(enrollment_token="not-the-secret")) == "invalid"


@pytest.mark.parametrize(
    "fields",
    [{"revoked": True}, {"revoked_at": datetime.now(timezone.utc)}],
)
async def test_revoked(db, fields):
    await _seed(db, **fields)
    assert await _reason(db) == "revoked"


async def test_revoked_takes_precedence_over_expired(db):
    await _seed(db, revoked=True, expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    assert await _reason(db) == "revoked"


@pytest.mark.parametrize(
    "expires_at",
    [None, datetime.now(timezone.utc) - timedelta(seconds=1)],
)
async def test_expired_or_without_expiry(db, expires_at):
    await _seed(db, expires_at=expires_at)
    assert await _reason(db) == "expired"


async def test_exhausted(db):
    await _seed(db, max_uses=2, uses=2)
    assert await _reason(db) == "exhausted"


async def test_missing_site_is_invalid_assignment(db):
    token = await _seed(db)
    site = await db.get(Site, token.site_id)
    # Detach the token from its site without the ORM cascading the delete.
    token.site_id = "00000000-0000-0000-0000-000000000000"
    await db.flush()
    await db.delete(site)
    await db.flush()
    assert await _reason(db) == "invalid_assignment"


async def test_site_claim_must_match(db):
    await _seed(db, site_name="HQ")
    assert await _reason(db, _body(site="Branch")) == "site_restriction"


async def test_hostname_restriction(db):
    await _seed(db, hostname_restriction="PC-99")
    assert await _reason(db) == "hostname_restriction"


async def test_agent_name_restriction_uses_hostname_when_name_absent(db):
    await _seed(db, agent_name_restriction="front-desk")
    assert await _reason(db) == "agent_name_restriction"


async def test_agent_name_restriction_checks_supplied_name(db):
    await _seed(db, agent_name_restriction="front-desk")
    assert await _reason(db, _body(agent_name="back-office")) == "agent_name_restriction"


async def test_environment_restriction(db):
    await _seed(db, environment="production")
    assert await _reason(db, _body(environment="staging")) == "environment_restriction"


async def test_concurrent_use_when_conditional_update_loses(db, monkeypatch):
    """The second guard: the row was valid on read but the UPDATE matched 0."""
    await _seed(db)
    real_execute = db.execute

    class _Lost:
        rowcount = 0

    async def execute(statement, *args, **kwargs):
        if isinstance(statement, Update):
            return _Lost()
        return await real_execute(statement, *args, **kwargs)

    monkeypatch.setattr(db, "execute", execute)
    assert await _reason(db) == "concurrent_use"


# --------------------------------------------------------------------------- #
# Success paths
# --------------------------------------------------------------------------- #
async def test_success_consumes_token_and_creates_pending_agent(db):
    token = await _seed(
        db,
        site_name="HQ",
        hostname_restriction="pc-01",
        agent_name_restriction="Front Desk",
        labels=["kiosk"],
        max_uses=2,
    )
    result = await redeem_enrollment_token(
        db,
        body=_body(
            agent_name="  front desk ",
            site="hq",
            hostname="PC-01",
            operating_system="Windows 11",
            os_version=" 23H2 ",
            environment="lab",
        ),
        source_ip="198.51.100.4",
    )
    agent = result.agent
    assert isinstance(agent, Agent)
    assert agent.status == AgentStatus.pending
    assert agent.name == "front desk"
    assert agent.hostname == "PC-01"
    # operating_system wins over the legacy os field.
    assert agent.os == "Windows 11"
    assert agent.os_version == "23H2"
    # The token sets no environment, so the agent's claim is kept.
    assert agent.environment == "lab"
    assert agent.labels == ["kiosk"]
    assert agent.ip_address == "198.51.100.4"
    assert agent.enrolled_by_token_id == token.id
    assert agent.token_hash == hash_token(result.agent_token)
    lifetime = agent.credential_expires_at - agent.credential_issued_at
    assert lifetime == timedelta(seconds=settings.agent_credential_lifetime_seconds)

    assert result.enrollment_token.uses == 1
    assert result.enrollment_token.last_used_at is not None
    site = await db.get(Site, token.site_id)
    assert result.organization_id == site.client_id
    assert result.site_name == "HQ"


async def test_unrestricted_hostname_is_stored_trimmed(db):
    await _seed(db)
    result = await redeem_enrollment_token(db, body=_body(hostname="  PC-01  "), source_ip=None)
    assert result.agent.hostname == "PC-01"
    assert result.agent.name == "PC-01"


async def test_token_environment_overrides_claim_and_allows_unclaimed(db):
    await _seed(db, environment="production")
    result = await redeem_enrollment_token(db, body=_body(), source_ip=None)
    assert result.agent.environment == "production"
    assert result.agent.ip_address is None


async def test_matching_environment_claim_is_accepted(db):
    await _seed(db, environment="Production")
    result = await redeem_enrollment_token(
        db, body=_body(environment="production"), source_ip=None
    )
    assert result.agent.environment == "Production"


async def test_single_use_token_is_exhausted_after_redemption(db):
    await _seed(db, max_uses=1)
    await redeem_enrollment_token(db, body=_body(), source_ip=None)
    assert await _reason(db, _body(hostname="PC-02")) == "exhausted"


async def test_naive_expiry_from_sqlite_is_treated_as_utc(db):
    # SQLite hands back naive datetimes; a naive future expiry must still pass.
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(tzinfo=None)
    await _seed(db, expires_at=future)
    result = await redeem_enrollment_token(db, body=_body(), source_ip=None)
    assert result.enrollment_token.uses == 1
