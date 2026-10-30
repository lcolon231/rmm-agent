# SPDX-License-Identifier: AGPL-3.0-only
"""Direct tests for per-endpoint patch compliance and history (issue #285).

Runs ``endpoint_compliance`` and ``endpoint_history`` against a private
in-memory SQLite database seeded with real policies and inventory snapshots,
covering each reported state in its documented precedence order.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_compliance_endpoint.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core import patch_compliance as pc  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentInventorySnapshot,
    Client,
    MonitoringScope,
    PatchApprovalPolicy,
    PatchApprovalPolicyRevision,
    Site,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
STALE_AFTER = timedelta(days=7)
RULES = [
    {"key": "critical", "action": "approve", "match": {"severities": ["Critical"]}},
    {"key": "hold", "action": "defer", "defer_days": 30, "match": {"severities": ["Important"]}},
]


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


@pytest_asyncio.fixture
async def agent(db) -> Agent:
    client = Client(name="Clinic")
    db.add(client)
    await db.flush()
    site = Site(client_id=client.id, name="HQ")
    db.add(site)
    await db.flush()
    agent = Agent(site_id=site.id, token_hash="h", hostname="PC-01")
    db.add(agent)
    await db.flush()
    return agent


async def _policy(db, rules=RULES, default_action="deny") -> PatchApprovalPolicy:
    policy = PatchApprovalPolicy(name="Global", scope=MonitoringScope.global_)
    db.add(policy)
    await db.flush()
    db.add(PatchApprovalPolicyRevision(
        policy_id=policy.id, version=1, rules=rules, default_action=default_action,
    ))
    await db.flush()
    return policy


_seq = 0


async def _snapshot(db, agent, *, missing=None, status="ok", scanned_at=NOW, payload=None, received_at=None):
    global _seq
    _seq += 1
    if payload is None:
        payload = {"missing": missing or []}
        if scanned_at is not None:
            payload["scanned_at"] = scanned_at.isoformat()
    snapshot = AgentInventorySnapshot(
        agent_id=agent.id, section="windows_updates", status=status,
        schema_version=1, content_hash=f"{_seq:064x}", byte_size=1, payload=payload,
        collected_at=scanned_at or NOW - timedelta(days=30),
        received_at=received_at or NOW + timedelta(seconds=_seq),
    )
    db.add(snapshot)
    await db.flush()
    return snapshot


async def _compliance(db, agent, **kwargs):
    return await pc.endpoint_compliance(db, agent, NOW, stale_after=STALE_AFTER, **kwargs)


# --------------------------------------------------------------------------- #
# endpoint_compliance
# --------------------------------------------------------------------------- #
async def test_exempt_without_policy(db, agent):
    await _snapshot(db, agent, missing=[{"severity": "Critical"}])
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_EXEMPT
    assert result.policy_id is None
    assert (result.site_name, result.client_name, result.hostname) == ("HQ", "Clinic", "PC-01")


async def test_unknown_when_never_scanned(db, agent):
    policy = await _policy(db)
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_UNKNOWN
    assert result.policy_id == policy.id
    assert result.scanned_at is None


@pytest.mark.parametrize(
    "status,payload",
    [("error", {"missing": []}), ("ok", {"missing": [], "error_code": "wua_failed"})],
)
async def test_unknown_when_scan_untrusted(db, agent, status, payload):
    await _policy(db)
    await _snapshot(db, agent, status=status, payload=payload, scanned_at=None)
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_UNKNOWN
    # The untrusted scan's time still falls back to collected_at.
    assert result.scanned_at == NOW - timedelta(days=30)
    assert result.total_missing == 0


async def test_stale_beats_non_compliant(db, agent):
    await _policy(db)
    await _snapshot(db, agent, missing=[{"severity": "Critical"}], scanned_at=NOW - timedelta(days=8))
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_STALE
    assert result.approved_missing == 1


async def test_non_compliant_counts_each_decision(db, agent):
    await _policy(db)
    await _snapshot(db, agent, missing=[
        {"severity": "Critical"},
        {"severity": "Important", "last_deployment_change": (NOW - timedelta(days=1)).isoformat()},
        {"severity": "Low"},
    ])
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_NON_COMPLIANT
    assert (result.total_missing, result.approved_missing, result.deferred_missing, result.denied_missing) == (3, 1, 1, 1)
    assert result.scanned_at == NOW


async def test_compliant_when_only_deferred_or_denied_missing(db, agent):
    await _policy(db)
    await _snapshot(db, agent, missing=[{"severity": "Low"}])
    result = await _compliance(db, agent)
    assert result.state == pc.STATE_COMPLIANT
    assert result.denied_missing == 1


async def test_supplied_site_and_client_skip_lookups(db, agent):
    await _policy(db)
    await _snapshot(db, agent)
    site = Site(id="s-given", client_id="c-given", name="Given Site")
    client = Client(id="c-given", name="Given Client")
    result = await _compliance(db, agent, site=site, client=client)
    assert (result.site_id, result.site_name) == ("s-given", "Given Site")
    assert (result.client_id, result.client_name) == ("c-given", "Given Client")


async def test_orphan_agent_reports_blank_identity(db):
    await _policy(db)
    orphan = Agent(id="orphan", site_id="gone", token_hash="h", hostname="PC-X")
    result = await _compliance(db, orphan)
    assert (result.site_id, result.site_name, result.client_id, result.client_name) == ("gone", "", "", "")
    assert result.state == pc.STATE_UNKNOWN


# --------------------------------------------------------------------------- #
# endpoint_history
# --------------------------------------------------------------------------- #
async def test_history_newest_first_with_limit(db, agent):
    await _policy(db)
    await _snapshot(db, agent, missing=[{"severity": "Critical"}], scanned_at=NOW - timedelta(days=2))
    await _snapshot(db, agent, status="error", payload={"missing": [{"severity": "Critical"}]})
    await _snapshot(db, agent, missing=[{"severity": "Critical"}, {"severity": "Low"}])
    points = await pc.endpoint_history(db, agent, NOW, limit=10)
    assert [(p.total_missing, p.approved_missing) for p in points] == [(2, 1), (0, 0), (1, 1)]
    assert all(p.received_at.tzinfo is not None for p in points)
    assert len(await pc.endpoint_history(db, agent, NOW, limit=2)) == 2


async def test_history_without_policy_reports_zero_approved(db, agent):
    await _snapshot(db, agent, missing=[{"severity": "Critical"}])
    points = await pc.endpoint_history(db, agent, NOW, limit=10)
    assert [(p.total_missing, p.approved_missing) for p in points] == [(1, 0)]


async def test_history_empty(db, agent):
    await _policy(db)
    assert await pc.endpoint_history(db, agent, NOW, limit=10) == []
