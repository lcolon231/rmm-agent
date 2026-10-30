# SPDX-License-Identifier: AGPL-3.0-only
"""Direct tests for patch policy resolution and the install gate (issue #285).

``resolve_effective_patch_policy`` and ``_latest_user_present`` run against a
private in-memory SQLite database. ``evaluate_patch_install`` is driven with its
collaborators (effective policy, scanned updates, maintenance windows, user
presence) replaced, so each branch of the gate is a plain table row.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_policy_resolution.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402
from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core import patch_policies as pp  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    Client,
    Heartbeat,
    MonitoringScope,
    PatchApprovalPolicy,
    PatchApprovalPolicyRevision,
    Site,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


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


async def _agent(db) -> Agent:
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


async def _policy(db, scope, scope_id=None, *, enabled=True, revision=True, created_at=None):
    policy = PatchApprovalPolicy(
        name=f"{scope.value}-{scope_id}", scope=scope, scope_id=scope_id, enabled=enabled,
        created_at=created_at or NOW,
    )
    db.add(policy)
    await db.flush()
    if revision:
        db.add(PatchApprovalPolicyRevision(policy_id=policy.id, version=1, rules=[]))
        db.add(PatchApprovalPolicyRevision(policy_id=policy.id, version=2, rules=[]))
        await db.flush()
    return policy


# --------------------------------------------------------------------------- #
# resolve_effective_patch_policy
# --------------------------------------------------------------------------- #
async def test_no_policy_resolves_to_none(db):
    agent = await _agent(db)
    assert await pp.resolve_effective_patch_policy(db, agent) is None


async def test_most_specific_scope_wins(db):
    agent = await _agent(db)
    site = await db.get(Site, agent.site_id)
    await _policy(db, MonitoringScope.global_)
    await _policy(db, MonitoringScope.client, site.client_id)
    site_policy = await _policy(db, MonitoringScope.site, agent.site_id)
    effective = await pp.resolve_effective_patch_policy(db, agent)
    assert effective.policy.id == site_policy.id
    # The current revision is the highest version.
    assert effective.revision.version == 2

    agent_policy = await _policy(db, MonitoringScope.agent, agent.id)
    assert (await pp.resolve_effective_patch_policy(db, agent)).policy.id == agent_policy.id


async def test_disabled_and_foreign_policies_are_ignored(db):
    agent = await _agent(db)
    await _policy(db, MonitoringScope.agent, agent.id, enabled=False)
    await _policy(db, MonitoringScope.site, "other-site")
    await _policy(db, MonitoringScope.client, "other-client")
    global_policy = await _policy(db, MonitoringScope.global_)
    assert (await pp.resolve_effective_patch_policy(db, agent)).policy.id == global_policy.id


async def test_earliest_created_wins_within_a_scope(db):
    agent = await _agent(db)
    # Keep both rows referenced: the session's identity map is weak, and a row
    # reloaded from SQLite comes back naive while a live one is still aware.
    newer = await _policy(db, MonitoringScope.global_, created_at=NOW)
    older = await _policy(db, MonitoringScope.global_, created_at=NOW - timedelta(days=1))
    assert (await pp.resolve_effective_patch_policy(db, agent)).policy.id == older.id
    assert newer.id != older.id


async def test_winner_without_revision_resolves_to_none(db):
    # A less-specific policy with a revision does not step in for a winner
    # that has none; resolution fails closed to "no policy".
    agent = await _agent(db)
    await _policy(db, MonitoringScope.global_)
    await _policy(db, MonitoringScope.agent, agent.id, revision=False)
    assert await pp.resolve_effective_patch_policy(db, agent) is None


async def test_agent_with_missing_site_still_matches_global_and_own_scopes(db):
    agent = Agent(id="orphan", site_id="gone", token_hash="h")
    global_policy = await _policy(db, MonitoringScope.global_)
    assert (await pp.resolve_effective_patch_policy(db, agent)).policy.id == global_policy.id
    agent_policy = await _policy(db, MonitoringScope.agent, "orphan")
    assert (await pp.resolve_effective_patch_policy(db, agent)).policy.id == agent_policy.id


# --------------------------------------------------------------------------- #
# _latest_user_present
# --------------------------------------------------------------------------- #
async def test_latest_user_present(db):
    agent = await _agent(db)
    # No heartbeat yet: assume a user is present so reboot policy fails safe.
    assert await pp._latest_user_present(db, agent) is True
    db.add(Heartbeat(agent_id=agent.id, ts=NOW - timedelta(minutes=5), logged_in_user="alice"))
    db.add(Heartbeat(agent_id=agent.id, ts=NOW, logged_in_user="  "))
    await db.flush()
    assert await pp._latest_user_present(db, agent) is False
    db.add(Heartbeat(agent_id=agent.id, ts=NOW + timedelta(minutes=1), logged_in_user="bob"))
    await db.flush()
    assert await pp._latest_user_present(db, agent) is True


# --------------------------------------------------------------------------- #
# evaluate_patch_install
# --------------------------------------------------------------------------- #
MISSING = [
    {"kb_id": "KB1000001", "severity": "Critical"},
    {"kb_id": "KB1000002", "severity": "Low"},
    {"update_id": "AAAA-1111", "severity": "Critical"},
    {"update_id": "BBBB-2222", "severity": "Low"},
]
RULES = [
    {"key": "critical", "action": "approve", "match": {"severities": ["Critical"]}},
    {"key": "low", "action": "deny", "match": {"severities": ["Low"]}},
]


def _revision(**overrides):
    fields = dict(
        rules=RULES,
        default_action="deny",
        require_maintenance_window=False,
        reboot_policy="never",
        reboot_delay_seconds=300,
        reboot_requires_no_user=True,
        max_install_attempts=3,
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


@pytest.fixture
def gate(monkeypatch):
    state = SimpleNamespace(
        effective=None, missing=list(MISSING), windows=[], user_present=False
    )

    async def resolve(db, agent):
        return state.effective

    async def missing(db, agent_id):
        return state.missing

    async def windows(db, agent, at):
        return state.windows

    async def user_present(db, agent):
        return state.user_present

    monkeypatch.setattr(pp, "resolve_effective_patch_policy", resolve)
    monkeypatch.setattr(pp, "latest_missing_updates", missing)
    monkeypatch.setattr(pp.monitoring_core, "active_maintenance_windows", windows)
    monkeypatch.setattr(pp, "_latest_user_present", user_present)

    def use(revision, capabilities=()):
        state.effective = pp.EffectivePatchPolicy(
            policy=SimpleNamespace(id="policy-1"), revision=revision
        )
        state.agent = SimpleNamespace(id="agent-1", supported_capabilities=list(capabilities))
        return state

    state.use = use
    return state


async def _run(gate, payload):
    return await pp.evaluate_patch_install(None, gate.agent, payload, NOW)


async def test_no_effective_policy_returns_none(gate):
    gate.agent = SimpleNamespace(id="agent-1", supported_capabilities=[])
    assert await _run(gate, {"install_all": True}) is None


async def test_install_all_is_narrowed_to_approved_subset(gate):
    gate.use(_revision())
    result = await _run(gate, {"install_all": True})
    assert result["outcome"] == "allowed"
    assert result["code"] is None
    assert result["payload"] == {
        "install_all": False, "kb_ids": ["KB1000001"], "update_ids": ["aaaa-1111"],
    }
    assert result["gated_detail"] | {} == {
        "policy_id": "policy-1", "outcome": "allowed", "install_all": True,
        "requested": 4, "approved": 2, "denied": 2, "deferred": 0,
        "window_required": False, "window_present": True,
    }
    # The agent does not advertise patch-reboot-v1: no extensions injected.
    assert "max_attempts" not in result["payload"]
    assert result["reboot_detail"] is None


async def test_install_all_with_nothing_approved(gate):
    gate.use(_revision(rules=[], default_action="deny"))
    result = await _run(gate, {"install_all": True})
    assert result["outcome"] == "no_approved_updates"
    assert result["code"] == "patch_install_no_approved_updates"


async def test_install_all_counts_deferred(gate):
    gate.use(_revision(rules=[
        {"key": "hold", "action": "defer", "defer_days": 7, "match": {"severities": ["Critical", "Low"]}},
    ]))
    result = await _run(gate, {"install_all": True})
    assert result["gated_detail"]["deferred"] == 4
    assert result["outcome"] == "no_approved_updates"


async def test_explicit_selection_all_approved_passes_payload_through(gate):
    gate.use(_revision())
    payload = {"kb_ids": ["kb1000001"], "update_ids": ["AAAA-1111"]}
    result = await _run(gate, payload)
    assert result["outcome"] == "allowed"
    assert result["blocked"] == []
    assert result["payload"] == payload
    assert result["payload"] is not payload


@pytest.mark.parametrize(
    "payload,blocked",
    [
        # Denied by a rule.
        ({"kb_ids": ["KB1000002"]}, ["KB1000002"]),
        ({"update_ids": ["bbbb-2222"]}, ["bbbb-2222"]),
        # Not in the latest scan at all: fail closed.
        ({"kb_ids": ["KB9999999"]}, ["KB9999999"]),
        ({"update_ids": ["cccc-3333"]}, ["cccc-3333"]),
        # One bad item blocks the whole explicit selection.
        ({"kb_ids": ["KB1000001", "KB1000002"], "update_ids": ["aaaa-1111"]}, ["KB1000002"]),
    ],
)
async def test_explicit_selection_fails_closed(gate, payload, blocked):
    gate.use(_revision())
    result = await _run(gate, payload)
    assert result["outcome"] == "denied"
    assert result["code"] == "patch_install_denied"
    assert result["blocked"] == blocked


async def test_required_window_absent_blocks_install(gate):
    gate.use(_revision(require_maintenance_window=True))
    result = await _run(gate, {"install_all": True})
    assert result["outcome"] == "maintenance_window_required"
    assert result["code"] == "patch_install_maintenance_window_required"
    assert result["gated_detail"]["window_present"] is False


async def test_capable_agent_gets_max_attempts_without_reboot(gate):
    gate.use(_revision(reboot_policy="never"), capabilities=[pp.PATCH_REBOOT_CAPABILITY])
    result = await _run(gate, {"install_all": True})
    assert result["payload"]["max_attempts"] == 3
    assert "reboot" not in result["payload"]
    assert result["reboot_detail"] is None


async def test_capable_agent_denied_install_gets_no_extensions(gate):
    gate.use(_revision(reboot_policy="forced"), capabilities=[pp.PATCH_REBOOT_CAPABILITY])
    result = await _run(gate, {"kb_ids": ["KB1000002"]})
    assert result["outcome"] == "denied"
    assert "max_attempts" not in result["payload"]
    assert result["reboot_detail"] is None


async def test_reboot_evidence_without_window(gate):
    gate.use(_revision(reboot_policy="if_required"), capabilities=[pp.PATCH_REBOOT_CAPABILITY])
    gate.user_present = True
    result = await _run(gate, {"install_all": True})
    assert result["payload"]["reboot"] == {
        "policy": "if_required", "delay_seconds": 300, "requires_no_user": True,
        "user_present_at_dispatch": True,
        "maintenance_window_id": None, "maintenance_window_ends_at": None,
    }
    assert result["reboot_detail"] == {
        "policy_id": "policy-1", "reboot_policy": "if_required", "delay_seconds": 300,
        "requires_no_user": True, "window_present": False, "user_present": True,
    }


async def test_reboot_evidence_binds_earliest_ending_window(gate):
    gate.use(
        _revision(reboot_policy="forced", require_maintenance_window=True),
        capabilities=[pp.PATCH_REBOOT_CAPABILITY],
    )
    gate.windows = [
        # Naive (as SQLite returns it) and aware values must compare correctly.
        SimpleNamespace(id="w-late", ends_at=datetime(2026, 6, 1, 15, 0)),
        SimpleNamespace(id="w-early", ends_at=datetime(2026, 6, 1, 16, 0, tzinfo=timezone(timedelta(hours=3)))),
    ]
    result = await _run(gate, {"install_all": True})
    reboot = result["payload"]["reboot"]
    assert reboot["maintenance_window_id"] == "w-early"
    assert reboot["maintenance_window_ends_at"].startswith("2026-06-01T13:00:00")
    assert result["reboot_detail"]["window_present"] is True
