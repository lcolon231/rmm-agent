# SPDX-License-Identifier: AGPL-3.0-only
"""Storage-growth retention and observability tests (issue #114).

Behavior under test:
  - prune deletes heartbeats older than the telemetry window and keeps recent
    ones
  - prune clears command stdout/stderr past the output window but keeps the
    command row and its accountability metadata (exit code, truncation totals)
  - prune NEVER touches audit events or anchors, and the hash chain still
    verifies afterwards
  - a retention setting of 0 disables that class's pruning
  - storage_status reports per-class counts and raises threshold-breach flags

Run just this file:  pytest tests/test_retention.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_retention.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.main import app  # noqa: E402
from app.core import audit, retention  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    Alert,
    AlertEmailAttempt,
    AlertEmailDelivery,
    AlertEvent,
    AlertEventType,
    AlertState,
    AuditEvent,
    CheckResult,
    CheckResultStatus,
    Client,
    Command,
    CommandKind,
    CommandStatus,
    EmailAttemptStatus,
    EmailDeliveryStatus,
    EvidenceLegalHold,
    Heartbeat,
    Operator,
    OperatorRole,
    Site,
    TenantRetentionPolicy,
)

NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def _agent(db) -> str:
    # Each call is a distinct tenant (client names are unique).
    count = (await db.execute(select(func.count()).select_from(Client))).scalar_one()
    client = Client(name=f"C{count}")
    db.add(client)
    await db.flush()
    site = Site(client_id=client.id, name="S")
    db.add(site)
    await db.flush()
    agent = Agent(site_id=site.id, token_hash="h", hostname="H")
    db.add(agent)
    await db.flush()
    return agent.id


def _heartbeat(agent_id, age_days) -> Heartbeat:
    return Heartbeat(agent_id=agent_id, ts=NOW - timedelta(days=age_days))


def _command(agent_id, age_days, with_output=True) -> Command:
    return Command(
        agent_id=agent_id,
        kind=CommandKind.shell,
        envelope_version="command-v2",
        status=CommandStatus.succeeded,
        exit_code=0,
        stdout="captured-output" if with_output else None,
        stderr="err" if with_output else None,
        stdout_total_bytes=15,
        completed_at=NOW - timedelta(days=age_days),
    )


@pytest.mark.asyncio
async def test_prune_deletes_old_heartbeats_keeps_recent(db):
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=40))  # older than 30d window
    db.add(_heartbeat(agent_id, age_days=5))   # recent
    await db.commit()

    result = await retention.prune_expired(
        db, settings, now=NOW
    )
    await db.commit()
    assert result.heartbeats_deleted == 1
    remaining = (await db.execute(select(func.count()).select_from(Heartbeat))).scalar_one()
    assert remaining == 1


@pytest.mark.asyncio
async def test_prune_clears_old_output_keeps_metadata_and_recent(db):
    agent_id = await _agent(db)
    old = _command(agent_id, age_days=120)   # older than 90d output window
    recent = _command(agent_id, age_days=10)
    db.add(old)
    db.add(recent)
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert result.command_outputs_cleared == 1

    await db.refresh(old)
    await db.refresh(recent)
    # Old command: text cleared, row + metadata intact.
    assert old.stdout is None and old.stderr is None
    assert old.exit_code == 0 and old.stdout_total_bytes == 15
    assert old.status == CommandStatus.succeeded
    # Recent command: untouched.
    assert recent.stdout == "captured-output"

    # Idempotent: a second prune clears nothing more.
    again = await retention.prune_expired(db, settings, now=NOW)
    assert again.command_outputs_cleared == 0


@pytest.mark.asyncio
async def test_prune_never_touches_audit_and_chain_verifies(db):
    await audit.record(
        db,
        action="agent.offline",
        detail={"last_seen_at": "2026-01-01T00:00:01+00:00"},
    )
    await audit.record(
        db,
        action="agent.offline",
        detail={"last_seen_at": "2026-01-01T00:00:02+00:00"},
    )
    await db.commit()
    before = [
        (e.seq, e.event_hash)
        for e in (await db.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars()
    ]

    # Prune with everything expired.
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=999))
    await db.commit()
    await retention.prune_expired(db, settings, now=NOW)
    await db.commit()

    after = (await db.execute(select(AuditEvent).order_by(AuditEvent.seq))).scalars().all()
    # Existing events are untouched; the sweep only *appends* its deletion
    # proof (issue #88): one purge event plus the sweep summary.
    assert [(e.seq, e.event_hash) for e in after[: len(before)]] == before
    assert [e.action for e in after[len(before):]] == [
        "retention.purged", "retention.sweep_completed"
    ]
    ok, broken = await audit.verify_chain(db)
    assert ok, f"chain broke at {broken}"


@pytest.mark.asyncio
async def test_zero_retention_disables_pruning(db, monkeypatch):
    monkeypatch.setattr(settings, "telemetry_retention_days", 0)
    monkeypatch.setattr(settings, "command_output_retention_days", 0)
    agent_id = await _agent(db)
    db.add(_heartbeat(agent_id, age_days=999))
    db.add(_command(agent_id, age_days=999))
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert result.heartbeats_deleted == 0
    assert result.command_outputs_cleared == 0


@pytest.mark.asyncio
async def test_storage_status_counts_and_alert_flags(db, monkeypatch):
    agent_id = await _agent(db)
    for _ in range(3):
        db.add(_heartbeat(agent_id, age_days=1))
    db.add(_command(agent_id, age_days=1))
    await audit.record(
        db,
        action="agent.offline",
        detail={"last_seen_at": "2026-01-01T00:00:00+00:00"},
    )
    await db.commit()

    # No breach with default thresholds.
    status = await retention.storage_status(db, settings)
    assert status["heartbeats"]["count"] == 3
    assert status["commands"]["count"] == 1
    assert status["commands"]["with_output"] == 1
    assert status["audit"]["event_count"] == 1
    assert status["alert"] is False

    # Lower the heartbeat threshold to force a breach.
    monkeypatch.setattr(settings, "heartbeat_backlog_alert", 2)
    breached = await retention.storage_status(db, settings)
    assert breached["heartbeats"]["backlog_alert"] is True
    assert breached["alert"] is True


@pytest_asyncio.fixture
async def api_client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(email="ro@nodelink.test", password_hash=hash_password("pw"),
                        role=OperatorRole.readonly))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post("/auth/login", json={"email": "ro@nodelink.test", "password": "pw"})
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


@pytest.mark.asyncio
async def test_storage_status_endpoint_readable_by_operator(api_client):
    r = await api_client.get("/storage/status")
    assert r.status_code == 200
    body = r.json()
    for key in ("heartbeats", "commands", "audit", "anchor_publication", "disk", "alert"):
        assert key in body
    assert "telemetry_retention_days" in body["retention_policy"]


# --------------------------------------------------------------------------- #
# Tenant-specific retention (issue #88)
# --------------------------------------------------------------------------- #
async def _client_of(db, agent_id) -> str:
    agent = await db.get(Agent, agent_id)
    site = await db.get(Site, agent.site_id)
    return site.client_id


async def _policy(db, client_id, **values) -> None:
    db.add(TenantRetentionPolicy(client_id=client_id, version=1, set_by="test", **values))
    await db.flush()


async def _events(db, action) -> list[AuditEvent]:
    return list((await db.execute(
        select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
    )).scalars())


async def _count(db, model, *where) -> int:
    query = select(func.count()).select_from(model)
    if where:
        query = query.where(*where)
    return (await db.execute(query)).scalar_one()


def _alert(agent_id, *, state=AlertState.resolved, resolved_days=None, key="cpu") -> Alert:
    return Alert(
        agent_id=agent_id,
        policy_id="p1",
        policy_revision_id="r1",
        check_key=key,
        state=state,
        last_result_status=CheckResultStatus.ok,
        resolved_at=NOW - timedelta(days=resolved_days) if resolved_days is not None else None,
    )


async def _alert_with_history(db, agent_id, *, resolved_days, key,
                              email_status=EmailDeliveryStatus.sent,
                              email_age_days=None) -> Alert:
    alert = _alert(agent_id, resolved_days=resolved_days, key=key)
    db.add(alert)
    await db.flush()
    event = AlertEvent(alert_id=alert.id, generation=1, event_type=AlertEventType.opened,
                       actor="system")
    db.add(event)
    await db.flush()
    age = email_age_days if email_age_days is not None else resolved_days
    delivery = AlertEmailDelivery(
        alert_id=alert.id, alert_event_id=event.id, generation=1,
        event_type=AlertEventType.opened, recipient="a@x.test", subject="s",
        text_body="t", html_body="h", status=email_status, max_attempts=3,
        created_at=NOW - timedelta(days=age),
    )
    db.add(delivery)
    await db.flush()
    db.add(AlertEmailAttempt(delivery_id=delivery.id, attempt_number=1,
                             status=EmailAttemptStatus.sent))
    await db.flush()
    return alert


@pytest.mark.asyncio
async def test_each_tenant_is_pruned_only_by_its_own_policy(db):
    a = await _agent(db)
    b = await _agent(db)
    client_a, client_b = await _client_of(db, a), await _client_of(db, b)
    await _policy(db, client_a, telemetry_days=10)  # tenant A: 10 days
    # tenant B inherits the 30-day platform default
    for agent_id in (a, b):
        db.add(_heartbeat(agent_id, age_days=20))
        db.add(_heartbeat(agent_id, age_days=5))
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert await _count(db, Heartbeat, Heartbeat.agent_id == a) == 1
    assert await _count(db, Heartbeat, Heartbeat.agent_id == b) == 2
    assert result.heartbeats_deleted == 1
    by_tenant = {t.client_id: t for t in result.tenants}
    assert by_tenant[client_a].counts == {"heartbeats_deleted": 1}
    assert by_tenant[client_b].counts == {}
    purged = await _events(db, "retention.purged")
    assert [(e.organization_id, e.detail["policy_source"]) for e in purged] == [
        (client_a, "tenant")
    ]


@pytest.mark.asyncio
async def test_boundary_time_row_at_cutoff_is_kept(db):
    agent_id = await _agent(db)
    at_cutoff = Heartbeat(agent_id=agent_id, ts=NOW - timedelta(days=30))
    just_past = Heartbeat(agent_id=agent_id, ts=NOW - timedelta(days=30, seconds=1))
    db.add_all([at_cutoff, just_past])
    await db.commit()
    kept_id, deleted_id = at_cutoff.id, just_past.id

    await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    remaining = (await db.execute(select(Heartbeat.id))).scalars().all()
    assert remaining == [kept_id]
    (purge,) = await _events(db, "retention.purged")
    assert purge.detail["cutoff"] == (NOW - timedelta(days=30)).isoformat()
    assert purge.detail["ids_sha256"] == retention.ids_digest([deleted_id])


@pytest.mark.asyncio
async def test_tenant_legal_hold_suspends_all_pruning_until_released(db):
    held = await _agent(db)
    free = await _agent(db)
    held_client = await _client_of(db, held)
    for agent_id in (held, free):
        db.add(_heartbeat(agent_id, age_days=400))
        db.add(_command(agent_id, age_days=400))
        # Check results are a global class; the hold must exempt them too.
        for i in range(settings.check_result_history_per_key + 1):
            db.add(CheckResult(agent_id=agent_id, check_key="cpu", status=CheckResultStatus.ok,
                               evaluated_at=NOW, received_at=NOW - timedelta(minutes=i)))
    hold = EvidenceLegalHold(client_id=held_client, record_id=None, scope_key="*",
                             status="active", reason="litigation", placed_by_email="x@y")
    db.add(hold)
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert await _count(db, Heartbeat, Heartbeat.agent_id == held) == 1
    assert await _count(db, Heartbeat, Heartbeat.agent_id == free) == 0
    held_cmd = (await db.execute(select(Command).where(Command.agent_id == held))).scalar_one()
    assert held_cmd.stdout == "captured-output"
    assert result.tenants_suspended == 1
    keep = settings.check_result_history_per_key
    assert await _count(db, CheckResult, CheckResult.agent_id == held) == keep + 1
    assert await _count(db, CheckResult, CheckResult.agent_id == free) == keep
    (suspended,) = await _events(db, "retention.purge_suspended")
    assert suspended.organization_id == held_client
    assert suspended.detail["reason"] == "tenant_legal_hold"

    # A record-scoped hold does not suspend tenant pruning; release the tenant hold.
    hold.status = "released"
    db.add(EvidenceLegalHold(client_id=held_client, record_id="rec-1", scope_key="rec-1",
                             status="active", reason="one record", placed_by_email="x@y"))
    await db.commit()
    again = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert await _count(db, Heartbeat, Heartbeat.agent_id == held) == 0
    assert again.tenants_suspended == 0


@pytest.mark.asyncio
async def test_failed_tenant_rolls_back_alone_and_next_sweep_retries(db, monkeypatch):
    a = await _agent(db)
    b = await _agent(db)
    client_a = await _client_of(db, a)
    for agent_id in (a, b):
        db.add(_heartbeat(agent_id, age_days=100))
        db.add(_command(agent_id, age_days=100))
    await db.commit()

    real = retention._prune_command_output

    async def flaky(db_, client_id, days, now, s):
        purges = await real(db_, client_id, days, now, s)
        if client_id == client_a:
            raise RuntimeError("disk full")
        return purges

    monkeypatch.setattr(retention, "_prune_command_output", flaky)
    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    db.expire_all()
    # Tenant A's whole unit of work rolled back -- its heartbeat delete too.
    assert await _count(db, Heartbeat, Heartbeat.agent_id == a) == 1
    a_cmd = (await db.execute(select(Command).where(Command.agent_id == a))).scalar_one()
    assert a_cmd.stdout == "captured-output"
    # Tenant B was pruned normally.
    assert await _count(db, Heartbeat, Heartbeat.agent_id == b) == 0
    assert result.tenants_failed == 1
    (failed,) = await _events(db, "retention.purge_failed")
    assert failed.organization_id == client_a
    assert failed.detail == {"client_id": client_a, "error_class": "RuntimeError",
                             "policy_version": 0}
    assert all(e.organization_id != client_a for e in await _events(db, "retention.purged"))
    ok, broken = await audit.verify_chain(db)
    assert ok, f"chain broke at {broken}"

    monkeypatch.setattr(retention, "_prune_command_output", real)
    retry = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert retry.tenants_failed == 0
    assert await _count(db, Heartbeat, Heartbeat.agent_id == a) == 0


@pytest.mark.asyncio
async def test_row_cap_bounds_one_sweep_and_digest_covers_all_batches(db, monkeypatch):
    monkeypatch.setattr(settings, "retention_batch_size", 2)
    monkeypatch.setattr(settings, "retention_max_rows_per_sweep", 5)
    agent_id = await _agent(db)
    rows = [_heartbeat(agent_id, age_days=100 + i) for i in range(7)]
    db.add_all(rows)
    await db.commit()
    all_ids = {r.id for r in rows}

    first = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert first.heartbeats_deleted == 5
    (purge,) = await _events(db, "retention.purged")
    assert purge.detail["truncated"] is True
    survivors = set((await db.execute(select(Heartbeat.id))).scalars().all())
    assert purge.detail["ids_sha256"] == retention.ids_digest(all_ids - survivors)

    second = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert second.heartbeats_deleted == 2
    assert (await _events(db, "retention.purged"))[-1].detail["truncated"] is False


@pytest.mark.asyncio
async def test_new_classes_are_inert_by_default(db):
    agent_id = await _agent(db)
    db.add(_command(agent_id, age_days=999))
    await _alert_with_history(db, agent_id, resolved_days=999, key="k1")
    await db.commit()

    await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert await _count(db, Command) == 1  # output cleared, row kept
    assert await _count(db, Alert) == 1
    assert await _count(db, AlertEmailDelivery) == 1


@pytest.mark.asyncio
async def test_command_records_and_task_history_pruned_by_tenant_policy(db):
    agent_id = await _agent(db)
    await _policy(db, await _client_of(db, agent_id), command_record_days=60)

    def aged(days, status=CommandStatus.succeeded):
        command = _command(agent_id, age_days=days)
        command.created_at = NOW - timedelta(days=days)
        command.status = status
        return command

    old_done, old_running, recent = aged(90), aged(90, CommandStatus.running), aged(10)
    db.add_all([old_done, old_running, recent])
    await db.flush()
    retry = aged(5)
    retry.parent_command_id = old_done.id
    db.add(retry)
    await db.commit()
    deleted_id, retry_id = old_done.id, retry.id

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    db.expire_all()
    assert result.command_records_deleted == 1
    assert await db.get(Command, deleted_id) is None
    # Live work is never deleted, and lineage pointers are nulled, not dangling.
    assert await _count(db, Command, Command.status == CommandStatus.running) == 1
    assert (await db.get(Command, retry_id)).parent_command_id is None
    (record_purge,) = [e for e in await _events(db, "retention.purged")
                       if e.detail["category"] == "command_record_days"]
    assert record_purge.detail["ids_sha256"] == retention.ids_digest([deleted_id])


@pytest.mark.asyncio
async def test_resolved_alerts_pruned_with_history_but_open_alerts_never(db):
    agent_id = await _agent(db)
    await _policy(db, await _client_of(db, agent_id), alert_days=90)
    expired = await _alert_with_history(db, agent_id, resolved_days=120, key="k1")
    await _alert_with_history(db, agent_id, resolved_days=10, key="k2")
    db.add(_alert(agent_id, state=AlertState.open, key="k3"))
    db.add(_alert(agent_id, state=AlertState.acknowledged, key="k4"))
    await db.commit()
    expired_id = expired.id

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    db.expire_all()
    assert result.alerts_deleted == 1
    assert await db.get(Alert, expired_id) is None
    assert await _count(db, Alert) == 3
    assert await _count(db, AlertEvent, AlertEvent.alert_id == expired_id) == 0
    assert await _count(db, AlertEmailDelivery, AlertEmailDelivery.alert_id == expired_id) == 0
    assert await _count(db, AlertEmailAttempt) == 1  # only the recent alert's attempt remains
    (purge,) = [e for e in await _events(db, "retention.purged")
                if e.detail["category"] == "alert_days"]
    assert purge.detail["dependent_rows"] == 3  # event, delivery, attempt


@pytest.mark.asyncio
async def test_only_terminal_notifications_are_pruned(db):
    agent_id = await _agent(db)
    await _policy(db, await _client_of(db, agent_id), notification_days=30)
    sent = await _alert_with_history(db, agent_id, resolved_days=1, email_age_days=60, key="k1")
    await _alert_with_history(db, agent_id, resolved_days=1, email_age_days=60, key="k2",
                              email_status=EmailDeliveryStatus.retrying)
    await _alert_with_history(db, agent_id, resolved_days=1, email_age_days=5, key="k3")
    await db.commit()

    result = await retention.prune_expired(db, settings, now=NOW)
    await db.commit()
    assert result.notifications_deleted == 1
    assert await _count(db, AlertEmailDelivery, AlertEmailDelivery.alert_id == sent.id) == 0
    assert await _count(db, AlertEmailDelivery) == 2
    assert await _count(db, AlertEmailAttempt) == 2
    assert await _count(db, Alert) == 3  # alerts themselves follow alert_days
