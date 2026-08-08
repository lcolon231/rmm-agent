# SPDX-License-Identifier: AGPL-3.0-only
"""Comprehensive automated tests for recurring task scheduling (issue #49)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_scheduled_tasks.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.scheduler import (  # noqa: E402
    compute_next_run,
    dispatch_scheduled_tasks_once,
    validate_cron_expression,
)
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentTrustState,
    AuditEvent,
    Client,
    Command,
    CommandKind,
    CommandStatus,
    Operator,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
    Site,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="sched-admin@nodelink.test",
                password_hash=hash_password("admin-password"),
                role=OperatorRole.admin,
            )
        )
        db.add(
            Operator(
                email="sched-readonly@nodelink.test",
                password_hash=hash_password("readonly-password"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as c:
        login = await c.post(
            "/auth/login",
            json={"email": "sched-admin@nodelink.test", "password": "admin-password"},
        )
        token = login.json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


def test_cron_expression_validation():
    assert validate_cron_expression("0 * * * *") is True
    assert validate_cron_expression("*/15 9-17 * * 1-5") is True
    assert validate_cron_expression("0 0 1,15 * *") is True
    assert validate_cron_expression("invalid cron") is False
    assert validate_cron_expression("60 * * * *") is False
    assert validate_cron_expression("0 24 * * *") is False


def test_cron_next_run_computation():
    base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
    # Every hour at top of hour -> next should be 13:00 UTC
    next_run = compute_next_run("0 * * * *", "UTC", base)
    assert next_run == datetime(2026, 8, 8, 13, 0, 0, tzinfo=timezone.utc)

    # Every day at 09:00 UTC
    next_daily = compute_next_run("0 9 * * *", "UTC", base)
    assert next_daily == datetime(2026, 8, 9, 9, 0, 0, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_scheduled_task_crud_and_auth(client):
    async with AsyncSessionLocal() as db:
        org = Client(id=str(uuid4()), name="Test Org")
        site = Site(id=str(uuid4()), client_id=org.id, name="Test Site")
        agent = Agent(
            id=str(uuid4()),
            site_id=site.id,
            hostname="test-host",
            token_hash=str(uuid4()),
            os="Windows 11 Pro",
            trust_state=AgentTrustState.active,
        )
        db.add_all([org, site, agent])
        await db.commit()
        agent_id = agent.id

    # 1. Create schedule
    create_payload = {
        "name": "Hourly Health Check",
        "description": "Runs hourly checks",
        "enabled": True,
        "target_type": "agent",
        "target_id": agent_id,
        "cron_expression": "0 * * * *",
        "timezone": "UTC",
        "kind": "powershell",
        "payload": {"script": "Get-Process"},
        "concurrency_policy": "skip",
        "misfire_policy": "run_once",
    }
    create_resp = await client.post("/scheduled-tasks", json=create_payload)
    assert create_resp.status_code == 201
    task_data = create_resp.json()
    assert task_data["name"] == "Hourly Health Check"
    task_id = task_data["id"]

    # 2. Get schedule
    get_resp = await client.get(f"/scheduled-tasks/{task_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == task_id

    # 3. List schedules
    list_resp = await client.get("/scheduled-tasks")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # 4. Update schedule
    update_resp = await client.put(
        f"/scheduled-tasks/{task_id}",
        json={"name": "Updated Health Check", "cron_expression": "*/30 * * * *"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Updated Health Check"
    assert update_resp.json()["cron_expression"] == "*/30 * * * *"

    # 5. Toggle schedule
    toggle_resp = await client.post(f"/scheduled-tasks/{task_id}/toggle")
    assert toggle_resp.status_code == 200
    assert toggle_resp.json()["enabled"] is False

    toggle_resp2 = await client.post(f"/scheduled-tasks/{task_id}/toggle")
    assert toggle_resp2.status_code == 200
    assert toggle_resp2.json()["enabled"] is True

    # 6. Run now
    run_resp = await client.post(f"/scheduled-tasks/{task_id}/run-now")
    assert run_resp.status_code == 200
    assert run_resp.json()["dispatched"] == 1

    # 7. Delete schedule
    del_resp = await client.delete(f"/scheduled-tasks/{task_id}")
    assert del_resp.status_code == 204

    get_after_del = await client.get(f"/scheduled-tasks/{task_id}")
    assert get_after_del.status_code == 404


@pytest.mark.asyncio
async def test_scheduler_engine_site_target_and_concurrency(client):
    async with AsyncSessionLocal() as db:
        org = Client(id=str(uuid4()), name="Site Org")
        site = Site(id=str(uuid4()), client_id=org.id, name="Site 1")
        agent1 = Agent(id=str(uuid4()), site_id=site.id, token_hash=str(uuid4()), hostname="host-1", os="Win11", trust_state=AgentTrustState.active)
        agent2 = Agent(id=str(uuid4()), site_id=site.id, token_hash=str(uuid4()), hostname="host-2", os="Win11", trust_state=AgentTrustState.active)
        db.add_all([org, site, agent1, agent2])
        await db.commit()

        now = datetime.now(timezone.utc)
        due_task = ScheduledTask(
            id=str(uuid4()),
            name="Site Scheduled Task",
            enabled=True,
            target_type=ScheduleTargetType.site,
            target_id=site.id,
            cron_expression="0 * * * *",
            timezone="UTC",
            kind=CommandKind.shell,
            payload={"command": "dir"},
            concurrency_policy=ScheduleConcurrencyPolicy.skip,
            misfire_policy=ScheduleMisfirePolicy.run_once,
            next_run_at=now - timedelta(minutes=5),  # Due
        )
        db.add(due_task)
        await db.commit()

        # Run scheduler tick
        res = await dispatch_scheduled_tasks_once(db, now=now)
        assert res["dispatched"] == 2  # Dispatched to both active agents in site

        # Verify Command objects created and signed
        cmds_res = await db.execute(select(Command).where(Command.kind == CommandKind.shell))
        cmds = cmds_res.scalars().all()
        assert len(cmds) == 2
        for cmd in cmds:
            assert cmd.status == CommandStatus.queued
            assert cmd.signature is not None

        # Verify task updated next_run_at > now
        await db.refresh(due_task)
        task_next = due_task.next_run_at if due_task.next_run_at.tzinfo is not None else due_task.next_run_at.replace(tzinfo=timezone.utc)
        assert task_next > now
        assert due_task.last_status == "dispatched"

        # Verify audit events
        audit_res = await db.execute(select(AuditEvent).where(AuditEvent.action == "scheduled_task.dispatched"))
        events = audit_res.scalars().all()
        assert len(events) == 2
