# SPDX-License-Identifier: AGPL-3.0-only
"""Recurring task scheduler engine and timezone-aware cron calculator (issue #49)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import approvals as approvals_core
from app.core import audit, metrics, patch_policies as patch_core
from app.core.command_envelope import (
    COMMAND_ENVELOPE_V2,
    COMMAND_ENVELOPE_V3,
    COMMAND_SCHEMA_VERSION,
    format_command_time,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.security import active_signing_key, sign_command
from app.models.models import (
    Agent,
    AgentTrustState,
    Command,
    CommandKind,
    CommandStatus,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
)



def parse_cron_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single 5-part cron field into a set of matching integer values."""
    field = field.strip()
    if field == "*":
        return set(range(min_val, max_val + 1))

    results = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue

        if "/" in part:
            expr, step_str = part.split("/", 1)
            step = int(step_str)
            if step <= 0:
                raise ValueError(f"Invalid step value: {step}")
            if expr == "*":
                start, end = min_val, max_val
            elif "-" in expr:
                start_str, end_str = expr.split("-", 1)
                start, end = int(start_str), int(end_str)
            else:
                start, end = int(expr), max_val
            for val in range(start, end + 1, step):
                if min_val <= val <= max_val:
                    results.add(val)
        elif "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            for val in range(start, end + 1):
                if min_val <= val <= max_val:
                    results.add(val)
        else:
            val = int(part)
            if min_val <= val <= max_val:
                results.add(val)

    return results


def validate_cron_expression(expr: str) -> bool:
    """Validate standard 5-part cron expression (minute hour dom month dow)."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    try:
        minutes = parse_cron_field(parts[0], 0, 59)
        hours = parse_cron_field(parts[1], 0, 23)
        doms = parse_cron_field(parts[2], 1, 31)
        months = parse_cron_field(parts[3], 1, 12)
        dows = parse_cron_field(parts[4], 0, 7)
        return bool(minutes and hours and doms and months and dows)
    except Exception:
        return False


def get_tz(tz_name: str):
    if not tz_name or tz_name.strip().upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc



def compute_next_run(cron_expr: str, tz_name: str, base_dt: datetime) -> datetime:
    """Compute the next run datetime in UTC matching the cron expression and timezone."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have exactly 5 fields")

    minutes = parse_cron_field(parts[0], 0, 59)
    hours = parse_cron_field(parts[1], 0, 23)
    doms = parse_cron_field(parts[2], 1, 31)
    months = parse_cron_field(parts[3], 1, 12)
    raw_dows = parse_cron_field(parts[4], 0, 7)

    # Normalize Sunday 7 to 0
    dows = {0 if d == 7 else d for d in raw_dows}

    tz = get_tz(tz_name)
    if base_dt.tzinfo is None:
        base_dt = base_dt.replace(tzinfo=timezone.utc)

    local_dt = base_dt.astimezone(tz)
    # Move forward at least 1 minute and truncate seconds/microseconds
    curr = (local_dt + timedelta(minutes=1)).replace(second=0, microsecond=0)

    # Search up to 5 years (5 * 366 * 1440 minutes) to prevent infinite loop
    max_minutes = 5 * 366 * 1440
    for _ in range(max_minutes):
        if curr.month in months and curr.day in doms and curr.hour in hours and curr.minute in minutes:
            # Python weekday(): Monday=0, Sunday=6 -> convert to Sunday=0, Monday=1
            cron_dow = (curr.weekday() + 1) % 7
            if cron_dow in dows:
                return curr.astimezone(timezone.utc)
        curr += timedelta(minutes=1)

    raise ValueError("No matching run time found for cron expression")


async def dispatch_scheduled_tasks_once(
    db: AsyncSession, now: datetime | None = None
) -> dict[str, int]:
    """Inspect all due scheduled tasks and dispatch corresponding commands."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    due_tasks_result = await db.execute(
        select(ScheduledTask).where(
            ScheduledTask.enabled == True,
            ScheduledTask.next_run_at <= now,
        )
    )
    due_tasks = due_tasks_result.scalars().all()

    dispatched_count = 0
    skipped_count = 0

    for task in due_tasks:
        # Power operations require a live operator confirmation, current
        # maintenance window, and user-session decision. Refuse even a legacy
        # or directly inserted task so the scheduler cannot bypass dispatch
        # policy merely because the public schema rejects new records.
        if task.kind in {
            CommandKind.reboot,
            CommandKind.shutdown,
            CommandKind.cancel_power_action,
        }:
            task.last_status = "power_operation_refused"
            task.last_run_at = now
            task.next_run_at = compute_next_run(task.cron_expression, task.timezone, now)
            task.updated_at = now
            skipped_count += 1
            continue
        task_next_run = task.next_run_at if task.next_run_at.tzinfo is not None else task.next_run_at.replace(tzinfo=timezone.utc)
        is_misfire = (now - task_next_run) > timedelta(hours=24)

        if is_misfire and task.misfire_policy == ScheduleMisfirePolicy.skip:
            await audit.record(
                db,
                action="scheduled_task.misfire_skipped",
                actor="system",
                detail={
                    "scheduled_task_id": task.id,
                    "scheduled_task_name": task.name,
                    "scheduled_for": task.next_run_at.isoformat(),
                    "detected_at": now.isoformat(),
                },
            )
            task.last_status = "misfire_skipped"
            task.last_run_at = now
            task.next_run_at = compute_next_run(task.cron_expression, task.timezone, now)
            skipped_count += 1
            continue

        # Determine target agents
        target_agents: list[Agent] = []
        if task.target_type == ScheduleTargetType.agent:
            agent_res = await db.execute(
                select(Agent).where(
                    Agent.id == task.target_id,
                    Agent.trust_state == AgentTrustState.active,
                )
            )
            agent = agent_res.scalar_one_or_none()
            if agent:
                target_agents.append(agent)
        elif task.target_type == ScheduleTargetType.site:
            agents_res = await db.execute(
                select(Agent).where(
                    Agent.site_id == task.target_id,
                    Agent.trust_state == AgentTrustState.active,
                )
            )
            target_agents.extend(agents_res.scalars().all())

        task_dispatched_any = False
        # An approval-gated kind is refused per agent; the flag survives the
        # loop so the task's recorded status says why nothing ran.
        task_approval_refused = False
        for agent in target_agents:
            # Two-person authorization (issue #64). An unattended run cannot
            # obtain approval from two live identities at fire time, and
            # pre-approving every future occurrence would defeat the control's
            # per-execution binding. So a scheduled task whose kind is under an
            # approval policy for this endpoint is refused here, the same way
            # power operations are refused above, rather than dispatching
            # around a control an operator deliberately turned on.
            approval_policy = await approvals_core.resolve_policy(db, agent, task.kind)
            if approval_policy is not None:
                await audit.record(
                    db,
                    action="scheduled_task.approval_refused",
                    actor="system",
                    agent_id=agent.id,
                    detail={
                        "scheduled_task_id": task.id,
                        "scheduled_task_name": task.name,
                        "kind": task.kind.value
                        if hasattr(task.kind, "value")
                        else str(task.kind),
                        "agent_id": agent.id,
                        "policy_id": approval_policy.id,
                        "required_approvals": approval_policy.required_approvals,
                    },
                )
                task_approval_refused = True
                skipped_count += 1
                continue
            # Check concurrency policy
            if task.concurrency_policy == ScheduleConcurrencyPolicy.skip:
                active_cmd_res = await db.execute(
                    select(Command).where(
                        Command.agent_id == agent.id,
                        Command.status.in_([
                            CommandStatus.queued,
                            CommandStatus.dispatched,
                            CommandStatus.running,
                            CommandStatus.result_pending,
                        ]),
                        Command.script_version_id == task.script_version_id if task.script_version_id else Command.kind == task.kind,
                    )
                )
                if active_cmd_res.first() is not None:
                    continue

            # Patch approval + maintenance-window gate (issue #52/#53): a scheduled
            # install_updates must honor the effective approval policy and only fire
            # inside an active window, exactly like an interactive dispatch. The
            # payload is narrowed to the approved subset; a blocked outcome skips
            # this agent this tick.
            command_payload = task.payload
            if task.kind == CommandKind.install_updates:
                decision = await patch_core.evaluate_patch_install(db, agent, task.payload, now)
                if decision is not None:
                    await audit.record(
                        db,
                        action="patch_install.gated",
                        actor="system",
                        agent_id=agent.id,
                        detail=decision["gated_detail"],
                    )
                    if decision["reboot_detail"] is not None:
                        await audit.record(
                            db,
                            action="patch_install.reboot_authorized",
                            actor="system",
                            agent_id=agent.id,
                            detail=decision["reboot_detail"],
                        )
                    if decision["outcome"] != "allowed":
                        continue
                    command_payload = decision["payload"]

            # Dispatch command
            envelope_version = (
                select_command_envelope_version(agent.command_envelope_versions or [])
                or COMMAND_ENVELOPE_V2
            )
            key_id = active_signing_key().key_id if envelope_version == COMMAND_ENVELOPE_V3 else None
            nonce = uuid.uuid4().hex

            cmd = Command(
                id=str(uuid.uuid4()),
                agent_id=agent.id,
                kind=task.kind,
                payload=command_payload,
                envelope_version=envelope_version,
                schema_version=COMMAND_SCHEMA_VERSION,
                issued_at=now,
                nonce=nonce,
                signing_key_id=key_id,
                status=CommandStatus.queued,
                created_at=now,
                expires_at=now + timedelta(days=1),
                actor_email=task.created_by_email,
                actor_operator_id=task.created_by_operator_id,
                script_version_id=task.script_version_id,
            )
            db.add(cmd)
            await db.flush()  # assign cmd.id

            cmd.signature = sign_command(
                envelope_version=cmd.envelope_version,
                schema_version=cmd.schema_version,
                command_id=cmd.id,
                agent_id=agent.id,
                kind=cmd.kind.value if hasattr(cmd.kind, "value") else str(cmd.kind),
                payload=cmd.payload,
                issued_at=format_command_time(cmd.issued_at),
                expires_at=format_command_time(cmd.expires_at),
                nonce=cmd.nonce,
                signing_key_id=cmd.signing_key_id,
            )
            task_dispatched_any = True
            dispatched_count += 1


            await audit.record(
                db,
                action="scheduled_task.dispatched",
                actor="system",
                agent_id=agent.id,
                detail={
                    "scheduled_task_id": task.id,
                    "scheduled_task_name": task.name,
                    "command_id": cmd.id,
                    "kind": task.kind.value if hasattr(task.kind, "value") else str(task.kind),
                    "target_type": task.target_type.value if hasattr(task.target_type, "value") else str(task.target_type),
                    "target_id": task.target_id,
                },
            )

        task.last_run_at = now
        task.last_status = (
            "dispatched"
            if task_dispatched_any
            else "approval_required"
            if task_approval_refused
            else "skipped"
        )
        task.next_run_at = compute_next_run(task.cron_expression, task.timezone, now)
        task.updated_at = now

    if dispatched_count > 0 or skipped_count > 0:
        await db.commit()

    return {"dispatched": dispatched_count, "skipped": skipped_count}
