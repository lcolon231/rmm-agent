# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI endpoints for recurring task scheduling (issue #49)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit
from app.core.clientip import client_ip
from app.core.database import get_db
from app.core.scheduler import compute_next_run, dispatch_scheduled_tasks_once
from app.models.models import (
    Agent,
    Operator,
    OperatorRole,
    ScheduleTargetType,
    ScheduledTask,
    Site,
)
from app.schemas.scheduled_tasks import (
    ScheduledTaskCreate,
    ScheduledTaskListOut,
    ScheduledTaskOut,
    ScheduledTaskUpdate,
)


router = APIRouter(
    prefix="/scheduled-tasks",
    tags=["scheduled-tasks"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_evidence(request: Request, operator: Operator) -> dict[str, Any]:
    return {
        "actor": operator.email,
        "actor_user_id": operator.id,
        "source_ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500] or None,
    }


@router.get("", response_model=ScheduledTaskListOut)
async def list_scheduled_tasks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    target_type: ScheduleTargetType | None = Query(None),
    target_id: str | None = Query(None),
    enabled: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List recurring task schedules with optional target/enabled filtering."""
    filters = []
    if target_type is not None:
        filters.append(ScheduledTask.target_type == target_type)
    if target_id is not None:
        filters.append(ScheduledTask.target_id == target_id)
    if enabled is not None:
        filters.append(ScheduledTask.enabled == enabled)

    total = (
        await db.execute(select(func.count()).select_from(ScheduledTask).where(*filters))
    ).scalar_one()

    result = await db.execute(
        select(ScheduledTask)
        .where(*filters)
        .order_by(ScheduledTask.created_at.desc(), ScheduledTask.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = result.scalars().all()
    return ScheduledTaskListOut(
        items=[ScheduledTaskOut.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "",
    response_model=ScheduledTaskOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(OperatorRole.operator))],
)
async def create_scheduled_task(
    body: ScheduledTaskCreate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Create a new recurring task schedule."""
    # Verify target existence
    if body.target_type == ScheduleTargetType.agent:
        agent_res = await db.execute(select(Agent).where(Agent.id == body.target_id))
        if agent_res.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target agent {body.target_id} not found",
            )
    elif body.target_type == ScheduleTargetType.site:
        site_res = await db.execute(select(Site).where(Site.id == body.target_id))
        if site_res.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target site {body.target_id} not found",
            )

    now = _now()
    try:
        next_run = compute_next_run(body.cron_expression, body.timezone, now)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to calculate next run time: {exc}",
        )

    task = ScheduledTask(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        target_type=body.target_type,
        target_id=body.target_id,
        cron_expression=body.cron_expression,
        timezone=body.timezone,
        kind=body.kind,
        script_version_id=body.script_version_id,
        payload=body.payload,
        concurrency_policy=body.concurrency_policy,
        misfire_policy=body.misfire_policy,
        next_run_at=next_run,
        created_by_operator_id=operator.id,
        created_by_email=operator.email,
        created_at=now,
        updated_at=now,
    )
    db.add(task)
    await db.flush()

    evidence = _request_evidence(request, operator)
    evidence.update({
        "scheduled_task_id": task.id,
        "name": task.name,
        "target_type": task.target_type.value,
        "target_id": task.target_id,
        "cron_expression": task.cron_expression,
        "timezone": task.timezone,
        "next_run_at": next_run.isoformat(),
    })
    await audit.record(
        db,
        action="scheduled_task.created",
        actor=operator.email,
        detail=evidence,
    )
    await db.commit()
    await db.refresh(task)
    return ScheduledTaskOut.model_validate(task)


@router.get("/{task_id}", response_model=ScheduledTaskOut)
async def get_scheduled_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Fetch details for a specific scheduled task."""
    result = await db.execute(select(ScheduledTask).where(ScheduledTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled task {task_id} not found",
        )
    return ScheduledTaskOut.model_validate(task)


@router.put(
    "/{task_id}",
    response_model=ScheduledTaskOut,
    dependencies=[Depends(require_role(OperatorRole.operator))],
)
async def update_scheduled_task(
    task_id: str,
    body: ScheduledTaskUpdate,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Update a scheduled task configuration."""
    result = await db.execute(select(ScheduledTask).where(ScheduledTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled task {task_id} not found",
        )

    now = _now()
    if body.name is not None:
        task.name = body.name
    if body.description is not None:
        task.description = body.description
    if body.enabled is not None:
        task.enabled = body.enabled
    if body.payload is not None:
        task.payload = body.payload
    if body.concurrency_policy is not None:
        task.concurrency_policy = body.concurrency_policy
    if body.misfire_policy is not None:
        task.misfire_policy = body.misfire_policy

    cron_changed = body.cron_expression is not None and body.cron_expression != task.cron_expression
    tz_changed = body.timezone is not None and body.timezone != task.timezone

    if cron_changed or tz_changed:
        if body.cron_expression is not None:
            task.cron_expression = body.cron_expression
        if body.timezone is not None:
            task.timezone = body.timezone
        try:
            task.next_run_at = compute_next_run(task.cron_expression, task.timezone, now)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to calculate next run time: {exc}",
            )

    task.updated_at = now

    evidence = _request_evidence(request, operator)
    evidence.update({
        "scheduled_task_id": task.id,
        "name": task.name,
        "enabled": task.enabled,
        "next_run_at": task.next_run_at.isoformat(),
    })
    await audit.record(
        db,
        action="scheduled_task.updated",
        actor=operator.email,
        detail=evidence,
    )
    await db.commit()
    await db.refresh(task)
    return ScheduledTaskOut.model_validate(task)


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(OperatorRole.operator))],
)
async def delete_scheduled_task(
    task_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scheduled task."""
    result = await db.execute(select(ScheduledTask).where(ScheduledTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled task {task_id} not found",
        )

    evidence = _request_evidence(request, operator)
    evidence.update({
        "scheduled_task_id": task.id,
        "name": task.name,
        "target_type": task.target_type.value,
        "target_id": task.target_id,
    })
    await audit.record(
        db,
        action="scheduled_task.deleted",
        actor=operator.email,
        detail=evidence,
    )
    await db.delete(task)
    await db.commit()


@router.post(
    "/{task_id}/toggle",
    response_model=ScheduledTaskOut,
    dependencies=[Depends(require_role(OperatorRole.operator))],
)
async def toggle_scheduled_task(
    task_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Toggle a scheduled task enabled/disabled state."""
    result = await db.execute(select(ScheduledTask).where(ScheduledTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled task {task_id} not found",
        )

    now = _now()
    task.enabled = not task.enabled
    if task.enabled:
        task.next_run_at = compute_next_run(task.cron_expression, task.timezone, now)
    task.updated_at = now

    evidence = _request_evidence(request, operator)
    evidence.update({
        "scheduled_task_id": task.id,
        "name": task.name,
        "enabled": task.enabled,
    })
    await audit.record(
        db,
        action="scheduled_task.toggled",
        actor=operator.email,
        detail=evidence,
    )
    await db.commit()
    await db.refresh(task)
    return ScheduledTaskOut.model_validate(task)


@router.post(
    "/{task_id}/run-now",
    dependencies=[Depends(require_role(OperatorRole.operator))],
)
async def run_scheduled_task_now(
    task_id: str,
    request: Request,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger immediate execution of a scheduled task."""
    result = await db.execute(select(ScheduledTask).where(ScheduledTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled task {task_id} not found",
        )

    now = _now()
    # Set next_run_at to now to force immediate dispatch
    task.next_run_at = now
    await db.flush()
    res = await dispatch_scheduled_tasks_once(db, now=now)


    evidence = _request_evidence(request, operator)
    evidence.update({
        "scheduled_task_id": task.id,
        "name": task.name,
        "dispatched_count": res["dispatched"],
    })
    await audit.record(
        db,
        action="scheduled_task.manually_triggered",
        actor=operator.email,
        detail=evidence,
    )
    await db.commit()
    return {"status": "triggered", "dispatched": res["dispatched"]}
