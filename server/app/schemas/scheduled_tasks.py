# SPDX-License-Identifier: AGPL-3.0-only
"""Pydantic schemas for recurring task scheduling (issue #49)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


from app.core.scheduler import validate_cron_expression
from app.models.models import (
    CommandKind,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
)


class ScheduledTaskCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    enabled: bool = True
    target_type: ScheduleTargetType
    target_id: str = Field(..., min_length=1, max_length=36)
    cron_expression: str = Field(..., min_length=5, max_length=100)
    timezone: str = Field("UTC", min_length=1, max_length=100)
    kind: CommandKind
    script_version_id: str | None = Field(None, max_length=36)
    payload: dict = Field(default_factory=dict)
    concurrency_policy: ScheduleConcurrencyPolicy = ScheduleConcurrencyPolicy.skip
    misfire_policy: ScheduleMisfirePolicy = ScheduleMisfirePolicy.run_once

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        if not validate_cron_expression(v):
            raise ValueError("Invalid 5-field cron expression")
        return v.strip()

    @field_validator("kind")
    @classmethod
    def power_operations_cannot_be_recurring(cls, value: CommandKind) -> CommandKind:
        if value in {
            CommandKind.reboot,
            CommandKind.shutdown,
            CommandKind.cancel_power_action,
        }:
            raise ValueError(
                "power operations require live confirmation and cannot be scheduled tasks"
            )
        return value


class ScheduledTaskUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    enabled: bool | None = None
    cron_expression: str | None = Field(None, min_length=5, max_length=100)
    timezone: str | None = Field(None, min_length=1, max_length=100)
    payload: dict | None = None
    concurrency_policy: ScheduleConcurrencyPolicy | None = None
    misfire_policy: ScheduleMisfirePolicy | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str | None) -> str | None:
        if v is not None and not validate_cron_expression(v):
            raise ValueError("Invalid 5-field cron expression")
        return v.strip() if v is not None else None


class ScheduledTaskOut(BaseModel):
    id: str
    name: str
    description: str | None
    enabled: bool
    target_type: ScheduleTargetType
    target_id: str
    cron_expression: str
    timezone: str
    kind: CommandKind
    script_version_id: str | None
    payload: dict
    concurrency_policy: ScheduleConcurrencyPolicy
    misfire_policy: ScheduleMisfirePolicy
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    created_by_operator_id: str | None
    created_by_email: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)



class ScheduledTaskListOut(BaseModel):
    items: list[ScheduledTaskOut]
    total: int
    page: int
    page_size: int
