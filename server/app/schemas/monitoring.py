# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy and check-result contracts (issue #41).

This module defines the *shape* of monitoring — versioned, scoped policies whose
check sets are validated here before storage, plus the check-result record #42's
agent-side evaluation will produce. It deliberately does not implement
evaluation, alerting, or suppression; those are #42/#43+.

The conventions mirror ``app/schemas/inventory.py``: ``extra="forbid"`` on every
model so an unexpected field is rejected rather than silently stored, bounded
collections and string lengths, and a per-type registry (``CHECK_PARAM_MODELS``)
that picks the right params model — the same idea as inventory's
``SECTION_MODELS``.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.models.models import CheckResultStatus, CheckType, MonitoringScope

# --------------------------------------------------------------------------- #
# Bounds (schema-level; runtime quotas live in app/core/config.py)
# --------------------------------------------------------------------------- #
#: Most checks one policy may carry. A policy is a curated set, not a dumping
#: ground; the cap keeps effective-policy resolution and storage bounded.
MAX_CHECKS_PER_POLICY = 100
#: Schedule interval bounds. Below the minimum an agent would spend its beat
#: budget evaluating; above the maximum a check is no longer "monitoring".
MIN_CHECK_INTERVAL_SECONDS = 30
MAX_CHECK_INTERVAL_SECONDS = 86_400
#: Consecutive-sample bounds for hysteresis (breach/clear debouncing).
MAX_HYSTERESIS_SAMPLES = 100

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)]
#: A stable, lowercase slug identifying a check within a policy. It is the key
#: effective-policy resolution merges on, so it must be machine-stable.
CheckKey = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
Note = Annotated[str, StringConstraints(max_length=2_000, strip_whitespace=True)]


class ThresholdOp(str, Enum):
    """How a check's measured value is compared against its thresholds.

    ``gt``/``gte`` alarm when the value rises (CPU, disk usage); ``lt``/``lte``
    alarm when it falls (free space, uptime). The direction determines the
    required ordering of the warning and critical values.
    """

    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"


class Threshold(BaseModel):
    """Warning/critical bounds for a numeric check.

    At least one of ``warning``/``critical`` must be set. Their required order
    depends on ``op``: for rising comparisons critical must be >= warning; for
    falling comparisons critical must be <= warning. Getting this wrong would
    make a check that can never reach critical, so it is rejected here.
    """

    model_config = ConfigDict(extra="forbid")
    op: ThresholdOp
    warning: float | None = None
    critical: float | None = None

    @model_validator(mode="after")
    def _validate_bounds(self) -> "Threshold":
        if self.warning is None and self.critical is None:
            raise ValueError("threshold requires at least one of warning/critical")
        if self.warning is not None and self.critical is not None:
            rising = self.op in (ThresholdOp.gt, ThresholdOp.gte)
            if rising and self.critical < self.warning:
                raise ValueError("critical must be >= warning for a rising threshold")
            if not rising and self.critical > self.warning:
                raise ValueError("critical must be <= warning for a falling threshold")
        return self


class Hysteresis(BaseModel):
    """How many consecutive samples must agree before a state change.

    Debounces flapping: ``raise_samples`` breaches in a row are needed to alarm
    and ``clear_samples`` passes in a row to recover. Defaults of 1 mean no
    debouncing.
    """

    model_config = ConfigDict(extra="forbid")
    raise_samples: int = Field(default=1, ge=1, le=MAX_HYSTERESIS_SAMPLES)
    clear_samples: int = Field(default=1, ge=1, le=MAX_HYSTERESIS_SAMPLES)


class Schedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interval_seconds: int = Field(
        ge=MIN_CHECK_INTERVAL_SECONDS, le=MAX_CHECK_INTERVAL_SECONDS
    )


# --------------------------------------------------------------------------- #
# Per-check-type params (registry, like inventory's SECTION_MODELS)
# --------------------------------------------------------------------------- #
class _NoParams(BaseModel):
    """A check that takes no parameters (cpu, memory, reboot_pending, uptime)."""

    model_config = ConfigDict(extra="forbid")


class DiskParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: The volume to evaluate, e.g. "C:". Required — a disk check without a
    #: target is ambiguous on a multi-volume machine.
    mount_point: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class ServiceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: Annotated[str, StringConstraints(min_length=1, max_length=256)]


#: Check type -> params model. ``typed_params`` uses this so an unknown or
#: malformed params object is rejected at policy-submit time, not at evaluation.
CHECK_PARAM_MODELS: dict[CheckType, type[BaseModel]] = {
    CheckType.cpu: _NoParams,
    CheckType.memory: _NoParams,
    CheckType.disk: DiskParams,
    CheckType.service: ServiceParams,
    CheckType.reboot_pending: _NoParams,
    CheckType.uptime: _NoParams,
}

#: Check types that carry a numeric threshold. ``reboot_pending`` is a boolean
#: state (a reboot is or is not pending), so it is threshold-free; the rest are
#: measured against warning/critical bounds.
THRESHOLD_FREE_TYPES = frozenset({CheckType.reboot_pending})


class CheckDefinition(BaseModel):
    """One configured check within a policy."""

    model_config = ConfigDict(extra="forbid")

    key: CheckKey
    type: CheckType
    enabled: bool = True
    schedule: Schedule
    threshold: Threshold | None = None
    hysteresis: Hysteresis = Field(default_factory=Hysteresis)
    params: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_type_specifics(self) -> "CheckDefinition":
        # Reject unknown/malformed params against this type's model.
        CHECK_PARAM_MODELS[self.type].model_validate(self.params)
        # Threshold presence must match the check family.
        if self.type in THRESHOLD_FREE_TYPES:
            if self.threshold is not None:
                raise ValueError(f"{self.type.value} check does not take a threshold")
        elif self.threshold is None:
            raise ValueError(f"{self.type.value} check requires a threshold")
        return self


def _unique_keys(checks: list[CheckDefinition]) -> list[CheckDefinition]:
    keys = [c.key for c in checks]
    if len(keys) != len(set(keys)):
        raise ValueError("check keys must be unique within a policy")
    return checks


def _validate_scope(scope: MonitoringScope, scope_id: str | None) -> None:
    if scope == MonitoringScope.global_ and scope_id is not None:
        raise ValueError("global scope must not include a scope_id")
    if scope != MonitoringScope.global_ and not scope_id:
        raise ValueError(f"{scope.value} scope requires a scope_id")


# --------------------------------------------------------------------------- #
# Policy request/response
# --------------------------------------------------------------------------- #
class MonitoringPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText
    scope: MonitoringScope
    scope_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    enabled: bool = True
    checks: list[CheckDefinition] = Field(
        default_factory=list, max_length=MAX_CHECKS_PER_POLICY
    )
    change_note: Note | None = None

    _keys = field_validator("checks")(_unique_keys)

    @model_validator(mode="after")
    def _scope_consistency(self) -> "MonitoringPolicyCreate":
        _validate_scope(self.scope, self.scope_id)
        return self


class MonitoringPolicyUpdate(BaseModel):
    """A new revision: replaces the check set and optionally toggles enabled.

    Scope and name are identity and are not changed by a revision; create a new
    policy for a different target.
    """

    model_config = ConfigDict(extra="forbid")
    checks: list[CheckDefinition] = Field(
        default_factory=list, max_length=MAX_CHECKS_PER_POLICY
    )
    enabled: bool | None = None
    change_note: Note | None = None

    _keys = field_validator("checks")(_unique_keys)


class MonitoringPolicyRevisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    version: int
    change_note: str | None
    created_by: str | None
    created_at: datetime
    checks: list[CheckDefinition] = Field(default_factory=list)


class MonitoringPolicyOut(BaseModel):
    id: str
    name: str
    scope: MonitoringScope
    scope_id: str | None
    enabled: bool
    created_at: datetime
    current_version: int
    check_count: int = Field(ge=0)


class MonitoringPolicyDetailOut(MonitoringPolicyOut):
    checks: list[CheckDefinition] = Field(default_factory=list)
    revisions: list[MonitoringPolicyRevisionOut] = Field(default_factory=list)


class EffectiveCheckOut(BaseModel):
    """One check in an agent's resolved policy, with where it came from."""

    definition: CheckDefinition
    source_scope: MonitoringScope
    source_policy_id: str
    source_policy_name: str


class EffectivePolicyOut(BaseModel):
    agent_id: str
    checks: list[EffectiveCheckOut] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Maintenance windows
# --------------------------------------------------------------------------- #
class MaintenanceWindowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText
    scope: MonitoringScope
    scope_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    starts_at: datetime
    ends_at: datetime

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _must_be_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("maintenance window times must include a timezone offset")
        return value

    @model_validator(mode="after")
    def _validate(self) -> "MaintenanceWindowCreate":
        _validate_scope(self.scope, self.scope_id)
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        return self


class MaintenanceWindowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    scope: MonitoringScope
    scope_id: str | None
    starts_at: datetime
    ends_at: datetime
    created_by: str | None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Check results (contract #42 populates; #41 defines + reads)
# --------------------------------------------------------------------------- #
class CheckResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    policy_id: str | None
    policy_revision_id: str | None
    check_key: str
    status: CheckResultStatus
    value: float | None
    detail: dict | None
    evaluated_at: datetime
    received_at: datetime


class CheckResultListOut(BaseModel):
    agent_id: str
    items: list[CheckResultOut] = Field(default_factory=list)
