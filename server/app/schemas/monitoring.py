# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy, check-result, and alert contracts (#41-#43).

This module defines the *shape* of monitoring — versioned, scoped policies whose
check sets are validated here before storage, plus the revision-pinned agent
assignment and idempotent result-ingestion shapes implemented by #42, and the
deduplicated automatic alert-state read contract from #43. Technician alert
actions remain #44.

The conventions mirror ``app/schemas/inventory.py``: ``extra="forbid"`` on every
model so an unexpected field is rejected rather than silently stored, bounded
collections and string lengths, and a per-type registry (``CHECK_PARAM_MODELS``)
that picks the right params model — the same idea as inventory's
``SECTION_MODELS``.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
import json
import math
import re
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.models.models import (
    AlertEventType,
    AlertState,
    CheckResultStatus,
    CheckType,
    EmailAttemptStatus,
    EmailDeliveryStatus,
    MonitoringScope,
    WebhookAttemptStatus,
    WebhookDeliveryStatus,
)

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
PATCH_AGE_MIN_INTERVAL_SECONDS = 3_600
#: Consecutive-sample bounds for hysteresis (breach/clear debouncing).
MAX_HYSTERESIS_SAMPLES = 100
MAX_RESULTS_PER_BATCH = 100
MAX_RESULT_DETAIL_BYTES = 16 * 1024

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
    CheckType.offline: _NoParams,
    CheckType.cpu: _NoParams,
    CheckType.memory: _NoParams,
    CheckType.disk: DiskParams,
    CheckType.service: ServiceParams,
    CheckType.reboot_pending: _NoParams,
    CheckType.uptime: _NoParams,
    CheckType.patch_age: _NoParams,
}

#: State checks derive status directly rather than comparing a numeric sample.
THRESHOLD_FREE_TYPES = frozenset({CheckType.reboot_pending})
#: #41 originally required a numeric threshold for service checks. #42 does
#: not use it, but accepts it so already-stored revisions remain readable.
THRESHOLD_OPTIONAL_TYPES = frozenset({CheckType.service})


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

    @model_validator(mode="before")
    @classmethod
    def _reject_patch_age_falling_threshold(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        check_type = data.get("type")
        threshold = data.get("threshold")
        if check_type in (CheckType.patch_age, CheckType.patch_age.value) and isinstance(
            threshold, dict
        ):
            op = threshold.get("op")
            if op in (ThresholdOp.lt, ThresholdOp.lte, "lt", "lte"):
                raise ValueError("patch_age check requires a rising threshold")
        return data

    @model_validator(mode="after")
    def _validate_type_specifics(self) -> "CheckDefinition":
        # Reject unknown/malformed params against this type's model.
        CHECK_PARAM_MODELS[self.type].model_validate(self.params)
        # Threshold presence must match the check family.
        if self.type in THRESHOLD_FREE_TYPES:
            if self.threshold is not None:
                raise ValueError(f"{self.type.value} check does not take a threshold")
        elif self.type not in THRESHOLD_OPTIONAL_TYPES and self.threshold is None:
            raise ValueError(f"{self.type.value} check requires a threshold")
        if self.type is CheckType.patch_age:
            if self.schedule.interval_seconds < PATCH_AGE_MIN_INTERVAL_SECONDS:
                raise ValueError(
                    "patch_age check interval must be at least 3600 seconds"
                )
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
    source_revision_id: str
    source_policy_name: str


class EffectivePolicyOut(BaseModel):
    agent_id: str
    checks: list[EffectiveCheckOut] = Field(default_factory=list)


class AgentCheckAssignment(BaseModel):
    """Revision-pinned check definition delivered to an authenticated agent."""

    model_config = ConfigDict(extra="forbid")
    definition: CheckDefinition
    policy_id: str
    policy_revision_id: str


class AgentCheckResultIn(BaseModel):
    """One durable agent evaluation. ``id`` is its idempotency key."""

    model_config = ConfigDict(extra="forbid")
    id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    policy_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    policy_revision_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    check_key: CheckKey
    status: CheckResultStatus
    value: float | None = None
    detail: dict | None = None
    evaluated_at: datetime

    @field_validator("value")
    @classmethod
    def value_must_be_finite(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("check result value must be finite")
        return value

    @field_validator("detail")
    @classmethod
    def detail_must_be_bounded_json(cls, value: dict | None) -> dict | None:
        if value is None:
            return None
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("check result detail must be finite JSON") from exc
        if len(encoded) > MAX_RESULT_DETAIL_BYTES:
            raise ValueError(
                f"check result detail exceeds {MAX_RESULT_DETAIL_BYTES} bytes"
            )
        return value

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("evaluated_at must include a timezone offset")
        return value


class AgentCheckResultBatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    results: list[AgentCheckResultIn] = Field(
        default_factory=list, min_length=1, max_length=MAX_RESULTS_PER_BATCH
    )

    @field_validator("results")
    @classmethod
    def result_ids_must_be_unique(
        cls, value: list[AgentCheckResultIn]
    ) -> list[AgentCheckResultIn]:
        ids = [result.id for result in value]
        if len(ids) != len(set(ids)):
            raise ValueError("check result IDs must be unique within a batch")
        return value


class AgentCheckResultAck(BaseModel):
    ok: bool = True
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)


# --------------------------------------------------------------------------- #
# Maintenance windows
# --------------------------------------------------------------------------- #
#: One week in minutes bounds a single recurring occurrence's duration.
MAX_MAINTENANCE_DURATION_MINUTES = 7 * 24 * 60
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class WeeklyRecurrence(BaseModel):
    """A weekly recurring sub-span within a window's overall validity (#52).

    ``days`` are ISO weekday numbers 0=Monday..6=Sunday. ``start`` is a local
    "HH:MM" wall-clock time in the window's timezone; ``duration_minutes`` is how
    long each occurrence stays open. Evaluation converts "now" into the window
    timezone via ``zoneinfo`` so DST transitions are handled correctly.
    """

    model_config = ConfigDict(extra="forbid")
    days: list[int] = Field(min_length=1, max_length=7)
    start: str
    duration_minutes: int = Field(ge=1, le=MAX_MAINTENANCE_DURATION_MINUTES)

    @field_validator("days")
    @classmethod
    def _days_unique_in_range(cls, value: list[int]) -> list[int]:
        if any(day < 0 or day > 6 for day in value):
            raise ValueError("recurrence days must be 0 (Monday) through 6 (Sunday)")
        if len(set(value)) != len(value):
            raise ValueError("recurrence days must be unique")
        return sorted(value)

    @field_validator("start")
    @classmethod
    def _start_is_hhmm(cls, value: str) -> str:
        if not _HHMM_RE.fullmatch(value):
            raise ValueError("recurrence start must be a 24-hour HH:MM local time")
        return value


def _validate_timezone(value: str) -> str:
    if value.strip().upper() in ("UTC", "Z", "GMT"):
        return "UTC"
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise ValueError("timezone must be a valid IANA name (e.g. America/New_York)") from exc
    return value


class MaintenanceWindowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText
    scope: MonitoringScope
    scope_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    starts_at: datetime
    ends_at: datetime
    timezone: str = "UTC"
    recurrence: WeeklyRecurrence | None = None

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _must_be_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("maintenance window times must include a timezone offset")
        return value

    @field_validator("timezone")
    @classmethod
    def _timezone_is_valid(cls, value: str) -> str:
        return _validate_timezone(value)

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
    timezone: str = "UTC"
    recurrence: WeeklyRecurrence | None = None
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


# --------------------------------------------------------------------------- #
# Deduplicated alert state (#43)
# --------------------------------------------------------------------------- #
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    policy_id: str
    policy_revision_id: str
    check_key: str
    state: AlertState
    last_result_status: CheckResultStatus
    occurrence_count: int = Field(ge=0)
    total_occurrence_count: int = Field(ge=0)
    generation: int = Field(ge=0)
    first_opened_at: datetime | None
    opened_at: datetime | None
    last_observed_at: datetime | None
    resolved_at: datetime | None
    last_evaluated_at: datetime | None
    last_result_id: str | None
    last_value: float | None
    resolution_reason: str | None
    assigned_to_operator_id: str | None
    assigned_to_email: str | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    version: int = Field(ge=1)
    suppression_window_id: str | None
    suppressed_until: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertListOut(BaseModel):
    items: list[AlertOut] = Field(default_factory=list)


class AlertObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    check_result_id: str
    alert_id: str
    status: CheckResultStatus
    value: float | None
    evaluated_at: datetime
    out_of_order: bool
    created_at: datetime


class AlertDetailOut(AlertOut):
    observations: list[AlertObservationOut] = Field(default_factory=list)
    events: list["AlertEventOut"] = Field(default_factory=list)


class AlertEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    alert_id: str
    generation: int = Field(ge=0)
    event_type: AlertEventType
    from_state: AlertState | None
    to_state: AlertState | None
    actor: str
    actor_user_id: str | None
    comment: str | None
    comment_redacted: bool
    assigned_to_operator_id: str | None
    assigned_to_email: str | None
    source_result_id: str | None
    request_id: str | None
    created_at: datetime


class AlertActionBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    ]
    expected_version: int = Field(ge=1)
    comment: Annotated[str, StringConstraints(max_length=2_000, strip_whitespace=True)] | None = None


class AlertAcknowledge(AlertActionBase):
    pass


class AlertComment(AlertActionBase):
    comment: Annotated[str, StringConstraints(min_length=1, max_length=2_000, strip_whitespace=True)]


class AlertResolve(AlertActionBase):
    comment: Annotated[str, StringConstraints(min_length=1, max_length=2_000, strip_whitespace=True)]


class AlertAssign(AlertActionBase):
    assigned_to_operator_id: str | None


class AlertAssigneeOut(BaseModel):
    id: str
    email: str


class AlertEmailAttemptOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    attempt_number: int = Field(ge=1)
    status: EmailAttemptStatus
    provider_message_id: str | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None


class AlertEmailDeliveryOut(BaseModel):
    id: str
    alert_id: str
    alert_event_id: str
    generation: int = Field(ge=0)
    event_type: AlertEventType
    recipient: str
    status: EmailDeliveryStatus
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    next_attempt_at: datetime
    provider_message_id: str | None
    last_error_code: str | None
    sent_at: datetime | None
    created_at: datetime
    updated_at: datetime
    attempts: list[AlertEmailAttemptOut] = Field(default_factory=list)


class AlertEmailDeliveryListOut(BaseModel):
    items: list[AlertEmailDeliveryOut] = Field(default_factory=list)


class AlertEmailStatusOut(BaseModel):
    provider: str
    enabled: bool
    valid: bool
    problems: list[str] = Field(default_factory=list)
    recipient_count: int = Field(ge=0, le=50)
    sender_configured: bool
    api_key_configured: bool
    counts: dict[str, int]


class AlertEmailRetry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    ]


# --------------------------------------------------------------------------- #
# Versioned signed webhook notifications (#46)
# --------------------------------------------------------------------------- #
WEBHOOK_EVENT_TYPES = frozenset(
    {
        AlertEventType.opened,
        AlertEventType.reopened,
        AlertEventType.acknowledged,
        AlertEventType.manual_resolution,
        AlertEventType.automatic_recovery,
        AlertEventType.policy_revised,
        AlertEventType.policy_deleted,
        AlertEventType.policy_superseded,
    }
)


class WebhookEndpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ]
    url: Annotated[
        str, StringConstraints(min_length=1, max_length=2_048, strip_whitespace=True)
    ]
    event_types: list[AlertEventType] = Field(
        default_factory=lambda: sorted(WEBHOOK_EVENT_TYPES, key=lambda item: item.value),
        min_length=1,
        max_length=8,
    )
    enabled: bool = True

    @field_validator("event_types")
    @classmethod
    def validate_webhook_event_types(
        cls, value: list[AlertEventType]
    ) -> list[AlertEventType]:
        if len(set(value)) != len(value) or not set(value) <= WEBHOOK_EVENT_TYPES:
            raise ValueError("event_types must be unique supported alert transitions")
        return value


class WebhookEndpointUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    ]
    expected_version: int = Field(ge=1)
    name: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ] | None = None
    url: Annotated[
        str, StringConstraints(min_length=1, max_length=2_048, strip_whitespace=True)
    ] | None = None
    event_types: list[AlertEventType] | None = Field(
        default=None, min_length=1, max_length=8
    )
    enabled: bool | None = None

    @field_validator("event_types")
    @classmethod
    def validate_webhook_event_types(
        cls, value: list[AlertEventType] | None
    ) -> list[AlertEventType] | None:
        if value is not None and (
            len(set(value)) != len(value) or not set(value) <= WEBHOOK_EVENT_TYPES
        ):
            raise ValueError("event_types must be unique supported alert transitions")
        return value

    @model_validator(mode="after")
    def require_change(self):
        if all(
            value is None
            for value in (self.name, self.url, self.event_types, self.enabled)
        ):
            raise ValueError("at least one endpoint field must be supplied")
        return self


class WebhookEndpointOut(BaseModel):
    id: str
    name: str
    url: str
    event_types: list[AlertEventType]
    enabled: bool
    current_secret_version: int = Field(ge=1)
    current_secret_key_id: str
    version: int = Field(ge=1)
    deleted_at: datetime | None
    created_at: datetime
    updated_at: datetime


class WebhookEndpointSecretOut(WebhookEndpointOut):
    secret: str
    signing_algorithm: str = "HMAC-SHA256"
    signature_header: str = "X-NodeLink-Signature"


class WebhookDestinationValidationOut(BaseModel):
    endpoint_id: str
    state: str
    code: str | None = None
    resolved_address_count: int = Field(ge=0)


class WebhookSecretRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    ]
    expected_version: int = Field(ge=1)


class AlertWebhookAttemptOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    attempt_number: int = Field(ge=1)
    status: WebhookAttemptStatus
    http_status: int | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None


class AlertWebhookDeliveryOut(BaseModel):
    id: str
    endpoint_id: str
    endpoint_name: str
    alert_id: str
    alert_event_id: str
    generation: int = Field(ge=0)
    event_type: AlertEventType
    destination: str
    status: WebhookDeliveryStatus
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    next_attempt_at: datetime
    last_http_status: int | None
    last_error_code: str | None
    delivered_at: datetime | None
    created_at: datetime
    updated_at: datetime
    attempts: list[AlertWebhookAttemptOut] = Field(default_factory=list)


class AlertWebhookDeliveryListOut(BaseModel):
    items: list[AlertWebhookDeliveryOut] = Field(default_factory=list)


class WebhookStatusOut(BaseModel):
    encryption_key_configured: bool
    endpoint_count: int = Field(ge=0)
    enabled_endpoint_count: int = Field(ge=0)
    endpoint_limit: int = Field(ge=1)
    counts: dict[str, int]


class AlertWebhookRetry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    ]
