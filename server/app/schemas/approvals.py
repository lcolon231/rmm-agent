# SPDX-License-Identifier: AGPL-3.0-only
"""Approval workflow and two-person authorization contracts (issue #64).

Mirrors ``app/schemas/patch_policies.py``: ``extra="forbid"`` everywhere,
bounded strings and collections, and scope validation shared with the
monitoring policies.

Two contracts are deliberately strict beyond ordinary input validation:

* A **reason is mandatory** on a request and on every decision, with the same
  printable-UTF-8 bounds power operations already require. An approval with no
  stated basis is a click, not evidence.
* A policy's **command kinds are an explicit closed list**. There is no "all
  kinds" wildcard: an administrator must name what they are putting behind
  dual control, so a later addition to ``CommandKind`` is never silently swept
  into (or out of) an existing policy.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.core.approvals import (
    MAX_REASON_BYTES,
    MAX_REQUEST_TTL_SECONDS,
    MIN_REASON_BYTES,
    MIN_REQUEST_TTL_SECONDS,
)
from app.models.models import (
    ApprovalDecisionKind,
    ApprovalRequestStatus,
    CommandKind,
    MonitoringScope,
    OperatorRole,
)
from app.schemas.monitoring import _validate_scope

# A policy may not name more kinds than exist; the bound is a cheap guard on a
# hostile request body, not a product limit.
MAX_POLICY_COMMAND_KINDS = 64

ShortText = Annotated[
    str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
]


def _distinct_kinds(value: list[CommandKind] | None) -> list[CommandKind] | None:
    if value is not None and len({kind.value for kind in value}) != len(value):
        raise ValueError("command_kinds must not repeat a kind")
    return value


def _validate_reason(value: str) -> str:
    """Bounded, printable justification prose.

    Control characters are refused rather than stripped: a reason is displayed
    to approvers and digested into the audit chain, and silently rewriting what
    someone wrote would make the stored digest disagree with what they typed.
    """
    reason = value.strip()
    size = len(reason.encode("utf-8"))
    if not MIN_REASON_BYTES <= size <= MAX_REASON_BYTES:
        raise ValueError(
            f"reason must contain {MIN_REASON_BYTES}-{MAX_REASON_BYTES} UTF-8 bytes"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in reason):
        raise ValueError("reason must be printable")
    return reason


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
class ApprovalPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ShortText
    scope: MonitoringScope
    scope_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    command_kinds: list[CommandKind] = Field(
        min_length=1, max_length=MAX_POLICY_COMMAND_KINDS
    )
    required_approvals: int = Field(default=2, ge=1, le=2)
    request_ttl_seconds: int = Field(
        default=3600, ge=MIN_REQUEST_TTL_SECONDS, le=MAX_REQUEST_TTL_SECONDS
    )
    enabled: bool = True

    _distinct = field_validator("command_kinds")(_distinct_kinds)

    @model_validator(mode="after")
    def _scope_consistency(self) -> "ApprovalPolicyCreate":
        _validate_scope(self.scope, self.scope_id)
        return self


class ApprovalPolicyUpdate(BaseModel):
    """Edit the terms of a policy. Name and scope are identity and are fixed.

    Every field is optional so an administrator can disable a policy without
    restating its kind list. Changes never reach requests already in flight --
    those carry the terms they were raised under.
    """

    model_config = ConfigDict(extra="forbid")

    command_kinds: list[CommandKind] | None = Field(
        default=None, min_length=1, max_length=MAX_POLICY_COMMAND_KINDS
    )
    required_approvals: int | None = Field(default=None, ge=1, le=2)
    request_ttl_seconds: int | None = Field(
        default=None, ge=MIN_REQUEST_TTL_SECONDS, le=MAX_REQUEST_TTL_SECONDS
    )
    enabled: bool | None = None

    _distinct = field_validator("command_kinds")(_distinct_kinds)

    @model_validator(mode="after")
    def _at_least_one_change(self) -> "ApprovalPolicyUpdate":
        if all(
            getattr(self, field) is None
            for field in (
                "command_kinds",
                "required_approvals",
                "request_ttl_seconds",
                "enabled",
            )
        ):
            raise ValueError("an update must change at least one field")
        return self


class ApprovalPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    scope: MonitoringScope
    scope_id: str | None
    command_kinds: list[str]
    required_approvals: int
    request_ttl_seconds: int
    enabled: bool
    created_at: datetime
    created_by: str | None
    updated_at: datetime | None
    updated_by: str | None


# --------------------------------------------------------------------------- #
# Requests and decisions
# --------------------------------------------------------------------------- #
class ApprovalRequestCreate(BaseModel):
    """The command an operator proposes to run, exactly as they would run it.

    ``payload`` is validated by the same command payload rules the dispatch
    endpoint applies, in the handler, so an approval can never be raised for a
    payload the dispatcher would reject -- which would otherwise produce
    approvals that can never be spent.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    kind: CommandKind
    payload: dict = Field(default_factory=dict)
    reason: str

    _reason = field_validator("reason")(_validate_reason)


class ApprovalDecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str

    _reason = field_validator("reason")(_validate_reason)


class ApprovalDecisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    operator_id: str
    operator_email: str
    operator_role: OperatorRole
    decision: ApprovalDecisionKind
    reason: str | None
    created_at: datetime


class ApprovalRequestOut(BaseModel):
    """List/summary view. Carries the binding digest but not the payload.

    Payload values are only returned on the detail read, so the reviewer queue
    can be shown widely without distributing the contents of every proposed
    command.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    client_id: str | None
    site_id: str | None
    kind: CommandKind
    status: ApprovalRequestStatus
    payload_sha256: str
    policy_id: str | None
    required_approvals: int
    approvals_recorded: int
    requested_by_email: str
    requested_by_operator_id: str | None
    reason: str
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    consumed_at: datetime | None


class ApprovalRequestDetail(ApprovalRequestOut):
    payload: dict
    payload_keys: list[str]
    decisions: list[ApprovalDecisionOut]
    closed_at: datetime | None
    closed_by_email: str | None
    closed_reason: str | None
    # The command this approval was spent on, when it has been. Resolved by the
    # handler from the run row that carries the binding, so the evidence trail
    # is navigable in both directions.
    consumed_command_id: str | None = None
