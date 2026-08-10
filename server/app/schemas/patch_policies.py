# SPDX-License-Identifier: AGPL-3.0-only
"""Patch approval policy contracts (issue #52).

Mirrors ``app/schemas/monitoring.py``: ``extra="forbid"`` everywhere, bounded
collections and strings, and a versioned/scoped policy whose rule set is
validated here before storage. A policy is a stable identity (name, scope,
enabled); its rule content lives in append-only revisions.

A rule is an ordered, first-match approve/deny/defer decision that matches a
scanned Windows update on its classification, MSRC severity, and/or specific KB
ids. ``default_action`` governs updates that no rule matches;
``require_maintenance_window`` additionally gates install dispatch on an active
maintenance window.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
import re
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.models.models import MonitoringScope
from app.schemas.monitoring import _validate_scope

# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #
MAX_RULES_PER_POLICY = 64
MAX_MATCH_CLASSIFICATIONS = 16
MAX_MATCH_SEVERITIES = 8
MAX_MATCH_KB_IDS = 64
MAX_DEFER_DAYS = 365

RuleKey = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
MatchText = Annotated[str, StringConstraints(min_length=1, max_length=64, strip_whitespace=True)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)]
Note = Annotated[str, StringConstraints(max_length=2_000, strip_whitespace=True)]

_KB_RE = re.compile(r"^KB[0-9]{4,10}$")


class PatchAction(str, Enum):
    approve = "approve"
    deny = "deny"
    defer = "defer"


class PatchDefaultAction(str, Enum):
    approve = "approve"
    deny = "deny"


class PatchMatch(BaseModel):
    """What a rule matches on. At least one facet must be constrained."""

    model_config = ConfigDict(extra="forbid")
    classifications: list[MatchText] | None = Field(default=None, max_length=MAX_MATCH_CLASSIFICATIONS)
    severities: list[MatchText] | None = Field(default=None, max_length=MAX_MATCH_SEVERITIES)
    kb_ids: list[str] | None = Field(default=None, max_length=MAX_MATCH_KB_IDS)

    @field_validator("kb_ids")
    @classmethod
    def _normalize_kb_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        out: list[str] = []
        for item in value:
            normalized = item.strip().upper()
            if not _KB_RE.fullmatch(normalized):
                raise ValueError("kb_ids must look like KB1234567")
            if normalized not in out:
                out.append(normalized)
        return out or None

    @model_validator(mode="after")
    def _at_least_one_facet(self) -> "PatchMatch":
        if not (self.classifications or self.severities or self.kb_ids):
            raise ValueError(
                "a rule match must constrain at least one of classifications, severities, or kb_ids"
            )
        return self


class PatchRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: RuleKey
    action: PatchAction
    match: PatchMatch
    defer_days: int | None = Field(default=None, ge=1, le=MAX_DEFER_DAYS)

    @model_validator(mode="after")
    def _defer_consistency(self) -> "PatchRule":
        if self.action == PatchAction.defer and self.defer_days is None:
            raise ValueError("a defer rule requires defer_days")
        if self.action != PatchAction.defer and self.defer_days is not None:
            raise ValueError("defer_days is only valid on a defer rule")
        return self


def _unique_rule_keys(value: list[PatchRule]) -> list[PatchRule]:
    keys = [rule.key for rule in value]
    if len(set(keys)) != len(keys):
        raise ValueError("rule keys must be unique within a policy")
    return value


class PatchApprovalPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText
    scope: MonitoringScope
    scope_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    enabled: bool = True
    rules: list[PatchRule] = Field(default_factory=list, max_length=MAX_RULES_PER_POLICY)
    default_action: PatchDefaultAction = PatchDefaultAction.deny
    require_maintenance_window: bool = False
    change_note: Note | None = None

    _keys = field_validator("rules")(_unique_rule_keys)

    @model_validator(mode="after")
    def _scope_consistency(self) -> "PatchApprovalPolicyCreate":
        _validate_scope(self.scope, self.scope_id)
        return self


class PatchApprovalPolicyUpdate(BaseModel):
    """A new revision: fully replaces the rule set and revision-level settings.

    Scope and name are identity and are not changed by a revision.
    """

    model_config = ConfigDict(extra="forbid")
    rules: list[PatchRule] = Field(default_factory=list, max_length=MAX_RULES_PER_POLICY)
    default_action: PatchDefaultAction = PatchDefaultAction.deny
    require_maintenance_window: bool = False
    enabled: bool | None = None
    change_note: Note | None = None

    _keys = field_validator("rules")(_unique_rule_keys)


class PatchApprovalPolicyRevisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    version: int
    default_action: str
    require_maintenance_window: bool
    change_note: str | None
    created_by: str | None
    created_at: datetime
    rules: list[PatchRule] = Field(default_factory=list)


class PatchApprovalPolicyOut(BaseModel):
    id: str
    name: str
    scope: MonitoringScope
    scope_id: str | None
    enabled: bool
    created_at: datetime
    current_version: int
    rule_count: int = Field(ge=0)
    default_action: str
    require_maintenance_window: bool


class PatchApprovalPolicyDetailOut(PatchApprovalPolicyOut):
    rules: list[PatchRule] = Field(default_factory=list)
    revisions: list[PatchApprovalPolicyRevisionOut] = Field(default_factory=list)


class PatchUpdateDecisionOut(BaseModel):
    """The effective decision for one currently-missing update on an agent."""

    kb_id: str | None
    update_id: str | None
    title: str
    classification: str | None
    severity: str | None
    decision: str
    reason: str
    matched_rule_key: str | None = None


class EffectivePatchPolicyOut(BaseModel):
    policy_id: str | None
    policy_name: str | None
    scope: MonitoringScope | None
    default_action: str | None
    require_maintenance_window: bool
    decisions: list[PatchUpdateDecisionOut] = Field(default_factory=list)
