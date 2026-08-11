# SPDX-License-Identifier: AGPL-3.0-only
"""Patch compliance report contracts (issue #54). Read-only projections computed
in ``app/core/patch_compliance.py``; no request bodies are accepted."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ComplianceEndpointOut(BaseModel):
    model_config = {"from_attributes": True}
    agent_id: str
    hostname: str
    site_id: str
    site_name: str
    client_id: str
    client_name: str
    state: str
    policy_id: str | None
    scanned_at: datetime | None
    total_missing: int
    approved_missing: int
    deferred_missing: int
    denied_missing: int


class ComplianceListOut(BaseModel):
    items: list[ComplianceEndpointOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    truncated: bool = False


class ComplianceSummaryOut(BaseModel):
    model_config = {"from_attributes": True}
    total_endpoints: int
    compliant: int
    non_compliant: int
    stale: int
    unknown: int
    exempt: int
    total_approved_missing: int
    truncated: bool


class ComplianceUpdateDecisionOut(BaseModel):
    kb_id: str | None
    update_id: str | None
    title: str
    classification: str | None
    severity: str | None
    decision: str
    reason: str
    matched_rule_key: str | None = None


class ComplianceEndpointDetailOut(ComplianceEndpointOut):
    decisions: list[ComplianceUpdateDecisionOut] = Field(default_factory=list)


class ComplianceHistoryPointOut(BaseModel):
    model_config = {"from_attributes": True}
    scanned_at: datetime | None
    received_at: datetime
    total_missing: int
    approved_missing: int


class ComplianceHistoryOut(BaseModel):
    agent_id: str
    policy_id: str | None
    evaluated_against: str = "current_policy"
    points: list[ComplianceHistoryPointOut] = Field(default_factory=list)
