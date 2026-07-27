# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit authorization policy for command execution.

Typed operations remain governed by the ordinary operator role. Arbitrary
PowerShell and shell execution additionally requires a persisted, explicitly
granted scope on the acting operator. Admin is deliberately not a bypass.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models.models import (
    Agent,
    CommandKind,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)


@dataclass(frozen=True)
class CommandAuthorizationDecision:
    allowed: bool
    policy: str
    reason: str
    permission_scope: ScriptExecutionScope | None = None
    permission_scope_id: str | None = None


def authorize_command(
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
) -> CommandAuthorizationDecision:
    """Return the deterministic role + explicit-scope authorization decision."""
    if operator.role == OperatorRole.readonly:
        return CommandAuthorizationDecision(
            allowed=False,
            policy="operator_role",
            reason="operator_role_insufficient",
        )

    if kind == CommandKind.collect_inventory:
        return CommandAuthorizationDecision(
            allowed=True,
            policy="typed_operation",
            reason="typed_operation_role_allowed",
        )

    scope = operator.script_execution_scope
    scope_id = operator.script_execution_scope_id
    if scope is None:
        return CommandAuthorizationDecision(
            allowed=False,
            policy="script_permission",
            reason="script_permission_missing",
        )

    matches = (
        scope == ScriptExecutionScope.global_
        or (scope == ScriptExecutionScope.site and scope_id == agent.site_id)
        or (scope == ScriptExecutionScope.agent and scope_id == agent.id)
    )
    return CommandAuthorizationDecision(
        allowed=matches,
        policy="script_permission",
        reason=(
            "script_permission_scope_allowed"
            if matches
            else "script_permission_scope_mismatch"
        ),
        permission_scope=scope,
        permission_scope_id=scope_id,
    )


def decision_audit_detail(
    decision: CommandAuthorizationDecision,
    *,
    operator: Operator,
    agent: Agent,
    kind: CommandKind,
) -> dict:
    """Safe accountable metadata for allow/deny events; never includes payload."""
    return {
        "operator_id": operator.id,
        "operator_role": operator.role.value,
        "kind": kind.value,
        "site_id": agent.site_id,
        "policy": decision.policy,
        "reason": decision.reason,
        "permission_scope": (
            decision.permission_scope.value
            if decision.permission_scope is not None
            else None
        ),
        "permission_scope_id": decision.permission_scope_id,
    }
