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

    if kind in (
        CommandKind.collect_inventory,
        CommandKind.scan_updates,
        CommandKind.install_updates,
        # Package discovery is read-only, like a Windows Update scan: operator+.
        CommandKind.scan_packages,
        CommandKind.list_services,
        CommandKind.list_processes,
    ):
        return CommandAuthorizationDecision(
            allowed=True,
            policy="typed_operation",
            reason="typed_operation_role_allowed",
        )

    # File mutation, registry mutation/readback, and rollback can expose or
    # change privileged endpoint state. Keep them behind the administrator
    # role even though they are typed operations; script permission is not an
    # appropriate substitute for this distinct trust boundary.
    if kind in (
        CommandKind.file_upload,
        CommandKind.file_download,
        CommandKind.registry_read,
        CommandKind.registry_write,
        CommandKind.registry_delete,
        CommandKind.remediation_rollback,
        CommandKind.reboot,
        CommandKind.shutdown,
        CommandKind.cancel_power_action,
        CommandKind.query_event_log,
        # Installing/upgrading arbitrary software is a broad trust boundary
        # (chocolatey pulls third-party sources); keep it admin-only.
        CommandKind.install_packages,
        # Deploying a downloaded MSI/EXE runs arbitrary vendor code on the
        # endpoint; the broadest trust boundary here, so admin-only.
        CommandKind.deploy_software,
        CommandKind.control_service,
        CommandKind.terminate_process,
        # Replacing the agent binary, or restoring the previous one, changes the
        # code running on the endpoint itself. Nothing here is broader.
        CommandKind.agent_self_update,
        CommandKind.agent_update_rollback,
    ):
        return CommandAuthorizationDecision(
            allowed=operator.role == OperatorRole.admin,
            policy=(
                "agent_self_update"
                if kind in {
                    CommandKind.agent_self_update,
                    CommandKind.agent_update_rollback,
                }
                else "service_process"
                if kind in {
                    CommandKind.control_service,
                    CommandKind.terminate_process,
                }
                else "power_operation"
                if kind in {
                    CommandKind.reboot,
                    CommandKind.shutdown,
                    CommandKind.cancel_power_action,
                }
                else "event_log_query"
                if kind == CommandKind.query_event_log
                else "package_management"
                if kind == CommandKind.install_packages
                else "software_deployment"
                if kind == CommandKind.deploy_software
                else "privileged_remediation"
            ),
            reason=(
                "administrator_role_allowed"
                if operator.role == OperatorRole.admin
                else "administrator_role_required"
            ),
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
