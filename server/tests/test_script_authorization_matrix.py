# SPDX-License-Identifier: AGPL-3.0-only
"""Direct decision-table tests for ``authorize_command`` (issue #285).

``test_script_authorization.py`` drives the policy through HTTP; this file
calls ``app.core.script_authorization`` directly over the full
role x script-scope x command-kind matrix described in
``docs/SCRIPT-AUTHORIZATION.md``. No database is involved.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_script_authorization_matrix.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402

from app.core.script_authorization import (  # noqa: E402
    CommandAuthorizationDecision,
    authorize_command,
    decision_audit_detail,
)
from app.models.models import (  # noqa: E402
    Agent,
    CommandKind,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)

SCRIPT_KINDS = {CommandKind.powershell, CommandKind.shell}
TYPED_KINDS = {
    CommandKind.collect_inventory,
    CommandKind.scan_updates,
    CommandKind.install_updates,
    CommandKind.scan_packages,
    CommandKind.list_services,
    CommandKind.list_processes,
}
ADMIN_POLICY = {
    CommandKind.file_upload: "privileged_remediation",
    CommandKind.file_download: "privileged_remediation",
    CommandKind.registry_read: "privileged_remediation",
    CommandKind.registry_write: "privileged_remediation",
    CommandKind.registry_delete: "privileged_remediation",
    CommandKind.remediation_rollback: "privileged_remediation",
    CommandKind.reboot: "power_operation",
    CommandKind.shutdown: "power_operation",
    CommandKind.cancel_power_action: "power_operation",
    CommandKind.query_event_log: "event_log_query",
    CommandKind.install_packages: "package_management",
    CommandKind.deploy_software: "software_deployment",
    CommandKind.control_service: "service_process",
    CommandKind.terminate_process: "service_process",
    CommandKind.agent_self_update: "agent_self_update",
    CommandKind.agent_update_rollback: "agent_self_update",
}

AGENT_ID = "agent-1"
SITE_ID = "site-1"

# (scope, scope_id, expected allow for an agent in SITE_ID with id AGENT_ID)
SCOPES = [
    (None, None, False),
    (ScriptExecutionScope.global_, None, True),
    (ScriptExecutionScope.site, SITE_ID, True),
    (ScriptExecutionScope.site, "other-site", False),
    (ScriptExecutionScope.agent, AGENT_ID, True),
    (ScriptExecutionScope.agent, "other-agent", False),
    # A site grant whose id happens to equal the agent id must not match, and
    # vice versa: the scope kind decides which attribute is compared.
    (ScriptExecutionScope.site, AGENT_ID, False),
    (ScriptExecutionScope.agent, SITE_ID, False),
]


def _operator(role: OperatorRole, scope=None, scope_id=None) -> Operator:
    return Operator(
        id="op-1",
        email="op@nodelink.test",
        password_hash="x",
        role=role,
        script_execution_scope=scope,
        script_execution_scope_id=scope_id,
    )


def _agent() -> Agent:
    return Agent(id=AGENT_ID, site_id=SITE_ID, token_hash="h")


def test_every_command_kind_is_classified():
    # A new kind silently falls through to the script branch; force a decision.
    assert SCRIPT_KINDS | TYPED_KINDS | set(ADMIN_POLICY) == set(CommandKind)
    assert not SCRIPT_KINDS & TYPED_KINDS
    assert not (SCRIPT_KINDS | TYPED_KINDS) & set(ADMIN_POLICY)


@pytest.mark.parametrize("kind", list(CommandKind))
@pytest.mark.parametrize("scope,scope_id,_", SCOPES)
def test_readonly_is_denied_everything_regardless_of_scope(kind, scope, scope_id, _):
    decision = authorize_command(_operator(OperatorRole.readonly, scope, scope_id), _agent(), kind)
    assert decision == CommandAuthorizationDecision(
        allowed=False, policy="operator_role", reason="operator_role_insufficient"
    )


@pytest.mark.parametrize("role", [OperatorRole.operator, OperatorRole.admin])
@pytest.mark.parametrize("kind", sorted(TYPED_KINDS, key=lambda k: k.value))
@pytest.mark.parametrize("scope,scope_id,_", SCOPES)
def test_typed_operations_need_only_the_role(role, kind, scope, scope_id, _):
    decision = authorize_command(_operator(role, scope, scope_id), _agent(), kind)
    assert decision == CommandAuthorizationDecision(
        allowed=True, policy="typed_operation", reason="typed_operation_role_allowed"
    )


@pytest.mark.parametrize("role", [OperatorRole.operator, OperatorRole.admin])
@pytest.mark.parametrize("kind", list(ADMIN_POLICY))
@pytest.mark.parametrize("scope,scope_id,_", SCOPES)
def test_admin_only_kinds_ignore_script_scope(role, kind, scope, scope_id, _):
    decision = authorize_command(_operator(role, scope, scope_id), _agent(), kind)
    is_admin = role == OperatorRole.admin
    assert decision == CommandAuthorizationDecision(
        allowed=is_admin,
        policy=ADMIN_POLICY[kind],
        reason="administrator_role_allowed" if is_admin else "administrator_role_required",
    )


@pytest.mark.parametrize("role", [OperatorRole.operator, OperatorRole.admin])
@pytest.mark.parametrize("kind", sorted(SCRIPT_KINDS, key=lambda k: k.value))
@pytest.mark.parametrize("scope,scope_id,allowed", SCOPES)
def test_script_kinds_require_matching_explicit_scope(role, kind, scope, scope_id, allowed):
    """Admin is not a bypass: an admin without a grant is refused like anyone."""
    decision = authorize_command(_operator(role, scope, scope_id), _agent(), kind)
    if scope is None:
        assert decision == CommandAuthorizationDecision(
            allowed=False, policy="script_permission", reason="script_permission_missing"
        )
        return
    assert decision == CommandAuthorizationDecision(
        allowed=allowed,
        policy="script_permission",
        reason=(
            "script_permission_scope_allowed"
            if allowed
            else "script_permission_scope_mismatch"
        ),
        permission_scope=scope,
        permission_scope_id=scope_id,
    )


def test_decision_audit_detail_with_scope():
    operator = _operator(OperatorRole.operator, ScriptExecutionScope.site, SITE_ID)
    agent = _agent()
    decision = authorize_command(operator, agent, CommandKind.powershell)
    assert decision_audit_detail(
        decision, operator=operator, agent=agent, kind=CommandKind.powershell
    ) == {
        "operator_id": "op-1",
        "operator_role": "operator",
        "kind": "powershell",
        "site_id": SITE_ID,
        "policy": "script_permission",
        "reason": "script_permission_scope_allowed",
        "permission_scope": "site",
        "permission_scope_id": SITE_ID,
    }


def test_decision_audit_detail_without_scope():
    operator = _operator(OperatorRole.readonly)
    agent = _agent()
    decision = authorize_command(operator, agent, CommandKind.shell)
    detail = decision_audit_detail(decision, operator=operator, agent=agent, kind=CommandKind.shell)
    assert detail["permission_scope"] is None
    assert detail["permission_scope_id"] is None
    assert detail["reason"] == "operator_role_insufficient"
