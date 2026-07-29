// SPDX-License-Identifier: AGPL-3.0-only

export type OperatorRole = "readonly" | "operator" | "admin";
export type OperatorKind = "administrator" | "technician";
export type ScriptPermissionScope = "global" | "site" | "agent";

export type OperatorRecord = {
  id: string;
  email: string;
  role: OperatorRole;
  script_execution_scope: ScriptPermissionScope | null;
  script_execution_scope_id: string | null;
  disabled: boolean;
  created_at: string;
};

export type OperatorCreateInput = {
  email: string;
  password: string;
  role: OperatorRole;
};

export type ScriptPermissionInput = {
  scope: ScriptPermissionScope;
  scope_id?: string;
  reason: string;
};

export type OperatorRoleChangeInput = {
  role: OperatorRole;
  reason: string;
};

export type OperatorStatusChangeInput = {
  disabled: boolean;
  reason: string;
};

export type OperatorAction =
  | "list"
  | "create"
  | "grant-script-permission"
  | "revoke-script-permission"
  | "revoke-tokens"
  | "change-role"
  | "change-status";

export type OperatorActionError = {
  message: string;
  status: number;
};

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const operatorRoles = new Set<OperatorRole>(["readonly", "operator", "admin"]);
const permissionScopes = new Set<ScriptPermissionScope>(["global", "site", "agent"]);

export const permissionReasonBounds = {
  min: 3,
  max: 500,
} as const;

export function operatorKindToRole(kind: OperatorKind): "admin" | "operator" {
  return kind === "administrator" ? "admin" : "operator";
}

export function operatorKindLabel(kind: OperatorKind): string {
  return kind === "administrator" ? "Administrator" : "Technician";
}

export function operatorRoleLabel(role: OperatorRole): string {
  if (role === "admin") return "Administrator";
  if (role === "operator") return "Technician";
  return "Read-only";
}

export function scriptPermissionScopeLabel(scope: ScriptPermissionScope): string {
  if (scope === "global") return "Global";
  if (scope === "site") return "Site";
  return "Agent";
}

export function validateOperatorCreateInput(value: unknown): OperatorCreateInput | null {
  if (!value || typeof value !== "object") return null;
  const { email, password, role } = value as Record<string, unknown>;
  if (
    typeof email !== "string"
    || typeof password !== "string"
    || typeof role !== "string"
    || !operatorRoles.has(role as OperatorRole)
  ) {
    return null;
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (
    normalizedEmail.length === 0
    || normalizedEmail.length > 320
    || !emailPattern.test(normalizedEmail)
    || password.length === 0
    || password.length > 1_024
  ) {
    return null;
  }
  return { email: normalizedEmail, password, role: role as OperatorRole };
}

export function createOperatorInputFromForm(
  formData: FormData,
  kind: OperatorKind,
): OperatorCreateInput | null {
  return validateOperatorCreateInput({
    email: formData.get("email"),
    password: formData.get("password"),
    role: operatorKindToRole(kind),
  });
}

export function validatePermissionReason(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const reason = value.trim();
  return reason.length >= permissionReasonBounds.min
    && reason.length <= permissionReasonBounds.max
    ? reason
    : null;
}

export function validateScriptPermissionInput(
  value: unknown,
  targetRole?: OperatorRole,
): ScriptPermissionInput | null {
  if (targetRole === "readonly" || !value || typeof value !== "object") return null;
  const { scope, scope_id: rawScopeId, reason: rawReason } = value as Record<string, unknown>;
  if (typeof scope !== "string" || !permissionScopes.has(scope as ScriptPermissionScope)) {
    return null;
  }
  const reason = validatePermissionReason(rawReason);
  if (!reason) return null;

  if (scope === "global") {
    if (rawScopeId !== undefined && rawScopeId !== null && rawScopeId !== "") return null;
    return { scope: "global", reason };
  }

  if (typeof rawScopeId !== "string") return null;
  const scopeId = rawScopeId.trim();
  if (scopeId.length < 1 || scopeId.length > 36) return null;
  return {
    scope: scope as "site" | "agent",
    scope_id: scopeId,
    reason,
  };
}

export function validateScriptPermissionRevokeInput(
  value: unknown,
): { reason: string } | null {
  if (!value || typeof value !== "object") return null;
  const reason = validatePermissionReason((value as Record<string, unknown>).reason);
  return reason ? { reason } : null;
}

export function validateOperatorRoleChangeInput(
  value: unknown,
): OperatorRoleChangeInput | null {
  if (!value || typeof value !== "object") return null;
  const { role, reason: rawReason } = value as Record<string, unknown>;
  const reason = validatePermissionReason(rawReason);
  if (
    typeof role !== "string"
    || !operatorRoles.has(role as OperatorRole)
    || !reason
  ) {
    return null;
  }
  return { role: role as OperatorRole, reason };
}

export function validateOperatorStatusChangeInput(
  value: unknown,
): OperatorStatusChangeInput | null {
  if (!value || typeof value !== "object") return null;
  const { disabled, reason: rawReason } = value as Record<string, unknown>;
  const reason = validatePermissionReason(rawReason);
  if (typeof disabled !== "boolean" || !reason) return null;
  return { disabled, reason };
}

export function canGrantScriptPermission(role: OperatorRole): boolean {
  return role !== "readonly";
}

export function operatorRecordFromUnknown(value: unknown): OperatorRecord | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const scope = record.script_execution_scope;
  const scopeId = record.script_execution_scope_id;
  if (
    typeof record.id !== "string"
    || record.id.length === 0
    || typeof record.email !== "string"
    || typeof record.role !== "string"
    || !operatorRoles.has(record.role as OperatorRole)
    || typeof record.disabled !== "boolean"
    || typeof record.created_at !== "string"
    || Number.isNaN(Date.parse(record.created_at))
    || (scope !== null && (typeof scope !== "string" || !permissionScopes.has(scope as ScriptPermissionScope)))
    || (scopeId !== null && typeof scopeId !== "string")
  ) {
    return null;
  }
  if (scope === null && scopeId !== null) return null;
  if (scope === "global" && scopeId !== null) return null;
  if ((scope === "site" || scope === "agent") && (typeof scopeId !== "string" || scopeId.length === 0)) {
    return null;
  }
  return {
    id: record.id,
    email: record.email,
    role: record.role as OperatorRole,
    script_execution_scope: scope as ScriptPermissionScope | null,
    script_execution_scope_id: scopeId as string | null,
    disabled: record.disabled,
    created_at: record.created_at,
  };
}

export function operatorListFromUnknown(value: unknown): OperatorRecord[] | null {
  if (!Array.isArray(value)) return null;
  const operators = value.map(operatorRecordFromUnknown);
  return operators.every((operator): operator is OperatorRecord => operator !== null)
    ? operators
    : null;
}

export function formatOperatorCreatedAtUtc(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

export function describeOperatorActionError(
  action: OperatorAction,
  upstreamStatus: number,
  code: string | null = null,
): OperatorActionError {
  if (upstreamStatus === 401) {
    return { message: "Your session expired. Sign in again to manage operators.", status: 401 };
  }
  if (upstreamStatus === 403) {
    return { message: "Only an administrator can manage operators.", status: 403 };
  }
  if (upstreamStatus === 404) {
    return {
      message: action === "grant-script-permission"
        ? "The operator or selected scope target no longer exists."
        : "This operator no longer exists.",
      status: 404,
    };
  }
  if (upstreamStatus === 409) {
    if (action === "create") {
      return { message: "An operator with this email already exists.", status: 409 };
    }
    if (code === "script_permission_role_ineligible") {
      return { message: "Read-only operators cannot receive script permission.", status: 409 };
    }
    if (code === "script_permission_not_granted") {
      return { message: "This operator has no script permission to revoke.", status: 409 };
    }
    if (code === "last_active_admin_required") {
      return {
        message: "NodeLink must retain at least one active administrator. Promote or re-enable another administrator first.",
        status: 409,
      };
    }
    if (code === "operator_role_unchanged") {
      return { message: "This operator already has the selected role.", status: 409 };
    }
    if (code === "operator_state_unchanged") {
      return { message: "This operator is already in the requested account state.", status: 409 };
    }
    return {
      message: "The operator changed before this action completed. Refresh and review the current state.",
      status: 409,
    };
  }
  if (upstreamStatus === 400 || upstreamStatus === 422) {
    if (action === "change-role") {
      return {
        message: "Select a valid role and enter an audit reason between 3 and 500 characters.",
        status: 400,
      };
    }
    if (action === "change-status") {
      return {
        message: "Enter an audit reason between 3 and 500 characters.",
        status: 400,
      };
    }
    return {
      message: action === "create"
        ? "Check the operator email, password, and role."
        : "Check the permission scope, target, and audit reason.",
      status: 400,
    };
  }
  return {
    message: action === "list"
      ? "Operator records are unavailable. Try again."
      : "The operator action is unavailable. Try again.",
    status: 503,
  };
}
