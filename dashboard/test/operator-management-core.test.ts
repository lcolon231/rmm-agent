// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  canGrantScriptPermission,
  describeOperatorActionError,
  formatOperatorCreatedAtUtc,
  operatorKindToRole,
  operatorRecordFromUnknown,
  operatorRoleLabel,
  permissionReasonBounds,
  validatePermissionReason,
  validateOperatorRoleChangeInput,
  validateOperatorStatusChangeInput,
  validateScriptPermissionInput,
} from "../src/lib/operator-management-core.ts";

test("maps product roles to exact API values", () => {
  assert.equal(operatorKindToRole("administrator"), "admin");
  assert.equal(operatorKindToRole("technician"), "operator");
  assert.equal(operatorRoleLabel("admin"), "Administrator");
  assert.equal(operatorRoleLabel("operator"), "Technician");
  assert.equal(operatorRoleLabel("readonly"), "Read-only");
});

test("enforces scope_id absence for global and presence for site or agent", () => {
  assert.deepEqual(
    validateScriptPermissionInput({ scope: "global", reason: "Approved globally" }, "admin"),
    { scope: "global", reason: "Approved globally" },
  );
  assert.equal(
    validateScriptPermissionInput({
      scope: "global",
      scope_id: "site-1",
      reason: "Wrong direction",
    }, "admin"),
    null,
  );
  assert.equal(
    validateScriptPermissionInput({ scope: "site", reason: "Missing target" }, "operator"),
    null,
  );
  assert.equal(
    validateScriptPermissionInput({ scope: "agent", scope_id: "", reason: "Empty target" }, "admin"),
    null,
  );
  assert.deepEqual(
    validateScriptPermissionInput({
      scope: "site",
      scope_id: " site-1 ",
      reason: " Approved for this site ",
    }, "operator"),
    { scope: "site", scope_id: "site-1", reason: "Approved for this site" },
  );
  assert.equal(
    validateScriptPermissionInput({
      scope: "agent",
      scope_id: "x".repeat(37),
      reason: "Target is too long",
    }, "admin"),
    null,
  );
});

test("enforces real audit-reason length bounds after trimming", () => {
  assert.equal(validatePermissionReason("ab"), null);
  assert.equal(validatePermissionReason("  ab  "), null);
  assert.equal(validatePermissionReason("abc"), "abc");
  assert.equal(
    validatePermissionReason("x".repeat(permissionReasonBounds.max)),
    "x".repeat(permissionReasonBounds.max),
  );
  assert.equal(validatePermissionReason("x".repeat(permissionReasonBounds.max + 1)), null);
});

test("rejects readonly script permission before submission", () => {
  assert.equal(canGrantScriptPermission("readonly"), false);
  assert.equal(canGrantScriptPermission("operator"), true);
  assert.equal(canGrantScriptPermission("admin"), true);
  assert.equal(
    validateScriptPermissionInput({
      scope: "global",
      reason: "Readonly must stay ineligible",
    }, "readonly"),
    null,
  );
});

test("maps duplicate email conflicts to a distinct actionable message", () => {
  assert.deepEqual(describeOperatorActionError("create", 409), {
    message: "An operator with this email already exists.",
    status: 409,
  });
});

test("validates audited operator role and account-state changes", () => {
  assert.deepEqual(
    validateOperatorRoleChangeInput({
      role: "readonly",
      reason: " Responsibilities changed ",
    }),
    { role: "readonly", reason: "Responsibilities changed" },
  );
  assert.equal(
    validateOperatorRoleChangeInput({ role: "owner", reason: "Invalid role" }),
    null,
  );
  assert.deepEqual(
    validateOperatorStatusChangeInput({
      disabled: true,
      reason: " Offboarding approved ",
    }),
    { disabled: true, reason: "Offboarding approved" },
  );
  assert.equal(
    validateOperatorStatusChangeInput({ disabled: "yes", reason: "Invalid state" }),
    null,
  );
  assert.equal(
    validateOperatorStatusChangeInput({ disabled: false, reason: "no" }),
    null,
  );
});

test("surfaces last-active-admin protection distinctly", () => {
  assert.deepEqual(
    describeOperatorActionError(
      "change-status",
      409,
      "last_active_admin_required",
    ),
    {
      message: "NodeLink must retain at least one active administrator. Promote or re-enable another administrator first.",
      status: 409,
    },
  );
});

test("formats operator creation timestamps explicitly in UTC", () => {
  assert.match(
    formatOperatorCreatedAtUtc("2026-07-28T23:15:30-04:00"),
    /Jul 29, 2026.*3:15:30 AM UTC/,
  );
});

test("operator records are allowlisted and never retain secret-adjacent fields", () => {
  const operator = operatorRecordFromUnknown({
    id: "operator-1",
    email: "admin@example.com",
    role: "admin",
    script_execution_scope: null,
    script_execution_scope_id: null,
    disabled: false,
    created_at: "2026-07-28T12:00:00Z",
    access_token: "token-sentinel",
    password: "password-sentinel",
  });
  assert.ok(operator);
  const rendered = JSON.stringify(operator);
  assert.doesNotMatch(rendered, /token-sentinel|password-sentinel/);
});
