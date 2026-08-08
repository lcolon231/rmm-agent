// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  asCommandKind,
  asCommandStatus,
  formatTaskRunTimestamp,
  hasTaskRunFilters,
  taskRunHistoryFromUnknown,
  taskRunItemFromUnknown,
  taskRunPageCount,
  taskRunPageHref,
} from "../src/lib/task-runs-core.ts";

function validRun(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "cmd-1",
    agent_id: "agent-1",
    hostname: "PC-1",
    kind: "shell",
    status: "queued",
    envelope_version: "command-v3",
    schema_version: 3,
    signing_key_id: "key-1",
    exit_code: null,
    stdout_truncated: null,
    stderr_truncated: null,
    created_at: "2026-08-01T05:00:00Z",
    issued_at: "2026-08-01T05:00:00Z",
    dispatched_at: null,
    agent_completed_at: null,
    completed_at: null,
    expires_at: "2026-08-01T05:05:00Z",
    actor_email: "op@nodelink.test",
    actor_operator_id: "op-1",
    script_version_id: null,
    script_parameter_value_set_id: null,
    dispatch_audit_event_id: "audit-1",
    planned_at: null,
    attempt: 1,
    parent_command_id: null,
    ...overrides,
  };
}

test("taskRunItemFromUnknown accepts a well-formed run and preserves provenance", () => {
  const run = taskRunItemFromUnknown(
    validRun({ script_version_id: "sv-9", actor_email: "who@nodelink.test" }),
  );
  assert.ok(run);
  assert.equal(run.script_version_id, "sv-9");
  assert.equal(run.actor_email, "who@nodelink.test");
  assert.equal(run.hostname, "PC-1");
  assert.equal(run.attempt, 1);
});

test("taskRunItemFromUnknown rejects drift and bad types", () => {
  assert.equal(taskRunItemFromUnknown(null), null);
  assert.equal(taskRunItemFromUnknown(validRun({ id: 5 })), null);
  assert.equal(taskRunItemFromUnknown(validRun({ kind: "reboot" })), null);
  assert.equal(taskRunItemFromUnknown(validRun({ status: "cancelled" })), null);
  assert.equal(taskRunItemFromUnknown(validRun({ created_at: "" })), null);
  assert.equal(taskRunItemFromUnknown(validRun({ attempt: 0 })), null);
  assert.equal(taskRunItemFromUnknown(validRun({ attempt: 1.5 })), null);
  // A nullable string field must be a string or null, never a number.
  assert.equal(taskRunItemFromUnknown(validRun({ actor_email: 7 })), null);
});

test("taskRunHistoryFromUnknown validates envelope and every item", () => {
  const data = taskRunHistoryFromUnknown({
    items: [validRun(), validRun({ id: "cmd-2" })],
    page: 1,
    page_size: 25,
    total: 2,
  });
  assert.ok(data);
  assert.equal(data.items.length, 2);
  assert.equal(data.total, 2);

  assert.equal(taskRunHistoryFromUnknown({ items: [], page: "1", page_size: 25, total: 0 }), null);
  assert.equal(taskRunHistoryFromUnknown({ items: [validRun({ id: 5 })], page: 1, page_size: 25, total: 1 }), null);
  assert.equal(taskRunHistoryFromUnknown({ page: 1, page_size: 25, total: 0 }), null);
});

test("status and kind narrowing reject unknown values", () => {
  assert.equal(asCommandStatus("succeeded"), "succeeded");
  assert.equal(asCommandStatus("nope"), undefined);
  assert.equal(asCommandKind("powershell"), "powershell");
  assert.equal(asCommandKind("reboot"), undefined);
});

test("taskRunPageHref preserves filters and omits page 1", () => {
  assert.equal(taskRunPageHref({}, 1), "/tasks");
  assert.equal(
    taskRunPageHref({ agentId: "a-1", status: "failed" }, 2),
    "/tasks?agent_id=a-1&status=failed&page=2",
  );
  assert.equal(taskRunPageHref({ kind: "shell" }, 1), "/tasks?kind=shell");
});

test("hasTaskRunFilters and taskRunPageCount", () => {
  assert.equal(hasTaskRunFilters({}), false);
  assert.equal(hasTaskRunFilters({ status: "queued" }), true);
  assert.equal(taskRunPageCount(0, 25), 1);
  assert.equal(taskRunPageCount(26, 25), 2);
});

test("formatTaskRunTimestamp handles null and invalid input", () => {
  assert.equal(formatTaskRunTimestamp(null), "—");
  assert.equal(formatTaskRunTimestamp("not-a-date"), "Unavailable");
  assert.match(formatTaskRunTimestamp("2026-08-01T05:00:00Z"), /UTC$/);
});
