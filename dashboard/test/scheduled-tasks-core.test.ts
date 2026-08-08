// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert";
import test from "node:test";

import {
  formatScheduleDateTime,
  scheduledTaskFromUnknown,
  scheduledTaskListFromUnknown,
} from "../src/lib/scheduled-tasks-core.ts";

test("scheduledTaskFromUnknown parses valid item", () => {
  const item = scheduledTaskFromUnknown({
    id: "sched-1",
    name: "Nightly Audit",
    description: "Runs nightly",
    enabled: true,
    target_type: "site",
    target_id: "site-123",
    cron_expression: "0 0 * * *",
    timezone: "UTC",
    kind: "powershell",
    script_version_id: null,
    payload: { script: "Get-Date" },
    concurrency_policy: "skip",
    misfire_policy: "run_once",
    next_run_at: "2026-08-09T00:00:00Z",
    last_run_at: null,
    last_status: null,
    created_by_operator_id: "op-1",
    created_by_email: "op@example.com",
    created_at: "2026-08-08T00:00:00Z",
    updated_at: "2026-08-08T00:00:00Z",
  });

  assert.notEqual(item, null);
  assert.equal(item?.id, "sched-1");
  assert.equal(item?.name, "Nightly Audit");
  assert.equal(item?.target_type, "site");
});

test("scheduledTaskListFromUnknown parses list data", () => {
  const list = scheduledTaskListFromUnknown({
    items: [
      {
        id: "sched-1",
        name: "Task 1",
        enabled: true,
        target_type: "agent",
        target_id: "agent-1",
        cron_expression: "* * * * *",
        timezone: "UTC",
        kind: "shell",
        next_run_at: "2026-08-08T12:00:00Z",
      },
    ],
    total: 1,
    page: 1,
    page_size: 50,
  });

  assert.notEqual(list, null);
  assert.equal(list?.total, 1);
  assert.equal(list?.items.length, 1);
});

test("formatScheduleDateTime handles valid and invalid dates", () => {
  assert.equal(formatScheduleDateTime(null, "N/A"), "N/A");
  assert.equal(formatScheduleDateTime("invalid-date", "Fallback"), "Fallback");
  assert.match(formatScheduleDateTime("2026-08-08T12:00:00Z"), /Aug 8, 2026/);
});
