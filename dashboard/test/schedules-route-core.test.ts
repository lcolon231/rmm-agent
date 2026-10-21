// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleCreateSchedule,
  handleRunScheduleNow,
  handleToggleSchedule,
  scheduleCreateInputFromUnknown,
  scheduledTaskActionPath,
} from "../src/lib/schedules-route-core.ts";
import { SENTINEL, apiError, bffContract, request, sessionFor, upstream } from "./bff-contract.ts";

const task = {
  id: "task-1",
  name: "Nightly inventory",
  description: null,
  enabled: true,
  target_type: "agent",
  target_id: "agent-1",
  cron_expression: "0 2 * * *",
  timezone: "UTC",
  kind: "collect_inventory",
  payload: {},
  next_run_at: "2026-10-22T02:00:00Z",
  signing_key_ref: SENTINEL,
};
const createBody = {
  name: "Nightly inventory",
  target_type: "agent",
  target_id: "agent-1",
  cron_expression: "0 2 * * *",
  timezone: "UTC",
  kind: "collect_inventory",
  payload: {},
};

bffContract([
  {
    name: "create schedule",
    minRole: "operator",
    mutation: true,
    upstreamResult: task,
    invoke: ({ getSession, origin, call }) =>
      handleCreateSchedule(request("/api/schedules", "POST", createBody, origin), {
        createScheduledTask: call,
        getSession,
      }),
  },
  {
    name: "toggle schedule",
    minRole: "operator",
    mutation: true,
    upstreamResult: { ...task, enabled: false },
    invoke: ({ getSession, origin, call }) =>
      handleToggleSchedule(request("/api/schedules/task-1/toggle", "POST", undefined, origin), "task-1", {
        getSession,
        toggleScheduledTask: call,
      }),
  },
  {
    name: "run schedule now",
    minRole: "operator",
    mutation: true,
    upstreamResult: { status: "triggered", dispatched: 2, internal: SENTINEL },
    invoke: ({ getSession, origin, call }) =>
      handleRunScheduleNow(request("/api/schedules/task-1/run-now", "POST", undefined, origin), "task-1", {
        getSession,
        runScheduledTaskNow: call,
      }),
  },
]);

test("create forwards only the fields the service accepts", async () => {
  const double = upstream(task);
  const response = await handleCreateSchedule(
    request("/api/schedules", "POST", { ...createBody, created_by_operator_id: "someone-else", id: "chosen" }),
    { createScheduledTask: double.fn, getSession: sessionFor("operator") },
  );
  assert.equal(response.status, 201);
  assert.deepEqual(double.calls[0][1], createBody);
  assert.equal(scheduleCreateInputFromUnknown([createBody]), null);
});

test("create refuses a malformed body before forwarding", async () => {
  const double = upstream(task);
  const response = await handleCreateSchedule(request("/api/schedules", "POST", "{nope"), {
    createScheduledTask: double.fn,
    getSession: sessionFor("operator"),
  });
  assert.equal(response.status, 400);
  assert.equal(double.calls.length, 0);
});

test("upstream error messages are never echoed to the browser", async () => {
  const leaky = Object.assign(new Error(`database said ${SENTINEL}`), { status: 422, code: null });
  const responses = [
    await handleCreateSchedule(request("/api/schedules", "POST", createBody), {
      createScheduledTask: async () => { throw leaky; },
      getSession: sessionFor("operator"),
    }),
    await handleToggleSchedule(request("/x", "POST"), "task-1", {
      getSession: sessionFor("operator"),
      toggleScheduledTask: async () => { throw leaky; },
    }),
    await handleRunScheduleNow(request("/x", "POST"), "task-1", {
      getSession: sessionFor("operator"),
      runScheduledTaskNow: async () => { throw new Error(SENTINEL); },
    }),
  ];
  for (const response of responses) {
    assert.ok(response.status >= 400);
    assert.ok(!(await response.text()).includes(SENTINEL));
  }
});

test("schedule errors map to fixed statuses", async () => {
  for (const [upstreamStatus, status] of [[404, 404], [403, 403], [409, 409], [500, 502]]) {
    const response = await handleToggleSchedule(request("/x", "POST"), "task-1", {
      getSession: sessionFor("operator"),
      toggleScheduledTask: async () => { throw apiError(upstreamStatus); },
    });
    assert.equal(response.status, status);
  }
});

test("the schedule id is encoded into the upstream path", () => {
  assert.equal(
    scheduledTaskActionPath("../agents/x?y=1", "toggle"),
    "/api/v1/scheduled-tasks/..%2Fagents%2Fx%3Fy%3D1/toggle",
  );
  assert.equal(scheduledTaskActionPath("task-1", "run-now"), "/api/v1/scheduled-tasks/task-1/run-now");
});

test("run-now rejects an invalid dispatch count", async () => {
  const response = await handleRunScheduleNow(request("/x", "POST"), "task-1", {
    getSession: sessionFor("operator"),
    runScheduledTaskNow: async () => ({ dispatched: -1 }),
  });
  assert.equal(response.status, 502);
});
