// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { custodySteps, inventoryBadge } from "../src/lib/endpoint-pages-core.ts";
import type { CommandDetailData } from "../src/lib/command-console-core.ts";
const command: CommandDetailData = { id: "c1", agent_id: "a1", kind: "collect_inventory", status: "queued", envelope_version: "1", schema_version: null, signing_key_id: null, signature: "", nonce: null, payload: {}, exit_code: null, stdout: null, stderr: null, stdout_total_bytes: null, stderr_total_bytes: null, stdout_truncated: null, stderr_truncated: null, created_at: "2026-01-01T00:00:00Z", issued_at: null, dispatched_at: null, agent_completed_at: null, completed_at: null, expires_at: null };
test("custody never marks missing signature, dispatch or result evidence complete", () => {
  const steps = custodySteps(command);
  assert.deepEqual(steps.filter((step) => step.state === "done").map((step) => step.key), ["requested"]);
  assert.equal(steps.some((step) => /approved|verified/i.test(step.label)), false);
  assert.equal(custodySteps({ ...command, signature: "stored" }).find((step) => step.key === "signed")?.state, "unknown");
});
test("failed collection is critical and partial or unsupported data never looks healthy", () => {
  assert.equal(inventoryBadge("permission_denied").tone, "crit");
  assert.equal(inventoryBadge("unavailable").tone, "crit");
  assert.equal(inventoryBadge("partial").tone, "off");
  assert.equal(inventoryBadge("unsupported").tone, "off");
});
