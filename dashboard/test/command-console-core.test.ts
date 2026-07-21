// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SCRIPT_BYTES,
  buildDispatchRequestBody,
  commandPageCount,
  describeCommandStatus,
  describeStreamCapture,
  formatByteCount,
  hasActiveCommands,
  validateDispatchInput,
  type CommandHistoryItem,
} from "../src/lib/command-console-core.ts";
import { extractNodelinkErrorCode } from "../src/lib/nodelink-api-core.ts";

function historyItem(status: CommandHistoryItem["status"]): CommandHistoryItem {
  return {
    id: "cmd-1",
    agent_id: "agent-1",
    kind: "shell",
    status,
    envelope_version: "command-v3",
    schema_version: 1,
    signing_key_id: "key-1",
    exit_code: null,
    stdout_truncated: null,
    stderr_truncated: null,
    created_at: "2026-07-21T05:00:00Z",
    issued_at: "2026-07-21T05:00:00Z",
    dispatched_at: null,
    completed_at: null,
    expires_at: "2026-07-21T05:05:00Z",
  };
}

test("accepts a script command and normalizes line endings and whitespace", () => {
  const input = validateDispatchInput({
    kind: "powershell",
    script: "  Get-Service\r\nGet-Process  ",
    ttl_seconds: 300,
  });
  assert.deepEqual(input, {
    kind: "powershell",
    script: "Get-Service\nGet-Process",
    ttl_seconds: 300,
  });
  assert.deepEqual(buildDispatchRequestBody(input!), {
    kind: "powershell",
    payload: { script: "Get-Service\nGet-Process" },
    ttl_seconds: 300,
  });
});

test("rejects invalid dispatch input instead of forwarding it", () => {
  // Missing or empty script on script-bearing kinds.
  assert.equal(validateDispatchInput({ kind: "shell", script: "   ", ttl_seconds: 300 }), null);
  // A script on an inventory request would be silently ignored by the agent.
  assert.equal(
    validateDispatchInput({ kind: "collect_inventory", script: "echo x", ttl_seconds: 300 }),
    null,
  );
  // Unknown kinds and out-of-range or fractional TTLs.
  assert.equal(validateDispatchInput({ kind: "reboot", script: "x", ttl_seconds: 300 }), null);
  assert.equal(validateDispatchInput({ kind: "shell", script: "x", ttl_seconds: 0 }), null);
  assert.equal(validateDispatchInput({ kind: "shell", script: "x", ttl_seconds: 86_401 }), null);
  assert.equal(validateDispatchInput({ kind: "shell", script: "x", ttl_seconds: 1.5 }), null);
  // Oversized scripts are refused client-side before signing is attempted.
  assert.equal(
    validateDispatchInput({
      kind: "shell",
      script: "x".repeat(MAX_SCRIPT_BYTES + 1),
      ttl_seconds: 300,
    }),
    null,
  );
  assert.equal(validateDispatchInput(null), null);
  assert.equal(validateDispatchInput("shell"), null);
});

test("inventory dispatches carry an empty payload", () => {
  const input = validateDispatchInput({ kind: "collect_inventory", script: "", ttl_seconds: 900 });
  assert.deepEqual(buildDispatchRequestBody(input!), {
    kind: "collect_inventory",
    payload: {},
    ttl_seconds: 900,
  });
});

test("classifies statuses into terminal and active work", () => {
  assert.equal(describeCommandStatus("queued").terminal, false);
  assert.equal(describeCommandStatus("dispatched").terminal, false);
  assert.equal(describeCommandStatus("running").terminal, false);
  assert.equal(describeCommandStatus("succeeded").terminal, true);
  assert.equal(describeCommandStatus("failed").tone, "failure");
  assert.equal(describeCommandStatus("expired").tone, "expired");

  assert.equal(hasActiveCommands([historyItem("succeeded"), historyItem("expired")]), false);
  assert.equal(hasActiveCommands([historyItem("succeeded"), historyItem("queued")]), true);
});

test("stream capture notes never present unknown truncation as complete", () => {
  assert.match(describeStreamCapture(true, 10_000_000_000, "partial"), /Truncated/);
  assert.match(describeStreamCapture(true, 10_000_000_000, "partial"), /9\.3 GiB/);
  assert.equal(describeStreamCapture(false, 12, "all of it"), "Complete capture.");
  assert.equal(describeStreamCapture(null, null, ""), "No output stored.");
  assert.match(describeStreamCapture(null, null, "legacy text"), /unknown/);
});

test("formats byte counts across magnitudes", () => {
  assert.equal(formatByteCount(null), "Unknown");
  assert.equal(formatByteCount(512), "512 B");
  assert.equal(formatByteCount(2_048), "2.0 KiB");
  assert.equal(formatByteCount(5 * 1024 * 1024), "5.0 MiB");
});

test("computes history page counts with a floor of one page", () => {
  assert.equal(commandPageCount(0, 25), 1);
  assert.equal(commandPageCount(25, 25), 1);
  assert.equal(commandPageCount(26, 25), 2);
});

test("extracts stable error codes from structured API error bodies", () => {
  assert.equal(
    extractNodelinkErrorCode({ detail: { code: "agent_not_trusted", trust_state: "quarantined" } }),
    "agent_not_trusted",
  );
  assert.equal(extractNodelinkErrorCode({ detail: "Agent not found" }), null);
  assert.equal(extractNodelinkErrorCode(null), null);
  assert.equal(extractNodelinkErrorCode("nope"), null);
});
