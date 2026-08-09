// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SCRIPT_BYTES,
  buildDispatchRequestBody,
  commandPageCount,
  commandKindDefinitionsForPermission,
  describeCommandStatus,
  describeStreamCapture,
  formatByteCount,
  hasActiveCommands,
  powerOperationResultFromUnknown,
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
    agent_completed_at: null,
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
    update_targets: [],
    install_all: false,
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
  assert.equal(validateDispatchInput({ kind: "erase_disk", script: "x", ttl_seconds: 300 }), null);
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
  const input = validateDispatchInput({
    kind: "collect_inventory",
    script: "",
    update_targets: [],
    install_all: false,
    ttl_seconds: 900,
  });
  assert.deepEqual(buildDispatchRequestBody(input!), {
    kind: "collect_inventory",
    payload: {},
    ttl_seconds: 900,
  });
});

test("install updates accepts KBs and Update IDs and builds a typed payload", () => {
  const input = validateDispatchInput({
    kind: "install_updates",
    script: "",
    update_targets: "5101650, KB5100998\n12345678-1234-ABCD-9876-1234567890AB",
    install_all: false,
    ttl_seconds: 3_600,
  });
  assert.deepEqual(input?.update_targets, [
    "KB5101650",
    "KB5100998",
    "12345678-1234-abcd-9876-1234567890ab",
  ]);
  assert.deepEqual(buildDispatchRequestBody(input!), {
    kind: "install_updates",
    payload: {
      kb_ids: ["KB5101650", "KB5100998"],
      update_ids: ["12345678-1234-abcd-9876-1234567890ab"],
    },
    ttl_seconds: 3_600,
  });
});

test("install updates requires explicit identifiers or install_all", () => {
  assert.equal(validateDispatchInput({
    kind: "install_updates", script: "", update_targets: [], install_all: false, ttl_seconds: 300,
  }), null);
  assert.equal(validateDispatchInput({
    kind: "install_updates", script: "", update_targets: ["bad-id"], install_all: false, ttl_seconds: 300,
  }), null);
  assert.equal(validateDispatchInput({
    kind: "install_updates", script: "", update_targets: ["KB5101650"], install_all: true, ttl_seconds: 300,
  }), null);

  const all = validateDispatchInput({
    kind: "install_updates", script: "", update_targets: [], install_all: true, ttl_seconds: 300,
  });
  assert.deepEqual(buildDispatchRequestBody(all!), {
    kind: "install_updates",
    payload: { install_all: true },
    ttl_seconds: 300,
  });
});

test("script command choices require explicit endpoint permission", () => {
  assert.deepEqual(
    commandKindDefinitionsForPermission(false).map((item) => item.kind),
    ["collect_inventory", "scan_updates", "install_updates"],
  );
  assert.deepEqual(
    commandKindDefinitionsForPermission(true).map((item) => item.kind),
    ["powershell", "shell", "collect_inventory", "scan_updates", "install_updates"],
  );
  assert.deepEqual(
    commandKindDefinitionsForPermission(false, true).map((item) => item.kind),
    [
      "collect_inventory", "scan_updates", "install_updates", "file_upload",
      "file_download", "registry_read", "registry_write", "registry_delete",
      "remediation_rollback", "reboot", "shutdown", "cancel_power_action",
    ],
  );
});

test("builds strict power-operation and cancellation payloads", () => {
  const base = { script: "", update_targets: [], install_all: false, ttl_seconds: 300 };
  const reboot = validateDispatchInput({
    ...base,
    kind: "reboot",
    operation_payload: {
      confirm: true,
      reason: "Approved maintenance restart",
      delay_seconds: 60,
      user_consent: "confirmed",
    },
  });
  assert.deepEqual(buildDispatchRequestBody(reboot!).payload, {
    confirm: true,
    reason: "Approved maintenance restart",
    delay_seconds: 60,
    user_consent: "confirmed",
  });
  assert.equal(validateDispatchInput({
    ...base,
    kind: "shutdown",
    operation_payload: { ...reboot!.operation_payload, confirm: false },
  }), null);
  assert.equal(validateDispatchInput({
    ...base,
    kind: "reboot",
    operation_payload: { ...reboot!.operation_payload, delay_seconds: 10 },
  }), null);

  const cancel = validateDispatchInput({
    ...base,
    kind: "cancel_power_action",
    operation_payload: { confirm: true, reason: "Cancel the maintenance restart" },
  });
  assert.equal(cancel?.operation_payload?.confirm, true);
});

test("parses structured power evidence without trusting arbitrary stdout", () => {
  const parsed = powerOperationResultFromUnknown(JSON.stringify({
    status: "scheduled",
    action: "reboot",
    delay_seconds: 60,
    maintenance_window_id: "window-1",
    maintenance_window_ends_at: "2026-08-09T15:00:00Z",
    user_consent: "confirmed",
    reason_sha256: "a".repeat(64),
    message: "Windows accepted the delayed power action",
  }));
  assert.equal(parsed?.status, "scheduled");
  assert.equal(parsed?.delaySeconds, 60);
  assert.equal(powerOperationResultFromUnknown("not json"), null);
  assert.equal(powerOperationResultFromUnknown(JSON.stringify({ ...parsed, reason_sha256: "bad" })), null);
});

test("builds controlled file and registry payloads without script fallback", () => {
  const upload = validateDispatchInput({
    kind: "file_upload",
    script: "",
    update_targets: [],
    install_all: false,
    ttl_seconds: 300,
    operation_payload: {
      path: "C:\\ProgramData\\NodeLink\\Managed\\patch.bin",
      content_base64: "cGF0Y2g=",
      sha256: "a".repeat(64),
      overwrite: false,
    },
  });
  assert.deepEqual(buildDispatchRequestBody(upload!).payload, upload!.operation_payload);

  const registryDelete = validateDispatchInput({
    kind: "registry_delete",
    script: "",
    update_targets: [],
    install_all: false,
    ttl_seconds: 300,
    operation_payload: {
      hive: "HKLM",
      key: "Software\\NodeLink\\Managed\\Policy",
      value_name: "Mode",
      view: 64,
      confirm: true,
    },
  });
  assert.equal(registryDelete?.operation_payload?.confirm, true);
});

test("rejects unmanaged paths, unconfirmed deletes, and malformed rollback IDs", () => {
  const base = { script: "", update_targets: [], install_all: false, ttl_seconds: 300 };
  assert.equal(validateDispatchInput({
    ...base,
    kind: "file_download",
    operation_payload: { path: "C:\\Windows\\System32\\config\\SAM" },
  }), null);
  assert.equal(validateDispatchInput({
    ...base,
    kind: "registry_delete",
    operation_payload: {
      hive: "HKLM", key: "Software\\NodeLink\\Managed", value_name: "Mode", view: 64, confirm: false,
    },
  }), null);
  assert.equal(validateDispatchInput({
    ...base,
    kind: "remediation_rollback",
    operation_payload: { backup_id: "../backup" },
  }), null);
});

test("classifies statuses into terminal and active work", () => {
  assert.equal(describeCommandStatus("queued").terminal, false);
  assert.equal(describeCommandStatus("dispatched").terminal, false);
  assert.equal(describeCommandStatus("running").terminal, false);
  assert.equal(describeCommandStatus("result_pending").terminal, false);
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
