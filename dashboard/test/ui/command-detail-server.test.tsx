// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { CommandDetailData } from "@/lib/command-console-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";

// Model the RSC boundary: exported client functions cannot be called on the server.
mock.module("@/components/endpoint/command-history-table", { namedExports: {
  commandKindLabel: () => { throw new Error("Cannot call a client function from the server"); },
  CommandHistoryTable: () => null,
} });
const { CommandDetailView } = await import("@/components/command-detail-view");
const command: CommandDetailData = {
  id: "c1", agent_id: "a1", kind: "collect_inventory", status: "succeeded",
  envelope_version: "1", schema_version: null, signing_key_id: null, signature: "", nonce: null,
  payload: {}, exit_code: 0, stdout: "collected", stderr: null,
  stdout_total_bytes: null, stderr_total_bytes: null, stdout_truncated: null, stderr_truncated: null,
  created_at: "2026-01-01T00:00:00Z", issued_at: null, dispatched_at: null,
  agent_completed_at: null, completed_at: null, expires_at: null,
};
const endpoint = { id: "a1", hostname: "Test endpoint", agent_version: "1.0" } as EndpointDetailData;
for (const tab of ["output", "custody", "details"] as const) {
  test(`command ${tab} renders on the server without calling client exports`, () => {
    const html = renderToStaticMarkup(<CommandDetailView command={command} endpoint={endpoint}
      operator={{ id: "op1", email: "operator@example.test", role: "operator", disabled: false }} tab={tab} />);
    assert.match(html, /Collect inventory/);
    assert.match(html, /Test endpoint/);
  });
}


test("failed commands retain stderr, truncation warnings, and unknown command names", () => {
  const html = renderToStaticMarkup(<CommandDetailView
    command={{ ...command, kind: "future_command" as CommandDetailData["kind"], status: "failed", exit_code: 7,
      stdout: null, stderr: "diagnostic output", stderr_truncated: true, stderr_total_bytes: 4000 }}
    endpoint={endpoint} operator={{ id: "op1", email: "operator@example.test", role: "operator", disabled: false }} />);
  assert.match(html, /future_command/);
  assert.match(html, /diagnostic output/);
  assert.match(html, /Output was truncated/);
  assert.match(html, /Exit code 7/);
});

test("expired commands show no result instead of claiming success", () => {
  const html = renderToStaticMarkup(<CommandDetailView
    command={{ ...command, status: "expired", exit_code: null, stdout: null }}
    endpoint={endpoint} operator={{ id: "op1", email: "operator@example.test", role: "operator", disabled: false }} />);
  assert.match(html, /No result: the command expired/);
  assert.doesNotMatch(html, /device reported success/);
});
