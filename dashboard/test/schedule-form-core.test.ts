// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import { schedulableScripts, siteOptionGroups } from "../src/lib/schedule-form-core.ts";
import type { ScriptItem, ScriptParameter } from "../src/lib/script-library-core.ts";

function script(id: string, overrides: {
  language?: "powershell" | "shell";
  review?: "approved" | "rejected" | null;
  deprecated?: boolean;
  parameters?: Array<Pick<ScriptParameter, "key" | "required">>;
} = {}): ScriptItem {
  const review = overrides.review === undefined ? "approved" : overrides.review;
  return {
    id, name: `Script ${id}`, latest_version: 2, record_version: 1,
    deprecated_at: overrides.deprecated ? "2026-02-01T00:00:00Z" : null, deprecated_by: overrides.deprecated ? "admin" : null,
    created_by: "author", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
    latest: {
      id: `${id}-v2`, version: 2, language: overrides.language ?? "powershell", content_sha256: "a".repeat(64), content_bytes: 4,
      description: null, tags: [], supported_platforms: ["windows"], created_by: "author", created_at: "2026-01-01T00:00:00Z",
      parameters: (overrides.parameters ?? []).map((p) => ({
        ...p, label: p.key, description: null, kind: "string", has_default: false, default_value: null,
        min_length: null, max_length: null, minimum: null, maximum: null, choices: null,
      })),
      review: review ? { state: review, reviewed_by: "reviewer", reason_sha256: "b".repeat(64), reason_bytes: 2, created_at: "2026-01-02T00:00:00Z" } : null,
    },
  };
}

test("only approved, live, kind-matching scripts without required parameters can be scheduled", () => {
  const items = [
    script("ok"),
    script("unreviewed", { review: null }),
    script("rejected", { review: "rejected" }),
    script("retired", { deprecated: true }),
    script("bash", { language: "shell" }),
    script("needs-input", { parameters: [{ key: "Path", required: true }] }),
    script("optional-input", { parameters: [{ key: "Verbose", required: false }] }),
  ];
  assert.deepEqual(schedulableScripts(items, "powershell").map((item) => item.id), ["ok", "optional-input"]);
  assert.deepEqual(schedulableScripts(items, "shell").map((item) => item.id), ["bash"]);
});

test("site options are grouped by client and labelled Client — Site", () => {
  // The full navigation response shape, as the API returns it.
  const navigation = {
    truncated: false,
    items: [
      { id: "c1", name: "Acme", sites: [{ id: "s1", client_id: "c1", name: "HQ", endpoint_count: 3 }, { id: "s2", client_id: "c1", name: "Lab", endpoint_count: 0 }] },
      { id: "c2", name: "Globex", sites: [{ id: "s3", client_id: "c2", name: "HQ", endpoint_count: 1 }] },
      { id: "c3", name: "Empty Co", sites: [] },
    ],
  };
  const groups = siteOptionGroups(navigation);
  assert.deepEqual(groups, [
    { client: "Acme", options: [{ id: "s1", label: "Acme — HQ" }, { id: "s2", label: "Acme — Lab" }] },
    { client: "Globex", options: [{ id: "s3", label: "Globex — HQ" }] },
  ]);
});
