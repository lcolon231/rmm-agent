// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { render, screen } from "@testing-library/react";
let failed = false;
mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => ({ kind: "authenticated", sessionToken: "t" }) } });
mock.module("@/lib/audit", { namedExports: {
 getAuditEventTypes: async () => ["agent.enrolled"],
 getAuditEventPage: async () => { if (failed) throw Error("down"); return { items: [{ id: "e1", seq: 99, action: "agent.enrolled", actor: "operator", agent_id: null, enrollment_token_id: null, ts: "2026-01-01T00:00:00Z" }], total: 150, page: 2, page_size: 50, before_seq: 100 }; },
 verifyAuditChain: async () => { throw Error("down"); }, getAuditPublicationStatus: async () => { throw Error("down"); },
} });
const { default: Page } = await import("@/app/audit/page");
test("audit pagination retains the sequence ceiling and filters when integrity is unavailable", async () => {
 failed = false;
 render(await Page({ searchParams: Promise.resolve({ page: "2", actor: "operator", before: "100" }) }));
 assert.ok(screen.getByRole("link", { name: /agent enrolled/i }));
 const older = new URL(screen.getByRole("link", { name: /Older/ }).getAttribute("href")!, "https://example.test");
 assert.equal(older.searchParams.get("before"), "100"); assert.equal(older.searchParams.get("actor"), "operator"); assert.equal(older.searchParams.get("page"), "3");
 assert.ok(screen.getByText("Unknown"));
});
test("an unreadable audit timeline never claims no events exist", async () => {
 failed = true;
 render(await Page({ searchParams: Promise.resolve({}) }));
 assert.match(screen.getByRole("alert").textContent ?? "", /not evidence that no events exist/);
 assert.equal(screen.queryByText("No audit events were returned."), null);
});

