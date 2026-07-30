// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  auditDetailRows,
  auditPageCount,
  auditPageHref,
  auditQueryToSearchParams,
  describeAnchorVerification,
  describeChainIntegrity,
  describePublication,
  describeReceipt,
  formatAuditAction,
  formatAuditDuration,
  formatAuditSequence,
  formatAuditTimestamp,
  hasAuditFilters,
  hasIntegrityFailure,
  hasNextAuditPage,
  parseAuditQuery,
  type AuditAnchorPublication,
  type AuditPublicationStatus,
} from "../src/lib/audit-core.ts";

const EVENT_TYPES = ["agent.enrolled", "agent.revoked", "audit.anchored"];

function publication(overrides: Partial<AuditPublicationStatus> = {}): AuditPublicationStatus {
  return {
    backend: "s3",
    total_anchors: 4,
    published: 4,
    pending: 0,
    oldest_unpublished_age_seconds: null,
    lag_alert: false,
    last_error: null,
    ...overrides,
  };
}

function receipt(overrides: Partial<AuditAnchorPublication> = {}): AuditAnchorPublication {
  return {
    backend: "s3",
    status: "published",
    uri: "s3://evidence/anchor-1",
    receipt: { version_id: "abc" },
    receipt_sha256: "a".repeat(64),
    receipt_intact: true,
    receipt_reason: null,
    attempts: 1,
    last_error: null,
    published_at: "2026-07-24T10:00:00Z",
    ...overrides,
  };
}

test("query parsing keeps only filters the server can match", () => {
  const query = parseAuditQuery(
    {
      actor: "  operator@nodelink.test  ",
      agent: "11111111-1111-4111-8111-111111111111",
      event: "agent.revoked",
      from: "2026-07-01",
      page: "3",
      to: "2026-07-24",
    },
    EVENT_TYPES,
  );
  assert.equal(query.actor, "operator@nodelink.test");
  assert.equal(query.agentId, "11111111-1111-4111-8111-111111111111");
  assert.equal(query.eventType, "agent.revoked");
  assert.equal(query.dateFrom, "2026-07-01");
  assert.equal(query.dateTo, "2026-07-24");
  assert.equal(query.page, 3);
});

test("an unknown event type is dropped rather than producing a silently empty timeline", () => {
  const query = parseAuditQuery({ event: "agent.enroled" }, EVENT_TYPES);
  assert.equal(query.eventType, undefined);
  assert.equal(hasAuditFilters(query), false);
});

test("malformed pages, dates, and oversized filters fall back to safe defaults", () => {
  const query = parseAuditQuery(
    { page: "-4", from: "07/01/2026", to: "2026-13-45", actor: "a".repeat(256), agent: "b".repeat(37) },
    EVENT_TYPES,
  );
  assert.equal(query.page, 1);
  assert.equal(query.dateFrom, undefined);
  assert.equal(query.dateTo, undefined);
  assert.equal(query.actor, undefined);
  assert.equal(query.agentId, undefined);
});

test("query round-trips through the page URL and omits the default page", () => {
  const query = parseAuditQuery({ event: "audit.anchored", actor: "ops", page: "1" }, EVENT_TYPES);
  assert.equal(auditQueryToSearchParams(query).toString(), "event=audit.anchored&actor=ops");
  assert.equal(auditPageHref(parseAuditQuery({}, EVENT_TYPES), 1), "/audit");
});

test("page 1 adopts the server's sequence ceiling so page 2 reads the same snapshot", () => {
  const first = parseAuditQuery({}, EVENT_TYPES);
  assert.equal(first.beforeSeq, undefined);
  assert.equal(auditPageHref(first, 2, 4096), "/audit?before=4096&page=2");

  // Once pinned, the ceiling travels with every later page and is not replaced
  // by a newer one the server reports for the snapshot being viewed.
  const second = parseAuditQuery({ before: "4096", page: "2" }, EVENT_TYPES);
  assert.equal(second.beforeSeq, 4096);
  assert.equal(auditPageHref(second, 3, 9999), "/audit?before=4096&page=3");
});

test("the ceiling is dropped on page 1 and when it is not a usable sequence", () => {
  const pinned = parseAuditQuery({ before: "4096", page: "2" }, EVENT_TYPES);
  // Returning to page 1 releases the snapshot rather than freezing the newest view.
  assert.equal(auditPageHref(pinned, 1, 9999), "/audit");
  assert.equal(parseAuditQuery({ before: "0", page: "2" }, EVENT_TYPES).beforeSeq, undefined);
  assert.equal(parseAuditQuery({ before: "-3", page: "2" }, EVENT_TYPES).beforeSeq, undefined);
  assert.equal(parseAuditQuery({ before: "abc", page: "2" }, EVENT_TYPES).beforeSeq, undefined);
});

test("an empty chain reports no ceiling and still produces a usable next link", () => {
  const query = parseAuditQuery({}, EVENT_TYPES);
  assert.equal(auditPageHref(query, 2, null), "/audit?page=2");
});

test("pagination math covers the exact-multiple and empty boundaries", () => {
  assert.equal(auditPageCount(0), 1);
  assert.equal(auditPageCount(50), 1);
  assert.equal(auditPageCount(51), 2);
  assert.equal(hasNextAuditPage(1, 50), false);
  assert.equal(hasNextAuditPage(1, 51), true);
  assert.equal(hasNextAuditPage(2, 100), false);
});

test("an unavailable chain check is reported as unknown, never as verified", () => {
  const statement = describeChainIntegrity(null);
  assert.equal(statement.tone, "unknown");
  assert.match(statement.detail, /unverified/i);
});

test("a broken chain names the first broken event and reads as a failure", () => {
  const statement = describeChainIntegrity({ intact: false, first_broken_event_id: "evt-7" });
  assert.equal(statement.tone, "failed");
  assert.match(statement.headline, /FAILED/);
  assert.match(statement.detail, /evt-7/);
  assert.equal(hasIntegrityFailure(statement), true);
});

test("an intact chain still states what local verification cannot prove", () => {
  const statement = describeChainIntegrity({ intact: true, first_broken_event_id: null });
  assert.equal(statement.tone, "verified");
  assert.match(statement.detail, /external anchors/i);
});

test("disabled external publication is never presented as healthy", () => {
  const statement = describePublication(publication({ backend: null, published: 0, pending: 4 }));
  assert.equal(statement.tone, "unknown");
  assert.match(statement.detail, /only in this database/i);
});

test("publication lag is a failure and reports the pending window", () => {
  const statement = describePublication(
    publication({ pending: 2, published: 2, lag_alert: true, oldest_unpublished_age_seconds: 7_200, last_error: "timeout" }),
  );
  assert.equal(statement.tone, "failed");
  assert.match(statement.detail, /2h 0m/);
  assert.match(statement.detail, /timeout/);
});

test("healthy publication reports the published fraction and backend", () => {
  const statement = describePublication(publication());
  assert.equal(statement.tone, "verified");
  assert.match(statement.detail, /4 of 4 anchors published to s3/);
});

test("a configured backend with nothing anchored yet is not reported as healthy", () => {
  const statement = describePublication(publication({ total_anchors: 0, published: 0 }));
  assert.equal(statement.tone, "unknown");
  assert.match(statement.detail, /no external copy/i);

  const disabled = describePublication(publication({ backend: null, total_anchors: 0, published: 0 }));
  assert.equal(disabled.tone, "unknown");
  assert.doesNotMatch(disabled.detail, /all 0 anchors/);
});

test("an unverified anchor is unknown and a mismatched anchor is a failure", () => {
  assert.equal(describeAnchorVerification(null).tone, "unknown");
  const failed = describeAnchorVerification({ anchor_id: "a1", intact: false, reason: "root mismatch" });
  assert.equal(failed.tone, "failed");
  assert.equal(failed.detail, "root mismatch");
  assert.equal(describeAnchorVerification({ anchor_id: "a1", intact: true, reason: null }).tone, "verified");
});

test("a tampered receipt outranks its publication status", () => {
  const statement = describeReceipt(receipt({ receipt_intact: false, receipt_reason: "digest mismatch" }));
  assert.equal(statement.tone, "failed");
  assert.equal(statement.detail, "digest mismatch");
});

test("a pending receipt is unknown and a published receipt is verified", () => {
  const pending = describeReceipt(receipt({ status: "pending", published_at: null, attempts: 3, last_error: "503" }));
  assert.equal(pending.tone, "unknown");
  assert.match(pending.detail, /3 attempts/);
  assert.match(pending.detail, /503/);
  assert.equal(describeReceipt(receipt()).tone, "verified");
});

test("timestamps render in UTC and legacy sequences are labelled, not blanked", () => {
  const formatted = formatAuditTimestamp("2026-07-24T05:03:09Z");
  assert.match(formatted, /UTC/);
  assert.match(formatted, /Jul 24, 2026/);
  assert.equal(formatAuditTimestamp(null), "Not recorded");
  assert.equal(formatAuditTimestamp("not-a-date"), "Not recorded");
  assert.equal(formatAuditSequence(null), "legacy");
  assert.equal(formatAuditSequence(0), "0");
});

test("durations and action labels stay readable at every scale", () => {
  assert.equal(formatAuditDuration(45), "45s");
  assert.equal(formatAuditDuration(600), "10m");
  assert.equal(formatAuditDuration(7_200), "2h 0m");
  assert.equal(formatAuditDuration(180_000), "2d 2h");
  assert.equal(formatAuditAction("agent.command_envelope_capabilities_changed"), "agent command envelope capabilities changed");
});

test("detail rows sort by key and render every sanitized value shape", () => {
  const rows = auditDetailRows({
    total: 12,
    command_ids: ["c1", "c2"],
    actor_filter: false,
    agent_id: null,
    empty_list: [],
  });
  assert.deepEqual(rows.map((row) => row.key), ["actor_filter", "agent_id", "command_ids", "empty_list", "total"]);
  assert.deepEqual(rows.map((row) => row.value), ["false", "null", "c1, c2", "(empty)", "12"]);
});
