// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  exportQueryFromUrl,
  handlePatchComplianceExport,
  neutralizeCsv,
  neutralizeCsvCell,
  parseCsv,
} from "../src/lib/patch-compliance-export-route-core.ts";
import { SENTINEL, bffContract, request, sessionFor, upstream } from "./bff-contract.ts";

const header = "client_id,client_name,hostname,state,total_missing";
const csv = `${header}\r\nc-1,"Acme, Inc.",PC-1,compliant,0\r\n`;

function csvResponse(body = csv) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": 'attachment; filename="patch-compliance-20261021T120000Z.csv"',
      "X-Internal": SENTINEL,
    },
  });
}

bffContract([
  {
    name: "patch compliance export",
    minRole: "readonly",
    mutation: false,
    upstreamResult: () => csvResponse(),
    invoke: ({ getSession, call }) =>
      handlePatchComplianceExport(request("/api/patch-compliance/export?format=csv"), {
        getSession,
        requestExport: call as (token: string, query: URLSearchParams) => Promise<Response>,
      }),
  },
]);

test("the query is validated and rebuilt from an allowlist", () => {
  assert.equal(exportQueryFromUrl("https://d.test/x?format=xml"), null);
  assert.equal(exportQueryFromUrl("https://d.test/x?state=hacked"), null);
  const parsed = exportQueryFromUrl(`https://d.test/x?format=json&state=stale&client_id=${"a".repeat(50)}&extra=1`);
  assert.equal(parsed?.format, "json");
  assert.equal(parsed?.query.toString(), `format=json&client_id=${"a".repeat(36)}&state=stale`);
});

test("an invalid query is refused before forwarding", async () => {
  const double = upstream(() => csvResponse());
  const response = await handlePatchComplianceExport(request("/api/patch-compliance/export?format=xlsx"), {
    getSession: sessionFor("readonly"),
    requestExport: double.fn as never,
  });
  assert.equal(response.status, 400);
  assert.equal(double.calls.length, 0);
});

test("the download carries a safe filename and none of the upstream headers", async () => {
  const response = await handlePatchComplianceExport(request("/api/patch-compliance/export"), {
    getSession: sessionFor("readonly"),
    requestExport: async () => csvResponse(),
  });
  assert.equal(response.headers.get("content-type"), "text/csv; charset=utf-8");
  assert.equal(response.headers.get("content-disposition"), 'attachment; filename="patch-compliance-20261021T120000Z.csv"');
  assert.equal(response.headers.get("x-internal"), null);
  assert.equal(await response.text(), csv);
});

test("upstream failures map to a fixed message", async () => {
  const failed = await handlePatchComplianceExport(request("/x"), {
    getSession: sessionFor("readonly"),
    requestExport: async () => new Response(SENTINEL, { status: 500 }),
  });
  assert.equal(failed.status, 500);
  assert.ok(!(await failed.text()).includes(SENTINEL));
  const transport = await handlePatchComplianceExport(request("/x"), {
    getSession: sessionFor("readonly"),
    requestExport: async () => { throw new TypeError("fetch failed"); },
  });
  assert.equal(transport.status, 503);
});

test("the CSV parser round-trips quoting, embedded newlines, and a missing final newline", () => {
  assert.deepEqual(parseCsv('a,"b ""q"", c","line\nbreak"\r\nd,,e'), [
    ["a", 'b "q", c', "line\nbreak"],
    ["d", "", "e"],
  ]);
  assert.deepEqual(parseCsv(""), []);
});

test("formula-leading cells are neutralized; ordinary cells are untouched", () => {
  for (const hostile of ["=HYPERLINK(\"https://evil\",\"x\")", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\t=1", "\r=1"]) {
    const safe = neutralizeCsvCell(hostile);
    assert.ok(!/^[=+\-@\t\r]/.test(safe), `${JSON.stringify(hostile)} -> ${JSON.stringify(safe)}`);
    assert.ok(safe.includes(hostile.trimStart()), "the original text stays readable");
  }
  for (const benign of ["PC-1", "compliant", "0", "12", "2026-10-21T12:00:00+00:00", "", "Acme, Inc."]) {
    assert.equal(neutralizeCsvCell(benign), benign);
  }
});

test("a hostile hostname cannot reach the download as a live formula", async () => {
  const hostile = `${header}\r\nc-1,Acme,"=HYPERLINK(""https://evil.example"",""open"")",compliant,0\r\n`;
  const response = await handlePatchComplianceExport(request("/x"), {
    getSession: sessionFor("readonly"),
    requestExport: async () => csvResponse(hostile),
  });
  const rows = parseCsv(await response.text());
  assert.equal(rows.length, 2);
  for (const cell of rows.flat()) assert.ok(!/^[=+\-@\t\r]/.test(cell), cell);
  assert.equal(neutralizeCsv(csv), csv, "a clean export is byte-identical");
});
