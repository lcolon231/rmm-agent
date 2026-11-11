// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";

import { csvCell, endpointsHref, parseEndpointsQuery } from "../src/lib/endpoints-list-core.ts";

test("unknown or malformed query values fall back to safe defaults", () => {
  assert.deepEqual(parseEndpointsQuery({ status: "critical", page: "-2", search: "   ", client: "../etc", site: ["a", "b"] }), {
    client: undefined,
    site: undefined,
    status: undefined,
    search: undefined,
    page: 1,
  });
  assert.equal(parseEndpointsQuery({ search: "x".repeat(300) }).search?.length, 100);
  assert.equal(parseEndpointsQuery({ page: "9999999" }).page, 1, "absurd pages are not forwarded");
});

test("changing a filter keeps the others and returns to page 1", () => {
  const current = parseEndpointsQuery({ client: "c1", status: "offline", search: "PHX", page: "4" });
  assert.equal(endpointsHref(current, { status: "online" }), "/endpoints?client=c1&status=online&search=PHX");
  assert.equal(endpointsHref(current, { page: 5 }), "/endpoints?client=c1&status=offline&search=PHX&page=5");
  assert.equal(endpointsHref(current, { status: undefined, search: undefined }), "/endpoints?client=c1");
  assert.equal(endpointsHref(parseEndpointsQuery({}), {}), "/endpoints");
});

test("search text is encoded, never injected into the URL", () => {
  const href = endpointsHref(parseEndpointsQuery({}), { search: "a&status=online#x" });
  assert.equal(new URL(href, "http://x").searchParams.get("search"), "a&status=online#x");
  assert.equal(new URL(href, "http://x").searchParams.get("status"), null);
});

test("exported cells cannot run as spreadsheet formulas", () => {
  assert.equal(csvCell('=HYPERLINK("http://evil","x")'), `"'=HYPERLINK(""http://evil"",""x"")"`);
  for (const lead of ["+", "-", "@", "\t", "\r"]) assert.ok(csvCell(`${lead}cmd`).startsWith(`"'`), JSON.stringify(lead));
  assert.equal(csvCell("PHX-FD-02"), '"PHX-FD-02"');
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(42), '"42"');
});
