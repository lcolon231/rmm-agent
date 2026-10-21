// SPDX-License-Identifier: AGPL-3.0-only
// The one place each pure route core's cookie instructions become real
// `Set-Cookie` headers (issue #281).

import assert from "node:assert/strict";
import test from "node:test";

import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { applyMfaResult } from "@/lib/mfa-route";

const appliers = [
  ["applyAdminSessionResult", applyAdminSessionResult],
  ["applyMfaResult", applyMfaResult],
] as const;

for (const [name, apply] of appliers) {
  test(`${name} returns the response untouched when there are no cookies`, () => {
    const response = Response.json({ ok: true });
    assert.equal(apply({ response, cookies: [] }), response);
  });

  test(`${name} keeps status, headers and body while setting each cookie`, async () => {
    const response = Response.json({ ok: true }, { status: 201, headers: { "Cache-Control": "no-store" } });
    const applied = apply({
      response,
      cookies: [
        { name: "nodelink-session", value: "fresh", options: { httpOnly: true, path: "/", sameSite: "lax" } },
        { name: "nodelink-mfa-pending", value: "", options: { httpOnly: true, path: "/", maxAge: 0 } },
      ],
    });

    assert.equal(applied.status, 201);
    assert.equal(applied.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(await applied.json(), { ok: true });
    const setCookies = applied.headers.getSetCookie();
    assert.equal(setCookies.length, 2);
    assert.match(setCookies[0], /^nodelink-session=fresh;.*HttpOnly/i);
    assert.match(setCookies[1], /^nodelink-mfa-pending=;.*Max-Age=0/i);
  });
}
