import assert from "node:assert/strict";
import test from "node:test";

import {
  isSameOrigin,
  sessionCookieName,
  sessionCookieOptions,
  validateLoginCredentials,
} from "../src/lib/dashboard-auth-core.ts";

test("normalizes valid login credentials", () => {
  assert.deepEqual(validateLoginCredentials({ email: "  Operator@Example.com ", password: "correct horse" }), {
    email: "operator@example.com",
    password: "correct horse",
  });
});

test("rejects malformed credentials", () => {
  assert.equal(validateLoginCredentials({ email: "not-an-email", password: "password" }), null);
  assert.equal(validateLoginCredentials({ email: "operator@example.com", password: "" }), null);
  assert.equal(validateLoginCredentials(null), null);
});

test("requires an exact same-origin request", () => {
  assert.equal(isSameOrigin("https://dashboard.example.test", "https://dashboard.example.test"), true);
  assert.equal(isSameOrigin("https://attacker.example.test", "https://dashboard.example.test"), false);
  assert.equal(isSameOrigin(null, "https://dashboard.example.test"), false);
});

test("uses secure, host-only production session cookies", () => {
  assert.equal(sessionCookieName("production"), "__Host-nodelink-session");
  assert.deepEqual(sessionCookieOptions("production"), {
    httpOnly: true,
    maxAge: 3600,
    path: "/",
    priority: "high",
    sameSite: "lax",
    secure: true,
  });
});

test("uses an HTTP development session cookie", () => {
  assert.equal(sessionCookieName("development"), "nodelink-session");
  assert.equal(sessionCookieOptions("development").secure, false);
});
