// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  isSameOrigin,
  loginErrorMessage,
  readLoginSubmission,
  requestOrigin,
  sanitizedLoginUrl,
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

test("derives the browser-visible origin from the incoming host", () => {
  assert.equal(
    requestOrigin("http://localhost:3000/api/auth/login", "127.0.0.1:3000"),
    "http://127.0.0.1:3000",
  );
  assert.equal(
    requestOrigin("https://dashboard.example.test/api/auth/login", "attacker.test/path"),
    "https://dashboard.example.test",
  );
});

test("strips legacy credential query parameters before rendering login", () => {
  const original = new URL("https://dashboard.example.test/login?email=user%40example.test&password=secret");
  const sanitized = sanitizedLoginUrl(original);
  assert.equal(sanitized?.href, "https://dashboard.example.test/login");
  assert.equal(original.searchParams.get("password"), "secret");
  assert.equal(sanitizedLoginUrl(new URL("https://dashboard.example.test/login?error=invalid-request")), null);
});

test("reads JSON and native form login submissions without using the URL", async () => {
  const jsonSubmission = await readLoginSubmission(new Request("https://dashboard.example.test/api/auth/login", {
    body: JSON.stringify({ email: "operator@example.com", password: "test-password" }),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  }));
  assert.equal(jsonSubmission?.kind, "json");
  assert.deepEqual(jsonSubmission?.body, {
    email: "operator@example.com",
    password: "test-password",
  });

  const formSubmission = await readLoginSubmission(new Request("https://dashboard.example.test/api/auth/login", {
    body: new URLSearchParams({ email: "operator@example.com", password: "test-password" }),
    method: "POST",
  }));
  assert.equal(formSubmission?.kind, "form");
  assert.deepEqual(formSubmission?.body, {
    email: "operator@example.com",
    password: "test-password",
  });
});

test("only renders allow-listed login error messages", () => {
  assert.equal(loginErrorMessage("invalid-credentials"), "Email or password is incorrect.");
  assert.equal(loginErrorMessage("password=secret"), undefined);
  assert.equal(loginErrorMessage(["invalid-credentials"]), undefined);
});

test("login form has a safe native POST fallback", async () => {
  const source = await readFile(new URL("../src/components/login-form.tsx", import.meta.url), "utf8");
  assert.match(source, /<form action="\/api\/auth\/login" method="post" onSubmit=/);
  assert.doesNotMatch(source, /router\.refresh\(\)/);
});
