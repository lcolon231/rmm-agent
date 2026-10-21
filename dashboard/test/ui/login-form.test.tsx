// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { LoginForm } from "@/components/login-form";

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function fillAndSubmit(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.submit(screen.getByRole("button", { name: /sign in/i }).closest("form")!);
}

test("empty credentials fail native validation and the no-JS fallback posts a body", () => {
  render(<LoginForm />);
  const form = screen.getByRole("button", { name: /sign in/i }).closest("form")!;
  assert.equal(form.method, "post");
  assert.equal(new URL(form.action).pathname, "/api/auth/login");
  assert.equal(form.checkValidity(), false);
  const email = screen.getByLabelText("Email") as HTMLInputElement;
  assert.equal(email.type, "email");
  assert.equal((screen.getByLabelText("Password") as HTMLInputElement).type, "password");
  fireEvent.change(email, { target: { value: "not-an-email" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
  assert.equal(email.validity.valid, false);
});

test("a server refusal is shown inline and the button re-enables", async (t) => {
  t.mock.method(globalThis, "fetch", async () => jsonResponse(401, { error: "Email or password is incorrect." }));
  render(<LoginForm />);
  fillAndSubmit("tech@example.com", "wrong-password");
  assert.equal((await screen.findByRole("alert")).textContent, "Email or password is incorrect.");
  assert.equal((screen.getByRole("button", { name: /sign in/i }) as HTMLButtonElement).disabled, false);
});

test("an MFA challenge routes to the second step without credentials in any URL", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    jsonResponse(200, { mfa_required: true, mfa_enrollment_required: true, mfa_methods: ["totp", "webauthn"] }));
  const replace = t.mock.method(window.location, "replace", () => {});
  render(<LoginForm />);
  fillAndSubmit("tech@example.com", "hunter2-password");
  await waitFor(() => assert.equal(replace.mock.callCount(), 1));

  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, "/api/auth/login");
  assert.equal(init.method, "POST");
  assert.deepEqual(JSON.parse(String(init.body)), { email: "tech@example.com", password: "hunter2-password" });

  const target = String(replace.mock.calls[0].arguments[0]);
  assert.equal(target, "/login/mfa?methods=totp%2Cwebauthn&enroll=1");
  for (const secret of ["tech@example.com", "tech%40example.com", "hunter2"]) assert.ok(!target.includes(secret));
  assert.ok(!window.location.href.includes("hunter2"));
});

test("a full sign-in goes straight to the fleet", async (t) => {
  t.mock.method(globalThis, "fetch", async () => jsonResponse(200, { ok: true }));
  const replace = t.mock.method(window.location, "replace", () => {});
  render(<LoginForm />);
  fillAndSubmit("tech@example.com", "correct-password");
  await waitFor(() => assert.deepEqual(replace.mock.calls.map((call) => call.arguments[0]), ["/"]));
});

test("a network failure shows the generic unavailable message", async (t) => {
  t.mock.method(globalThis, "fetch", async () => { throw new TypeError("offline"); });
  render(<LoginForm initialError="Session expired." />);
  assert.equal(screen.getByRole("alert").textContent, "Session expired.");
  fillAndSubmit("tech@example.com", "pw");
  await waitFor(() => assert.equal(screen.getByRole("alert").textContent, "Sign-in is unavailable. Try again later."));
});
