// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  canManageEnrollment,
  createTokenInputFromForm,
  formatEnrollmentDateTime,
  maskEnrollmentToken,
  statusLabel,
} from "../src/lib/enrollment-core.ts";

test("role capabilities keep viewers read-only", () => {
  assert.equal(canManageEnrollment("readonly"), false);
  assert.equal(canManageEnrollment("operator"), true);
  assert.equal(canManageEnrollment("admin"), true);
});

test("masking never includes more than a support prefix", () => {
  assert.equal(maskEnrollmentToken("nlenr_abcdef_secret"), "nlenr_abcdef••••••••");
  assert.equal(maskEnrollmentToken(""), "nlenr••••••••");
});

test("status labels are stable", () => {
  assert.equal(statusLabel("active"), "Active");
  assert.equal(statusLabel("revoked"), "Revoked");
});

test("UTC timestamps include the time zone exactly once", () => {
  const formatted = formatEnrollmentDateTime("2026-07-28T02:37:53Z", "Never", true);
  assert.match(formatted, /UTC$/);
  assert.equal(formatted.match(/UTC/g)?.length, 1);
  assert.equal(formatEnrollmentDateTime(null), "Never");
});

test("create form validates future expiry, use limits, and labels", () => {
  const form = new FormData();
  form.set("site_id", "site-1");
  form.set("name", "Tampa rollout");
  form.set("expires_at", new Date(Date.now() + 3_600_000).toISOString());
  form.set("max_uses", "1");
  form.set("labels", "windows, production");
  const value = createTokenInputFromForm(form);
  assert.ok(value);
  assert.deepEqual(value.labels, ["windows", "production"]);

  form.set("labels", "windows, WINDOWS");
  assert.equal(createTokenInputFromForm(form), null);
  form.set("labels", "windows");
  form.set("max_uses", "0");
  assert.equal(createTokenInputFromForm(form), null);
});
