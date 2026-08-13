// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  describeRemoteDesktopAvailability,
  isMeshLaunchStatus,
  meshLaunchFromUnknown,
  remoteDesktopAvailabilityFromUnknown,
  remoteDesktopLaunchErrorMessage,
} from "../src/lib/remote-desktop-core.ts";

test("availability is fail-closed for every non-available reason", () => {
  const available = describeRemoteDesktopAvailability({
    available: true,
    reason: "available",
  });
  assert.equal(available.canLaunch, true);

  for (const reason of [
    "provider_disabled",
    "agent_not_trusted",
    "not_authorized",
    "no_mapping",
    "mapping_unmapped",
    "mapping_stale",
    "mapping_conflict",
  ]) {
    const decided = describeRemoteDesktopAvailability({ available: false, reason });
    assert.equal(decided.canLaunch, false, reason);
    assert.ok(decided.message.length > 0);
  }
});

test("an unknown reason still fails closed with a generic message", () => {
  const decided = describeRemoteDesktopAvailability({
    available: false,
    reason: "something_new",
  });
  assert.equal(decided.canLaunch, false);
  assert.match(decided.message, /unavailable/i);
});

test("available=true but a non-available reason is refused", () => {
  const decided = describeRemoteDesktopAvailability({
    available: true,
    reason: "mapping_stale",
  });
  assert.equal(decided.canLaunch, false);
});

test("launch status guard", () => {
  assert.equal(isMeshLaunchStatus("authorized"), true);
  assert.equal(isMeshLaunchStatus("bogus"), false);
  assert.equal(isMeshLaunchStatus(3), false);
});

test("meshLaunchFromUnknown allowlists fields and drops unexpected/secret keys", () => {
  const parsed = meshLaunchFromUnknown({
    id: "L1",
    agent_id: "A1",
    status: "authorized",
    meshcentral_node_id: "node//abc",
    denied_reason: null,
    expires_at: "2026-08-12T00:02:00Z",
    created_at: "2026-08-12T00:00:00Z",
    closed_at: null,
    login_url: "https://mesh/?c=token",
    login_expires_at: "2026-08-12T00:02:00Z",
    // Attacker/regression-injected extras must not survive.
    meshcentral_admin_token: "SECRET",
    cookie: "SECRET",
    extra: { nested: "SECRET" },
  });
  assert.ok(parsed);
  const serialized = JSON.stringify(parsed);
  assert.doesNotMatch(serialized, /SECRET/);
  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "cookie"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "extra"), false);
  // login_url is legitimately retained (create-once).
  assert.equal(parsed!.login_url, "https://mesh/?c=token");
});

test("meshLaunchFromUnknown rejects malformed shapes", () => {
  assert.equal(meshLaunchFromUnknown(null), null);
  assert.equal(meshLaunchFromUnknown({ id: "x" }), null);
  assert.equal(
    meshLaunchFromUnknown({ id: "x", agent_id: "y", status: "nope" }),
    null,
  );
});

test("availability shape validation", () => {
  assert.deepEqual(
    remoteDesktopAvailabilityFromUnknown({
      available: false,
      reason: "no_mapping",
      provider_enabled: true,
    }),
    { available: false, reason: "no_mapping", provider_enabled: true },
  );
  assert.equal(remoteDesktopAvailabilityFromUnknown({ available: "yes" }), null);
  assert.equal(remoteDesktopAvailabilityFromUnknown(null), null);
});

test("launch error messages map server codes to guidance", () => {
  assert.match(
    remoteDesktopLaunchErrorMessage("remote_desktop_disabled", 409),
    /not configured/i,
  );
  assert.match(
    remoteDesktopLaunchErrorMessage("remote_desktop_unavailable", 503),
    /unavailable/i,
  );
  assert.match(
    remoteDesktopLaunchErrorMessage("remote_desktop_rate_limited", 429),
    /wait a minute/i,
  );
  assert.match(remoteDesktopLaunchErrorMessage(null, 401), /sign in/i);
  assert.match(remoteDesktopLaunchErrorMessage(null, 404), /no longer exists/i);
});
