// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  SHELL_SESSION_CAPABILITY,
  describeShellSessionAvailability,
  isShellSessionStatus,
  shellFrameBatchFromUnknown,
  shellSessionFromUnknown,
  shellSessionOpenErrorMessage,
  shellSessionStatePresentation,
} from "../src/lib/shell-session-core.ts";

test("availability is fail-closed across trust, capability, and scope", () => {
  assert.equal(
    describeShellSessionAvailability({
      trusted: false,
      capable: true,
      canExecuteScripts: true,
    }).availability,
    "unavailable_untrusted",
  );
  assert.equal(
    describeShellSessionAvailability({
      trusted: true,
      capable: false,
      canExecuteScripts: true,
    }).availability,
    "unsupported",
  );
  assert.equal(
    describeShellSessionAvailability({
      trusted: true,
      capable: true,
      canExecuteScripts: false,
    }).availability,
    "unavailable_forbidden",
  );
  const ok = describeShellSessionAvailability({
    trusted: true,
    capable: true,
    canExecuteScripts: true,
  });
  assert.equal(ok.availability, "available");
  assert.equal(ok.canOpen, true);
});

test("state presentation marks terminal states", () => {
  assert.equal(shellSessionStatePresentation("active").terminal, false);
  assert.equal(shellSessionStatePresentation("pending").terminal, false);
  for (const s of ["closed", "denied", "timed_out", "failed"] as const) {
    assert.equal(shellSessionStatePresentation(s).terminal, true);
  }
  assert.equal(shellSessionStatePresentation("active").tone, "positive");
});

test("status guard only accepts known states", () => {
  assert.equal(isShellSessionStatus("active"), true);
  assert.equal(isShellSessionStatus("nonsense"), false);
  assert.equal(isShellSessionStatus(42), false);
});

test("session allowlisting keeps expected fields and drops secret-adjacent ones", () => {
  const session = shellSessionFromUnknown({
    id: "s1",
    agent_id: "a1",
    status: "pending",
    capability_version: SHELL_SESSION_CAPABILITY,
    close_reason: null,
    created_at: "2026-08-08T00:00:00Z",
    activated_at: null,
    last_activity_at: null,
    closed_at: null,
    absolute_deadline: "2026-08-08T00:30:00Z",
    idle_deadline: "2026-08-08T00:05:00Z",
    output_bytes_limit: 1048576,
    output_bytes_total: 0,
    frames_in: 0,
    frames_out: 0,
    client_last_seq: 0,
    agent_last_seq: 0,
    // secret-adjacent field that must never survive
    access_token: "session-token-sentinel",
    stdout: "should not appear",
  });
  assert.ok(session);
  assert.equal(session.status, "pending");
  assert.equal(session.capability_version, SHELL_SESSION_CAPABILITY);
  assert.doesNotMatch(
    JSON.stringify(session),
    /session-token-sentinel|access_token|stdout/,
  );
});

test("frame batches validate sequence, streams, and bounded payload shape", () => {
  const session = {
    id: "s1", agent_id: "a1", status: "active", capability_version: SHELL_SESSION_CAPABILITY,
    close_reason: null, created_at: "2026-08-08T00:00:00Z", activated_at: null,
    last_activity_at: null, closed_at: null, absolute_deadline: null, idle_deadline: null,
    output_bytes_limit: 100, output_bytes_total: 2, frames_in: 0, frames_out: 1,
    client_last_seq: 0, agent_last_seq: 1,
  };
  const batch = shellFrameBatchFromUnknown({
    session,
    frames: [{ seq: 1, stream: "stdout", data_b64: "b2s=", eof: false, byte_length: 2 }],
    bearer_token: "must-drop",
  });
  assert.ok(batch);
  assert.equal(batch.frames[0].stream, "stdout");
  assert.doesNotMatch(JSON.stringify(batch), /bearer_token|must-drop/);
  assert.equal(shellFrameBatchFromUnknown({ session, frames: [{ seq: 0, stream: "stdout", data_b64: "", eof: false, byte_length: 0 }] }), null);
  assert.equal(shellFrameBatchFromUnknown({ session, frames: [{ seq: 1, stream: "input", data_b64: "", eof: false, byte_length: 0 }] }), null);
});

test("session allowlisting rejects malformed shapes", () => {
  assert.equal(shellSessionFromUnknown(null), null);
  assert.equal(shellSessionFromUnknown({ id: "x" }), null);
  assert.equal(
    shellSessionFromUnknown({ id: "x", agent_id: "y", status: "bogus" }),
    null,
  );
});

test("open error messages map codes to operator guidance", () => {
  assert.match(shellSessionOpenErrorMessage("agent_not_trusted", 409), /quarantined|revoked/);
  assert.match(
    shellSessionOpenErrorMessage("shell_session_unsupported", 409),
    /does not support/,
  );
  assert.match(
    shellSessionOpenErrorMessage("shell_session_already_active", 409),
    /already active/,
  );
  assert.match(shellSessionOpenErrorMessage(null, 401), /Sign in/);
});
