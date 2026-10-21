// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleCloseShellSession,
  handleGetShellSession,
  handleOpenShellSession,
  handleShellInput,
  handleShellOutput,
} from "../src/lib/shell-session-route-core.ts";
import {
  SENTINEL,
  apiError,
  bffContract,
  request,
  sessionFor,
  sessionToken,
  upstream,
} from "./bff-contract.ts";

const base = "/api/endpoints/agent-1/shell-sessions";

function shellSession(extra: Record<string, unknown> = {}) {
  return {
    id: "shell-1",
    agent_id: "agent-1",
    status: "active",
    created_at: "2026-10-21T12:00:00Z",
    leaked_secret: SENTINEL,
    ...extra,
  };
}

const frameBatch = {
  session: shellSession(),
  frames: [{ seq: 1, stream: "stdout", data_b64: "aGk=", eof: false, byte_length: 2, leaked: SENTINEL }],
  next_after: 1,
  leaked: SENTINEL,
};

bffContract([
  {
    name: "open shell session",
    minRole: "operator",
    mutation: true,
    upstreamResult: shellSession(),
    invoke: ({ getSession, origin, call }) =>
      handleOpenShellSession(request(base, "POST", undefined, origin), "agent-1", {
        getSession,
        openShellSession: call,
      }),
  },
  {
    name: "get shell session",
    minRole: "readonly",
    mutation: false,
    upstreamResult: shellSession(),
    invoke: ({ getSession, call }) =>
      handleGetShellSession(request(`${base}/shell-1`), "agent-1", "shell-1", {
        getSession,
        getShellSession: call,
      }),
  },
  {
    name: "close shell session",
    minRole: "operator",
    mutation: true,
    upstreamResult: shellSession({ status: "closed" }),
    invoke: ({ getSession, origin, call }) =>
      handleCloseShellSession(request(`${base}/shell-1`, "POST", undefined, origin), "agent-1", "shell-1", {
        closeShellSession: call,
        getSession,
      }),
  },
  {
    name: "shell input",
    minRole: "operator",
    mutation: true,
    upstreamResult: shellSession(),
    invoke: ({ getSession, origin, call }) =>
      handleShellInput(
        request(`${base}/shell-1/input`, "POST", { seq: 1, data_b64: "ZGly" }, origin),
        "agent-1",
        "shell-1",
        { getSession, sendShellInput: call },
      ),
  },
  {
    name: "shell output",
    minRole: "operator",
    mutation: false,
    upstreamResult: frameBatch,
    invoke: ({ getSession, call }) =>
      handleShellOutput(request(`${base}/shell-1/output?after=0&ack=0`), "agent-1", "shell-1", {
        getSession,
        readShellOutput: call,
      }),
  },
]);

test("open maps upstream refusals through the open-error messages", async () => {
  const response = await handleOpenShellSession(request(base, "POST"), "agent-1", {
    getSession: sessionFor("operator"),
    openShellSession: async () => {
      throw apiError(409, "agent_not_trusted");
    },
  });
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /\w/);
});

test("open answers 201 with the allowlisted session", async () => {
  const response = await handleOpenShellSession(request(base, "POST"), "agent-1", {
    getSession: sessionFor("operator"),
    openShellSession: async () => shellSession(),
  });
  assert.equal(response.status, 201);
  assert.equal((await response.json()).session.id, "shell-1");
});

test("an invalid upstream session shape is a 502, not a pass-through", async () => {
  const response = await handleGetShellSession(request(`${base}/shell-1`), "agent-1", "shell-1", {
    getSession: sessionFor("readonly"),
    getShellSession: async () => ({ leaked: SENTINEL }),
  });
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes(SENTINEL));
});

test("shell input rejects malformed frames before forwarding", async () => {
  for (const body of [
    "not json",
    { seq: 0, data_b64: "" },
    { seq: 1.5, data_b64: "" },
    { seq: 1, data_b64: 5 },
    { seq: 1, data_b64: "a".repeat(24_001) },
  ]) {
    const double = upstream(shellSession());
    const response = await handleShellInput(request(`${base}/shell-1/input`, "POST", body), "agent-1", "shell-1", {
      getSession: sessionFor("operator"),
      sendShellInput: double.fn,
    });
    assert.equal(response.status, 400);
    assert.equal(double.calls.length, 0);
  }
});

test("shell input forwards only seq and data", async () => {
  const double = upstream(shellSession());
  await handleShellInput(
    request(`${base}/shell-1/input`, "POST", { seq: 3, data_b64: "ZGly", stream: "stdout", eof: true }),
    "agent-1",
    "shell-1",
    { getSession: sessionFor("operator"), sendShellInput: double.fn },
  );
  assert.deepEqual(double.calls[0], [sessionToken, "agent-1", "shell-1", { seq: 3, data_b64: "ZGly" }]);
});

test("shell input reports back-pressure distinctly", async () => {
  const response = await handleShellInput(
    request(`${base}/shell-1/input`, "POST", { seq: 1, data_b64: "" }),
    "agent-1",
    "shell-1",
    { getSession: sessionFor("operator"), sendShellInput: async () => { throw apiError(429); } },
  );
  assert.equal(response.status, 429);
  assert.match((await response.json()).error, /catching up/);
});

test("shell output validates cursors and maps an expired window", async () => {
  for (const query of ["after=-1", "ack=1.5", "after=abc"]) {
    const double = upstream(frameBatch);
    const response = await handleShellOutput(request(`${base}/shell-1/output?${query}`), "agent-1", "shell-1", {
      getSession: sessionFor("operator"),
      readShellOutput: double.fn,
    });
    assert.equal(response.status, 400);
    assert.equal(double.calls.length, 0);
  }
  const expired = await handleShellOutput(request(`${base}/shell-1/output?after=4&ack=2`), "agent-1", "shell-1", {
    getSession: sessionFor("operator"),
    readShellOutput: async () => { throw apiError(409); },
  });
  assert.equal(expired.status, 409);
  assert.match((await expired.json()).error, /expired/);
});

test("shell output forwards parsed cursors", async () => {
  const double = upstream(frameBatch);
  await handleShellOutput(request(`${base}/shell-1/output?after=4&ack=2`), "agent-1", "shell-1", {
    getSession: sessionFor("operator"),
    readShellOutput: double.fn,
  });
  assert.deepEqual(double.calls[0], [sessionToken, "agent-1", "shell-1", 4, 2]);
});
