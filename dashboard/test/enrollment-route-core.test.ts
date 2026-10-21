// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  createdTokenFromUnknown,
  handleCreateEnrollmentToken,
  handleInstallerPackage,
  handleRevokeAgent,
  handleRevokeEnrollmentToken,
} from "../src/lib/enrollment-route-core.ts";
import { SENTINEL, apiError, bffContract, request, sessionFor, sessionToken, upstream } from "./bff-contract.ts";

const tokenMetadata = {
  id: "token-1",
  site_id: "site-1",
  organization_id: "org-1",
  organization_name: "Acme",
  site_name: "HQ",
  masked_token: "nlk_abcd…",
  name: "Laptops",
  description: null,
  labels: ["laptop"],
  max_uses: 5,
  use_count: 0,
  expires_at: "2026-11-01T00:00:00Z",
  created_at: "2026-10-21T12:00:00Z",
  status: "active",
  notes: null,
  token_hash: SENTINEL,
};
const createBody = { site_id: "site-1", name: "Laptops", labels: ["laptop"], expires_at: "2026-11-01T00:00:00Z", max_uses: 5 };

function zipResponse(headers: Record<string, string> = {}) {
  return new Response(new Uint8Array([0x50, 0x4b, 3, 4]), {
    status: 200,
    headers: {
      "Content-Disposition": 'attachment; filename="nodelink-installer-site-1.zip"',
      "X-Bundled-Token": SENTINEL,
      ...headers,
    },
  });
}

bffContract([
  {
    name: "create enrollment token",
    minRole: "operator",
    mutation: true,
    upstreamResult: { ...tokenMetadata, token: "nlk_plaintext" },
    invoke: ({ getSession, origin, call }) =>
      handleCreateEnrollmentToken(request("/api/enrollment-tokens", "POST", createBody, origin), {
        createEnrollmentToken: call,
        getSession,
      }),
  },
  {
    name: "revoke enrollment token",
    minRole: "operator",
    mutation: true,
    upstreamResult: { ...tokenMetadata, status: "revoked" },
    invoke: ({ getSession, origin, call }) =>
      handleRevokeEnrollmentToken(
        request("/api/enrollment-tokens/token-1/revoke", "POST", { reason: "Lost laptop" }, origin),
        "token-1",
        { getSession, revokeEnrollmentToken: call },
      ),
  },
  {
    name: "revoke agent",
    minRole: "admin",
    mutation: true,
    upstreamResult: { id: "agent-1", trust_state: "revoked", certificate_serial: SENTINEL },
    invoke: ({ getSession, origin, call }) =>
      handleRevokeAgent(request("/api/enrollment-agents/agent-1/revoke", "POST", { reason: "Stolen" }, origin), "agent-1", {
        getSession,
        revokeAgent: call,
      }),
  },
  {
    name: "installer package",
    minRole: "operator",
    mutation: true,
    upstreamResult: () => zipResponse(),
    invoke: ({ getSession, origin, call }) =>
      handleInstallerPackage(request("/api/sites/site-1/installer-package", "POST", undefined, origin), "site-1", {
        getSession,
        requestInstallerPackage: call as (token: string, siteId: string) => Promise<Response>,
      }),
  },
]);

test("the created token keeps its one-time plaintext and drops unknown fields", async () => {
  const response = await handleCreateEnrollmentToken(request("/api/enrollment-tokens", "POST", createBody), {
    createEnrollmentToken: async () => ({ ...tokenMetadata, token: "nlk_plaintext" }),
    getSession: sessionFor("operator"),
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.token, "nlk_plaintext");
  assert.equal(body.site_name, "HQ");
  assert.equal("token_hash" in body, false);
  assert.equal(createdTokenFromUnknown(tokenMetadata), null, "no plaintext means no created token");
});

test("token creation forwards only the documented input fields", async () => {
  const double = upstream({ ...tokenMetadata, token: "nlk_plaintext" });
  await handleCreateEnrollmentToken(
    request("/api/enrollment-tokens", "POST", { ...createBody, created_by_id: "someone-else" }),
    { createEnrollmentToken: double.fn, getSession: sessionFor("operator") },
  );
  assert.deepEqual(double.calls[0][1], createBody);
});

test("revocations require a 3-500 character reason and forward only it", async () => {
  for (const body of [{}, { reason: "  x " }, { reason: "x".repeat(501) }, "nope"]) {
    const double = upstream(tokenMetadata);
    const response = await handleRevokeEnrollmentToken(request("/x", "POST", body), "token-1", {
      getSession: sessionFor("operator"),
      revokeEnrollmentToken: double.fn,
    });
    assert.equal(response.status, 400);
    assert.equal(double.calls.length, 0);
  }
  const double = upstream({ id: "agent-1", trust_state: "revoked" });
  await handleRevokeAgent(request("/x", "POST", { reason: "  Stolen  ", trust_state: "active" }), "agent-1", {
    getSession: sessionFor("admin"),
    revokeAgent: double.fn,
  });
  assert.deepEqual(double.calls[0], [sessionToken, "agent-1", "Stolen"]);
});

test("revocation errors map to fixed text", async () => {
  const agent = async (status: number) =>
    handleRevokeAgent(request("/x", "POST", { reason: "Stolen" }), "agent-1", {
      getSession: sessionFor("admin"),
      revokeAgent: async () => { throw apiError(status); },
    });
  assert.equal((await agent(404)).status, 404);
  assert.equal((await agent(409)).status, 409);
  assert.equal((await agent(500)).status, 503);

  const token = await handleRevokeEnrollmentToken(request("/x", "POST", { reason: "Lost" }), "token-1", {
    getSession: sessionFor("operator"),
    revokeEnrollmentToken: async () => { throw apiError(404); },
  });
  assert.equal(token.status, 404);
});

test("token creation errors map to fixed text", async () => {
  for (const [upstreamStatus, status] of [[403, 403], [404, 404], [422, 422], [409, 409], [500, 503]]) {
    const response = await handleCreateEnrollmentToken(request("/x", "POST", createBody), {
      createEnrollmentToken: async () => { throw apiError(upstreamStatus); },
      getSession: sessionFor("operator"),
    });
    assert.equal(response.status, status);
  }
});

test("the installer streams the archive with only our own headers", async () => {
  const response = await handleInstallerPackage(request("/x", "POST"), "site-1", {
    getSession: sessionFor("operator"),
    requestInstallerPackage: async () => zipResponse(),
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/zip");
  assert.equal(response.headers.get("x-bundled-token"), null);
  assert.match(response.headers.get("content-disposition") ?? "", /^attachment; filename="[^"]+\.zip"$/);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([0x50, 0x4b, 3, 4]));
});

test("installer failures map through the installer error table", async () => {
  const transport = await handleInstallerPackage(request("/x", "POST"), "site-1", {
    getSession: sessionFor("operator"),
    requestInstallerPackage: async () => { throw new TypeError("fetch failed"); },
  });
  assert.equal(transport.status, 503);

  const refused = await handleInstallerPackage(request("/x", "POST"), "site-1", {
    getSession: sessionFor("operator"),
    requestInstallerPackage: async () =>
      Response.json({ detail: { code: "installer_unavailable", message: SENTINEL } }, { status: 404 }),
  });
  assert.ok(refused.status >= 400);
  assert.ok(!(await refused.text()).includes(SENTINEL));
});
