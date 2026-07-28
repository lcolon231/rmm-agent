// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dashboardRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const nextBin = join(dashboardRoot, "node_modules", "next", "dist", "bin", "next");
const buildId = join(dashboardRoot, ".next", "BUILD_ID");
const smokeToken = "enr_smoke_value_returned_once";
const now = "2026-07-28T00:00:00Z";

assert(existsSync(buildId), "Run `npm run build` before the production smoke test.");

const operator = {
  id: "user-smoke",
  email: "admin@example.invalid",
  role: "admin",
  disabled: false,
};

const tokenMetadata = {
  id: "token-smoke",
  site_id: "site-smoke",
  organization_id: "client-smoke",
  organization_name: "Smoke Client",
  site_name: "Smoke Site",
  masked_token: "enr_…moke",
  name: "Smoke enrollment",
  description: "Production-route smoke fixture",
  assigned_user_id: null,
  assigned_user_email: null,
  environment: "test",
  hostname_restriction: null,
  agent_name_restriction: null,
  labels: ["smoke"],
  max_uses: 1,
  use_count: 0,
  expires_at: "2026-07-29T00:00:00Z",
  created_at: now,
  created_by_id: operator.id,
  created_by_email: operator.email,
  last_used_at: null,
  revoked_at: null,
  revoked_by_id: null,
  revoked_by_email: null,
  status: "active",
  notes: null,
};

const agent = {
  id: "agent-smoke",
  site_id: "site-smoke",
  name: "Smoke Agent",
  hostname: "smoke.example.invalid",
  os: "Windows",
  os_version: "11",
  agent_version: "0.1.2",
  architecture: "amd64",
  environment: "test",
  labels: ["smoke"],
  owner_user_id: null,
  enrolled_by_token_id: tokenMetadata.id,
  credential_fingerprint: "a".repeat(64),
  credential_issued_at: now,
  credential_expires_at: null,
  command_envelope_versions: ["v1"],
  status: "online",
  trust_state: "active",
  trust_state_reason: null,
  trust_state_changed_at: null,
  trust_state_changed_by: null,
  last_seen_at: now,
  enrolled_at: now,
  revoked_at: null,
};

function sendJson(response, body, status = 200) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

function createMockApi() {
  return createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://mock.invalid");
    const method = request.method ?? "GET";

    if (method === "POST" && url.pathname === "/api/v1/auth/login") {
      sendJson(response, { access_token: "smoke-session", token_type: "bearer" });
      return;
    }

    if (request.headers.authorization !== "Bearer smoke-session") {
      sendJson(response, { detail: "unauthorized" }, 401);
      return;
    }

    if (method === "GET" && url.pathname === "/api/v1/auth/me") {
      sendJson(response, operator);
    } else if (method === "GET" && url.pathname === "/api/v1/enrollment-dashboard") {
      sendJson(response, {
        total_agents: 1,
        active_agents: 1,
        offline_agents: 0,
        revoked_agents: 0,
        active_enrollment_tokens: 1,
        expired_tokens: 0,
        recently_enrolled_agents: [agent],
        recent_enrollment_failures: 0,
      });
    } else if (method === "GET" && url.pathname === "/api/v1/clients/navigation") {
      sendJson(response, {
        items: [{
          id: "client-smoke",
          name: "Smoke Client",
          sites: [{
            id: "site-smoke",
            client_id: "client-smoke",
            name: "Smoke Site",
            endpoint_count: 1,
          }],
        }],
        truncated: false,
      });
    } else if (method === "GET" && url.pathname === "/api/v1/enrollment-tokens") {
      sendJson(response, { items: [tokenMetadata], page: 1, page_size: 25, total: 1 });
    } else if (method === "POST" && url.pathname === "/api/v1/enrollment-tokens") {
      sendJson(response, { ...tokenMetadata, token: smokeToken }, 201);
    } else if (
      method === "POST" &&
      url.pathname === `/api/v1/enrollment-tokens/${tokenMetadata.id}/revoke`
    ) {
      sendJson(response, { ...tokenMetadata, status: "revoked", revoked_at: now });
    } else if (method === "GET" && url.pathname === "/api/v1/agents") {
      sendJson(response, [agent]);
    } else if (method === "GET" && url.pathname === `/api/v1/agents/${agent.id}`) {
      sendJson(response, agent);
    } else if (method === "POST" && url.pathname === `/api/v1/agents/${agent.id}/revoke`) {
      sendJson(response, { ...agent, trust_state: "revoked", revoked_at: now });
    } else if (method === "GET" && url.pathname === "/api/v1/audit/events") {
      sendJson(response, {
        items: [{
          id: "audit-smoke",
          seq: 1,
          ts: now,
          actor: operator.email,
          actor_user_id: operator.id,
          action: "agent.enrolled",
          agent_id: agent.id,
          enrollment_token_id: tokenMetadata.id,
          organization_id: "client-smoke",
          source_ip: "127.0.0.1",
          detail: {},
        }],
        page: 1,
        page_size: 50,
        total: 1,
      });
    } else {
      sendJson(response, { detail: `unhandled smoke route: ${method} ${url.pathname}` }, 404);
    }
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  return address.port;
}

async function reservePort() {
  const server = createNetServer();
  const port = await listen(server);
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForDashboard(origin, child, output) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    assert(child.exitCode === null, `Next.js exited before startup:\n${output.join("")}`);
    try {
      const response = await fetch(`${origin}/login`);
      if (response.ok) return;
    } catch {
      // The production server has not bound its socket yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Next.js did not become ready:\n${output.join("")}`);
}

async function fetchPage(origin, path, cookie, expectedText) {
  const response = await fetch(`${origin}${path}`, {
    headers: cookie ? { Cookie: cookie } : undefined,
    redirect: "manual",
  });
  assert.equal(response.status, 200, `${path} returned ${response.status}`);
  const body = await response.text();
  assert(body.includes(expectedText), `${path} did not render ${JSON.stringify(expectedText)}`);
  assert(!body.includes(smokeToken), `${path} exposed the one-time plaintext token`);
}

const mockApi = createMockApi();
const apiPort = await listen(mockApi);
const dashboardPort = await reservePort();
const dashboardOrigin = `http://localhost:${dashboardPort}`;
const output = [];
const next = spawn(process.execPath, [nextBin, "start", "-H", "localhost", "-p", String(dashboardPort)], {
  cwd: dashboardRoot,
  env: {
    ...process.env,
    NEXT_TELEMETRY_DISABLED: "1",
    NODE_ENV: "production",
    NODELINK_API_BASE_URL: `http://127.0.0.1:${apiPort}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

for (const stream of [next.stdout, next.stderr]) {
  stream.on("data", (chunk) => {
    if (output.join("").length < 20_000) output.push(chunk.toString());
  });
}

try {
  await waitForDashboard(dashboardOrigin, next, output);

  const anonymous = await fetch(`${dashboardOrigin}/enrollment`, { redirect: "manual" });
  if ([303, 307, 308].includes(anonymous.status)) {
    assert.equal(new URL(anonymous.headers.get("location"), dashboardOrigin).pathname, "/login");
  } else {
    const anonymousBody = await anonymous.text();
    assert.equal(anonymous.status, 200);
    assert(
      anonymousBody.includes("/login") && !anonymousBody.includes("Active enrollment tokens"),
      "Anonymous enrollment response neither redirected nor rendered Next.js login navigation",
    );
  }

  const anonymousMutation = await fetch(`${dashboardOrigin}/api/enrollment-tokens`, {
    body: "{}",
    headers: { "Content-Type": "application/json", Origin: dashboardOrigin },
    method: "POST",
  });
  assert.equal(anonymousMutation.status, 401);

  const login = await fetch(`${dashboardOrigin}/api/auth/login`, {
    body: JSON.stringify({ email: operator.email, password: "placeholder-not-a-secret" }),
    headers: { "Content-Type": "application/json", Origin: dashboardOrigin },
    method: "POST",
  });
  assert.equal(login.status, 200);
  const setCookie = login.headers.getSetCookie?.()[0] ?? login.headers.get("set-cookie");
  assert(setCookie, "Login did not issue a session cookie");
  assert(setCookie.includes("HttpOnly") && setCookie.includes("Secure"));
  const cookie = setCookie.split(";", 1)[0];

  await fetchPage(dashboardOrigin, "/enrollment", cookie, "Agent enrollment");
  await fetchPage(dashboardOrigin, "/enrollment/tokens", cookie, "Enrollment tokens");
  await fetchPage(dashboardOrigin, "/enrollment/tokens/new", cookie, "Create enrollment token");
  await fetchPage(dashboardOrigin, "/enrollment/agents", cookie, "Agent inventory");
  await fetchPage(dashboardOrigin, `/enrollment/agents/${agent.id}`, cookie, agent.name);
  await fetchPage(dashboardOrigin, "/enrollment/audit", cookie, "Audit log");

  const csrfFailure = await fetch(`${dashboardOrigin}/api/enrollment-tokens`, {
    body: "{}",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    method: "POST",
  });
  assert.equal(csrfFailure.status, 403);

  const create = await fetch(`${dashboardOrigin}/api/enrollment-tokens`, {
    body: JSON.stringify({
      name: tokenMetadata.name,
      site_id: tokenMetadata.site_id,
      expires_at: tokenMetadata.expires_at,
      max_uses: 1,
    }),
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie,
      Origin: dashboardOrigin,
    },
    method: "POST",
  });
  assert.equal(create.status, 201);
  assert.equal((await create.json()).token, smokeToken);

  for (const path of [
    `/api/enrollment-tokens/${tokenMetadata.id}/revoke`,
    `/api/enrollment-agents/${agent.id}/revoke`,
  ]) {
    const response = await fetch(`${dashboardOrigin}${path}`, {
      body: JSON.stringify({ reason: "production smoke" }),
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
        Origin: dashboardOrigin,
      },
      method: "POST",
    });
    assert.equal(response.status, 200, `${path} returned ${response.status}`);
  }

  await fetchPage(dashboardOrigin, "/enrollment/tokens", cookie, "enr_…moke");
  console.log("Production smoke passed: auth, enrollment pages, create/revoke routes, and token non-disclosure.");
} finally {
  const nextExit = once(next, "exit");
  next.kill();
  await Promise.race([
    nextExit,
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  await new Promise((resolve) => mockApi.close(resolve));
}
