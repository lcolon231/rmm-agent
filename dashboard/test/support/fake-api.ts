// SPDX-License-Identifier: AGPL-3.0-only
// Replaces the global `fetch` for one test so the server-only API wrappers can
// be exercised end to end against a scripted NodeLink API.
import type { TestContext } from "node:test";

export type RecordedCall = {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
  signal: AbortSignal | null;
};

export function jsonResponse(status: number, body?: unknown): Response {
  return body === undefined
    ? new Response(null, { status })
    : Response.json(body, { status });
}

export function fakeApi(
  t: TestContext,
  respond: (call: RecordedCall) => Response | Promise<Response> = () => jsonResponse(200, {}),
): RecordedCall[] {
  const calls: RecordedCall[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init: RequestInit = {}) => {
    const call: RecordedCall = {
      url: String(input),
      method: init.method ?? "GET",
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? init.body : null,
      signal: init.signal ?? null,
    };
    calls.push(call);
    return respond(call);
  });
  return calls;
}
