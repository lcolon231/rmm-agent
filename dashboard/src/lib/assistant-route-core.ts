// SPDX-License-Identifier: AGPL-3.0-only
import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";

type Session = { kind: "anonymous" | "unavailable" } | { kind: "authenticated"; sessionToken: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function assistantPath(parts: string[], method: string, url: URL): string | null {
  const valid = (parts.length === 1 && (
    (parts[0] === "status" && method === "GET") ||
    (parts[0] === "conversations" && ["GET", "POST"].includes(method)))) ||
    (parts[0] === "conversations" && uuid.test(parts[1] ?? "") && (
      (parts.length === 2 && method === "GET") ||
      (parts.length === 3 && parts[2] === "runs" && method === "POST") ||
      (parts.length === 5 && parts[2] === "runs" && uuid.test(parts[3]) && parts[4] === "cancel" && method === "POST")));
  if (!valid) return null;
  let query = "";
  if (method === "GET" && parts.length === 1 && parts[0] === "conversations") {
    const clientId = url.searchParams.get("client_id") ?? "";
    if (!uuid.test(clientId)) return null;
    query = `?client_id=${encodeURIComponent(clientId)}`;
  }
  return `/api/v1/assistant/${parts.join("/")}${query}`;
}

function json(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

export async function handleAssistant(request: Request, parts: string[], deps: {
  getSession: () => Promise<Session>;
  send: (path: string, token: string, method: string, body?: string) => Promise<unknown>;
}): Promise<Response> {
  const path = assistantPath(parts, request.method, new URL(request.url));
  if (!path) return json({ error: "Unknown assistant request." }, 400);
  if (request.method !== "GET" && !isSameOrigin(request.headers.get("origin"), requestOrigin(request.url, request.headers.get("host")))) {
    return json({ error: "The request origin was rejected." }, 403);
  }
  const session = await deps.getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind !== "authenticated") return json({ error: session.kind === "anonymous" ? "Sign in again to continue." : "Session verification is unavailable." }, session.kind === "anonymous" ? 401 : 503);
  let body: string | undefined;
  if (request.method === "POST" && parts.at(-1) !== "cancel") {
    const reader = request.body?.getReader();
    if (!reader) return json({ error: "A message is required." }, 400);
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 20000) {
        await reader.cancel();
        return json({ error: "The message is too large." }, 413);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    body = new TextDecoder().decode(bytes);
    try { JSON.parse(body); } catch { return json({ error: "Invalid assistant request." }, 400); }
  }
  try {
    return json(await deps.send(path, session.sessionToken, request.method, body));
  } catch (error) {
    const status = error && typeof error === "object" && "status" in error ? Number(error.status) : 503;
    const message = status === 401 ? "Your session expired. Sign in again." :
      status === 403 || status === 404 ? "This conversation or client is no longer accessible. Refresh your client selection." :
      status === 409 ? "An investigation is already running. Refresh history or cancel it before retrying." :
      status === 429 ? "The assistant usage or history limit has been reached. Try later or use an existing conversation." :
      status === 422 || status === 413 ? "The request was rejected. Messages must contain 1–4,000 characters." :
      "The assistant is unavailable. Refresh history before retrying; an interrupted request may still finish.";
    return json({ error: message }, [401, 403, 404, 409, 413, 422, 429].includes(status) ? status : 503);
  }
}
