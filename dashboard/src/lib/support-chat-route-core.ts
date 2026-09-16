// SPDX-License-Identifier: AGPL-3.0-only
import { chatApiPath, chatStateFromUnknown, messageFromUnknown } from "./support-chat-core.ts";

function json(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
}
export async function handleChat(request: Request, parts: string[], baseUrl: string, fetchImpl: typeof fetch = fetch) {
  const url = new URL(request.url);
  const path = chatApiPath(parts, url.search);
  if (!path || !["GET", "POST"].includes(request.method) || (request.method === "GET" && parts[1] !== "messages")) return json({ error: "Invalid chat request." }, 400);
  if (request.method === "POST" && request.headers.get("origin") !== url.origin) return json({ error: "Request origin refused." }, 403);
  const authorization = request.headers.get("authorization") ?? "";
  if (!/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization)) return json({ error: "Open NodeLink Support on your computer to start a session." }, 401);
  let body: string | undefined;
  if (request.method === "POST") {
    if (!request.headers.get("content-type")?.startsWith("application/json")) return json({ error: "Invalid chat request." }, 400);
    // Bound actual streamed bytes, not the caller-controlled Content-Length.
    const reader = request.body?.getReader();
    let length = 0;
    const decoder = new TextDecoder();
    body = "";
    if (reader) {
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          length += chunk.value.length;
          if (length > 32768) { await reader.cancel(); return json({ error: "Message is too large." }, 400); }
          body += decoder.decode(chunk.value, { stream: true });
        }
        body += decoder.decode();
      } finally { reader.releaseLock(); }
    }
    try { JSON.parse(body); } catch { return json({ error: "Invalid chat request." }, 400); }
  }
  try {
    const upstream = await fetchImpl(new URL(path, baseUrl), { method: request.method, body, cache: "no-store", redirect: "error",
      headers: { Authorization: authorization, "Content-Type": "application/json" }, signal: AbortSignal.timeout(15000) });
    const raw: unknown = await upstream.json();
    if (!upstream.ok) {
      const detail = raw && typeof raw === "object" ? (raw as { detail?: { code?: unknown } }).detail : undefined;
      const code = typeof detail?.code === "string" && /^support_chat_[a-z_]+$/.test(detail.code) ? detail.code : "support_chat_unavailable";
      const status = [400, 401, 403, 409, 422, 429].includes(upstream.status) ? upstream.status : 503;
      return json({ error: status === 429 ? "Too many requests. Please wait a minute." : "Chat request could not be completed.", code }, status);
    }
    if (request.method === "GET") {
      const state = chatStateFromUnknown(raw);
      return state ? json(state) : json({ error: "Chat is temporarily unavailable." }, 502);
    }
    if (parts[1] === "messages") {
      const message = messageFromUnknown(raw);
      return message ? json(message) : json({ error: "Message delivery could not be confirmed." }, 502);
    }
    if (parts[1] === "notice") return json({ notice_acknowledged: true });
    const rotated = raw as { token?: unknown; token_expires_at?: unknown } | null;
    if (!rotated || typeof rotated.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(rotated.token) || typeof rotated.token_expires_at !== "string" || !Number.isFinite(Date.parse(rotated.token_expires_at))) return json({ error: "Session renewal failed." }, 502);
    return json({ token: rotated.token, token_expires_at: rotated.token_expires_at });
  } catch { return json({ error: "Chat is temporarily unavailable. Try again shortly." }, 503); }
}
