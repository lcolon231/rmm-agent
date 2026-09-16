// SPDX-License-Identifier: AGPL-3.0-only
export type ChatMessage = { seq: number; sender: "end_user" | "technician"; body: string; created_at: string };
export type ChatState = { status: "open" | "closed"; notice_version: string; notice_acknowledged: boolean; retention_days: number; token_expires_at: string; messages: ChatMessage[] };
export type ChatAccess = { conversation: string; token: string; expires: number };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function readChatAccess(fragment: string): ChatAccess | null {
  const params = new URLSearchParams(fragment.replace(/^#/, ""));
  const conversation = params.get("c") ?? "";
  const token = params.get("t") ?? "";
  const expires = Date.parse(params.get("expires") ?? "");
  return uuid.test(conversation) && /^[A-Za-z0-9_-]{43}$/.test(token) && Number.isFinite(expires) ? { conversation, token, expires } : null;
}
export function messageFromUnknown(value: unknown): ChatMessage | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  return Number.isSafeInteger(r.seq) && Number(r.seq) > 0 && (r.sender === "end_user" || r.sender === "technician") &&
    typeof r.body === "string" && new TextEncoder().encode(r.body).length <= 4096 &&
    typeof r.created_at === "string" && Number.isFinite(Date.parse(r.created_at))
    ? { seq: Number(r.seq), sender: r.sender, body: r.body, created_at: r.created_at } : null;
}
export function chatStateFromUnknown(value: unknown): ChatState | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  if ((r.status !== "open" && r.status !== "closed") || typeof r.notice_version !== "string" || typeof r.notice_acknowledged !== "boolean" ||
    !Number.isInteger(r.retention_days) || Number(r.retention_days) < 0 || typeof r.token_expires_at !== "string" || !Number.isFinite(Date.parse(r.token_expires_at)) ||
    !Array.isArray(r.messages) || r.messages.length > 500) return null;
  const messages = r.messages.map(messageFromUnknown);
  if (messages.some(m => m === null)) return null;
  return { status: r.status, notice_version: r.notice_version, notice_acknowledged: r.notice_acknowledged, retention_days: Number(r.retention_days), token_expires_at: r.token_expires_at, messages: messages as ChatMessage[] };
}
export function mergeMessages(previous: ChatMessage[], tail: ChatMessage[]): ChatMessage[] {
  return [...new Map([...previous, ...tail].map(m => [m.seq, m])).values()].sort((a, b) => a.seq - b.seq);
}
export function chatApiPath(parts: string[], search: string): string | null {
  if (parts.length !== 2 || !uuid.test(parts[0]) || !["messages", "notice", "refresh"].includes(parts[1])) return null;
  const params = new URLSearchParams(search);
  const after = params.get("after");
  if ([...params.keys()].some(k => k !== "after") || (after !== null && (!/^\d{1,10}$/.test(after) || parts[1] !== "messages"))) return null;
  return `/api/v1/support/chat/${parts[0]}/${parts[1]}${after === null ? "" : `?after=${after}`}`;
}
