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
export function mergeMessages<T extends { seq: number }>(previous: T[], tail: T[]): T[] {
  return [...new Map([...previous, ...tail].map(m => [m.seq, m])).values()].sort((a, b) => a.seq - b.seq);
}

// --- Operator (technician) side (#235) --------------------------------------
export type ChatSender = "end_user" | "technician";
export type OperatorConversation = {
  id: string; agent_id: string; endpoint: string | null; subject: string | null;
  status: "open" | "closed"; opened_by: ChatSender; last_message_at: string | null;
  created_at: string; unread: number;
};
export type TranscriptMessage = { seq: number; sender: ChatSender; operator_email: string | null; body: string; created_at: string };
export type OperatorTranscript = {
  id: string; agent_id: string; endpoint: string | null; subject: string | null;
  status: "open" | "closed"; opened_by: ChatSender; messages: TranscriptMessage[];
};

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function operatorConversationsFromUnknown(value: unknown): OperatorConversation[] | null {
  if (!value || typeof value !== "object") return null;
  const list = (value as Record<string, unknown>).conversations;
  if (!Array.isArray(list)) return null;
  const out: OperatorConversation[] = [];
  for (const item of list) {
    if (!item || typeof item !== "object") return null;
    const r = item as Record<string, unknown>;
    if (!uuid.test(String(r.id ?? "")) || typeof r.agent_id !== "string") return null;
    if (r.status !== "open" && r.status !== "closed") return null;
    if (r.opened_by !== "end_user" && r.opened_by !== "technician") return null;
    if (!Number.isInteger(r.unread) || Number(r.unread) < 0) return null;
    if (typeof r.created_at !== "string") return null;
    out.push({
      id: r.id as string, agent_id: r.agent_id, endpoint: optionalString(r.endpoint),
      subject: optionalString(r.subject), status: r.status, opened_by: r.opened_by,
      last_message_at: optionalString(r.last_message_at), created_at: r.created_at, unread: Number(r.unread),
    });
  }
  return out;
}

export function transcriptMessageFromUnknown(value: unknown): TranscriptMessage | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  if (!Number.isSafeInteger(r.seq) || Number(r.seq) <= 0) return null;
  if (r.sender !== "end_user" && r.sender !== "technician") return null;
  if (typeof r.body !== "string" || typeof r.created_at !== "string") return null;
  return { seq: Number(r.seq), sender: r.sender, operator_email: optionalString(r.operator_email), body: r.body, created_at: r.created_at };
}

export function operatorTranscriptFromUnknown(value: unknown): OperatorTranscript | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  if (!uuid.test(String(r.id ?? "")) || typeof r.agent_id !== "string") return null;
  if (r.status !== "open" && r.status !== "closed") return null;
  if (r.opened_by !== "end_user" && r.opened_by !== "technician") return null;
  if (!Array.isArray(r.messages)) return null;
  const messages = r.messages.map(transcriptMessageFromUnknown);
  if (messages.some(m => m === null)) return null;
  return {
    id: r.id as string, agent_id: r.agent_id, endpoint: optionalString(r.endpoint), subject: optionalString(r.subject),
    status: r.status, opened_by: r.opened_by, messages: messages as TranscriptMessage[],
  };
}

export function totalUnread(conversations: OperatorConversation[]): number {
  return conversations.reduce((sum, c) => sum + (c.unread > 0 ? c.unread : 0), 0);
}

export function formatChatTimestamp(iso: string | null): string {
  if (!iso) return "";
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  return new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
export function chatApiPath(parts: string[], search: string): string | null {
  if (parts.length !== 2 || !uuid.test(parts[0]) || !["messages", "notice", "refresh"].includes(parts[1])) return null;
  const params = new URLSearchParams(search);
  const after = params.get("after");
  if ([...params.keys()].some(k => k !== "after") || (after !== null && (!/^\d{1,10}$/.test(after) || parts[1] !== "messages"))) return null;
  return `/api/v1/support/chat/${parts[0]}/${parts[1]}${after === null ? "" : `?after=${after}`}`;
}
