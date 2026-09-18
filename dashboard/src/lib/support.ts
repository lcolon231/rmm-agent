// SPDX-License-Identifier: AGPL-3.0-only
import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  operatorConversationsFromUnknown,
  operatorTranscriptFromUnknown,
  type OperatorConversation,
  type OperatorTranscript,
  type TranscriptMessage,
} from "@/lib/support-chat-core";

export async function getSupportConversations(sessionToken: string): Promise<OperatorConversation[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/support/conversations", { method: "GET", sessionToken });
  const conversations = operatorConversationsFromUnknown(value);
  if (!conversations) throw new Error("The management service returned invalid support conversations.");
  return conversations;
}

export async function getSupportUnreadCount(sessionToken: string): Promise<number> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/support/unread-count", { method: "GET", sessionToken });
  const record = value as { unread?: unknown } | null;
  return record && Number.isInteger(record.unread) && Number(record.unread) >= 0 ? Number(record.unread) : 0;
}

export async function getSupportTranscript(sessionToken: string, conversationId: string): Promise<OperatorTranscript> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/support/conversations/${encodeURIComponent(conversationId)}`,
    { method: "GET", sessionToken },
  );
  const transcript = operatorTranscriptFromUnknown(value);
  if (!transcript) throw new Error("The management service returned an invalid support transcript.");
  return transcript;
}

export async function postSupportReply(sessionToken: string, conversationId: string, body: string): Promise<TranscriptMessage> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/support/conversations/${encodeURIComponent(conversationId)}/messages`,
    { method: "POST", sessionToken, body: JSON.stringify({ body }), headers: { "Content-Type": "application/json" } },
  );
  // The reply route returns {seq, sender, body, created_at}; the technician's own
  // identity is implicit, so coerce it into a TranscriptMessage for an echo.
  const record = value as Record<string, unknown> | null;
  if (!record || typeof record.seq !== "number") throw new Error("The management service did not confirm the reply.");
  return {
    seq: Number(record.seq),
    sender: "technician",
    operator_email: null,
    body: typeof record.body === "string" ? record.body : body,
    created_at: typeof record.created_at === "string" ? record.created_at : new Date().toISOString(),
  };
}

export async function closeSupportConversation(sessionToken: string, conversationId: string): Promise<void> {
  await nodelinkApiRequest<unknown>(
    `/api/v1/support/conversations/${encodeURIComponent(conversationId)}/close`,
    { method: "POST", sessionToken, headers: { "Content-Type": "application/json" } },
  );
}
