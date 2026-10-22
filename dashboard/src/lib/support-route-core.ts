// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for the technician side of NodeLink Support (issue #280).
 *
 * Every operator route in `server/app/api/support_chat.py` requires the
 * operator role, so readonly sessions are refused here before any token is
 * forwarded — except the unread badge, which every signed-in operator polls
 * and which simply reads zero for a role that cannot see conversations.
 */

import {
  authorizeSession,
  isRecord,
  isSameOriginRequest,
  json,
  readJsonBody,
  upstreamError,
  type GetSession,
} from "./bff-route-core.ts";
import {
  operatorConversationsFromUnknown,
  operatorTranscriptFromUnknown,
  transcriptMessageFromUnknown,
} from "./support-chat-core.ts";

const SIGNED_OUT = "Sign in to use NodeLink Support.";
const FORBIDDEN = "Your role cannot use NodeLink Support.";
const MAX_REPLY_BYTES = 4096;

function requireOperator(getSession: GetSession) {
  return authorizeSession(getSession, { minRole: "operator", signedOut: SIGNED_OUT, forbidden: FORBIDDEN });
}

export async function handleListConversations(
  _request: Request,
  deps: { getSession: GetSession; getSupportConversations: (sessionToken: string) => Promise<unknown> },
): Promise<Response> {
  const auth = await requireOperator(deps.getSession);
  if (auth instanceof Response) return auth;
  try {
    // The lib returns the parsed array; re-wrap so the allowlist runs here too.
    const conversations = operatorConversationsFromUnknown({
      conversations: await deps.getSupportConversations(auth.sessionToken),
    });
    return conversations
      ? json({ conversations })
      : json({ error: "Support chat is temporarily unavailable." }, 502);
  } catch {
    return json({ error: "Support chat is temporarily unavailable." }, 502);
  }
}

export async function handleUnreadCount(
  _request: Request,
  deps: { getSession: GetSession; getSupportUnreadCount: (sessionToken: string) => Promise<unknown> },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: SIGNED_OUT,
    forbidden: FORBIDDEN,
  });
  if (auth instanceof Response) return auth;
  if (auth.role === "readonly") return json({ unread: 0 });
  try {
    const unread = await deps.getSupportUnreadCount(auth.sessionToken);
    return json({ unread: Number.isSafeInteger(unread) && Number(unread) >= 0 ? Number(unread) : 0 });
  } catch {
    // A badge must never break the shell; a failed poll reads as "nothing new".
    return json({ unread: 0 });
  }
}

export async function handleGetTranscript(
  _request: Request,
  conversationId: string,
  deps: {
    getSession: GetSession;
    getSupportTranscript: (sessionToken: string, conversationId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await requireOperator(deps.getSession);
  if (auth instanceof Response) return auth;
  try {
    const transcript = operatorTranscriptFromUnknown(
      await deps.getSupportTranscript(auth.sessionToken, conversationId),
    );
    return transcript ? json(transcript) : json({ error: "Conversation is unavailable." }, 502);
  } catch {
    return json({ error: "Conversation is unavailable." }, 502);
  }
}

export function supportReplyFromUnknown(value: unknown): string | null {
  if (!isRecord(value)) return null;
  const text = value.body;
  if (typeof text !== "string" || text.trim() === "") return null;
  return new TextEncoder().encode(text).length <= MAX_REPLY_BYTES ? text : null;
}

export async function handlePostReply(
  request: Request,
  conversationId: string,
  deps: {
    getSession: GetSession;
    postSupportReply: (sessionToken: string, conversationId: string, body: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Request origin refused." }, 403);
  const auth = await requireOperator(deps.getSession);
  if (auth instanceof Response) return auth;
  const body = await readJsonBody(request);
  if (body === undefined) return json({ error: "Invalid request." }, 400);
  const text = supportReplyFromUnknown(body);
  if (text === null) return json({ error: "Message must be between 1 and 4096 bytes." }, 400);
  try {
    const message = transcriptMessageFromUnknown(
      await deps.postSupportReply(auth.sessionToken, conversationId, text),
    );
    return message ? json(message) : json({ error: "Reply could not be delivered." }, 502);
  } catch {
    return json({ error: "Reply could not be delivered." }, 502);
  }
}

export async function handleCloseConversation(
  request: Request,
  conversationId: string,
  deps: {
    getSession: GetSession;
    closeSupportConversation: (sessionToken: string, conversationId: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Request origin refused." }, 403);
  const auth = await requireOperator(deps.getSession);
  if (auth instanceof Response) return auth;
  try {
    await deps.closeSupportConversation(auth.sessionToken, conversationId);
    return json({ status: "closed" });
  } catch {
    return json({ error: "Could not close the conversation." }, 502);
  }
}

export function supportStartErrorMessage(code: string | null, status: number): string {
  if (code === "support_chat_unsupported") return "This endpoint must be updated before a technician can start support chat.";
  if (code === "support_chat_agent_untrusted") return "Support chat is unavailable while this endpoint is not trusted.";
  if (code === "support_chat_not_configured") return "Support chat is not configured on the server.";
  if (status === 404) return "The endpoint was not found or is outside your client access.";
  if (status === 403) return "Your role cannot start support chat for this endpoint.";
  return "NodeLink Support could not be started. Try again.";
}

export async function handleStartConversation(
  request: Request,
  endpointId: string,
  deps: {
    getSession: GetSession;
    startSupportConversation: (sessionToken: string, endpointId: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Support chat request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to start support chat.",
    forbidden: "Your role cannot start support chat for this endpoint.",
  });
  if (auth instanceof Response) return auth;
  try {
    const result = await deps.startSupportConversation(auth.sessionToken, endpointId);
    if (!isRecord(result) || typeof result.conversation_id !== "string") {
      return json({ error: "NodeLink Support could not be started. Try again." }, 502);
    }
    return json({ conversation_id: result.conversation_id }, 201);
  } catch (error) {
    const upstream = upstreamError(error);
    if (!upstream) return json({ error: "NodeLink Support could not be started. Try again." }, 502);
    const status = upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502;
    return json({ error: supportStartErrorMessage(upstream.code, upstream.status) }, status);
  }
}
