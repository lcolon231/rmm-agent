// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The integrity summary every dashboard page shows in its sidebar card and
 * record footer.
 *
 * "Intact" is only ever reported from a successful chain verification in
 * this request. A failed or unreachable check reads "unknown", never intact,
 * and a broken chain reads "failed" so the shell can raise it.
 */

import { authorizeSession, isRecord, json, type GetSession } from "./bff-route-core.ts";

export type ChainState = "intact" | "failed" | "unknown";

export type AuditIntegritySummary = {
  chain: ChainState;
  /** ISO time of the newest integrity anchor, if any could be read. */
  last_anchor_at: string | null;
};

export type IntegrityInputs = {
  verification: unknown;
  anchors: unknown;
};

function chainState(verification: unknown): ChainState {
  if (!isRecord(verification) || typeof verification.intact !== "boolean") return "unknown";
  return verification.intact ? "intact" : "failed";
}

function newestAnchor(anchors: unknown): string | null {
  if (!Array.isArray(anchors)) return null;
  let newest: { iso: string; ms: number } | null = null;
  for (const anchor of anchors) {
    if (!isRecord(anchor) || typeof anchor.created_at !== "string") continue;
    const ms = Date.parse(anchor.created_at);
    if (Number.isNaN(ms)) continue;
    if (!newest || ms > newest.ms) newest = { iso: new Date(ms).toISOString(), ms };
  }
  return newest?.iso ?? null;
}

/** Reduce upstream answers to the two facts the shell shows; nothing else passes. */
export function summarizeIntegrity({ verification, anchors }: IntegrityInputs): AuditIntegritySummary {
  return { chain: chainState(verification), last_anchor_at: newestAnchor(anchors) };
}

/** Parse the route's JSON on the client; anything unexpected reads unknown. */
export function integrityFromUnknown(value: unknown): AuditIntegritySummary {
  if (!isRecord(value)) return { chain: "unknown", last_anchor_at: null };
  const chain: ChainState = value.chain === "intact" || value.chain === "failed" ? value.chain : "unknown";
  const anchor = typeof value.last_anchor_at === "string" && !Number.isNaN(Date.parse(value.last_anchor_at)) ? value.last_anchor_at : null;
  return { chain, last_anchor_at: anchor };
}

/** "today, 09:40", "yesterday, 17:05" or "3 Nov 2026, 09:40". */
export function formatAnchorTime(iso: string, now: Date = new Date()): string {
  const at = new Date(iso);
  const time = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" }).format(at);
  const dayKey = (date: Date) => `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (dayKey(at) === dayKey(now)) return `today, ${time}`;
  if (dayKey(at) === dayKey(yesterday)) return `yesterday, ${time}`;
  return `${new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" }).format(at)}, ${time}`;
}

const SIGNED_OUT = "Sign in to view audit integrity.";
const FORBIDDEN = "Your role cannot view audit integrity.";

export async function handleAuditIntegrity(
  _request: Request,
  deps: { getSession: GetSession; getIntegrityInputs: (sessionToken: string) => Promise<IntegrityInputs> },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: SIGNED_OUT,
    forbidden: FORBIDDEN,
  });
  if (auth instanceof Response) return auth;
  try {
    return json(summarizeIntegrity(await deps.getIntegrityInputs(auth.sessionToken)));
  } catch {
    // The shell must never break, and an unreachable check is not "intact".
    return json({ chain: "unknown", last_anchor_at: null } satisfies AuditIntegritySummary);
  }
}
