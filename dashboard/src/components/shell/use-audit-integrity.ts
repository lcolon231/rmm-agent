// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { useEffect, useState } from "react";

import { integrityFromUnknown, type AuditIntegritySummary } from "@/lib/audit-integrity-core";

export type IntegrityView = AuditIntegritySummary | { chain: "checking"; last_anchor_at: null };

const CACHE_KEY = "nodelink.audit-integrity";
export const INTEGRITY_CACHE_MS = 60_000;

/**
 * Only an intact result is reused, and only for a minute in this tab. A
 * failed or unknown result is re-checked on every page, so a broken chain is
 * never hidden behind an older "intact".
 */
function readCache(now: number): AuditIntegritySummary | null {
  try {
    const raw = window.sessionStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { at?: unknown; summary?: unknown };
    if (typeof parsed.at !== "number" || now - parsed.at < 0 || now - parsed.at >= INTEGRITY_CACHE_MS) return null;
    const summary = integrityFromUnknown(parsed.summary);
    return summary.chain === "intact" ? summary : null;
  } catch {
    return null;
  }
}

function writeCache(summary: AuditIntegritySummary, now: number) {
  try {
    if (summary.chain === "intact") window.sessionStorage.setItem(CACHE_KEY, JSON.stringify({ at: now, summary }));
    else window.sessionStorage.removeItem(CACHE_KEY);
  } catch {
    /* storage blocked: every page simply re-checks */
  }
}

export function useAuditIntegrity(): IntegrityView {
  const [view, setView] = useState<IntegrityView>({ chain: "checking", last_anchor_at: null });

  useEffect(() => {
    let cancelled = false;
    const cached = readCache(Date.now());
    if (cached) {
      // Deferred so the first paint matches the server render ("checking").
      queueMicrotask(() => {
        if (!cancelled) setView(cached);
      });
      return () => {
        cancelled = true;
      };
    }
    (async () => {
      let summary: AuditIntegritySummary;
      try {
        const response = await fetch("/api/audit/integrity", { cache: "no-store" });
        summary = response.ok ? integrityFromUnknown(await response.json()) : { chain: "unknown", last_anchor_at: null };
      } catch {
        summary = { chain: "unknown", last_anchor_at: null };
      }
      writeCache(summary, Date.now());
      if (!cancelled) setView(summary);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return view;
}
