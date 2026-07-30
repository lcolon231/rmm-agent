// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pure presentation logic for the audit timeline and verification views.
 *
 * Nothing here fetches: the module turns URL search parameters into a bounded
 * server query and turns API responses into the states the pages render. The
 * split keeps the integrity reasoning — which failures are prominent, which
 * "unknown" states must never be shown as healthy — testable without a server.
 */

export const AUDIT_PAGE_SIZE = 50;

/** Widest window the timeline will request in one page of filters. */
const MAX_FILTER_LENGTH = 255;

export type AuditEventRecord = {
  id: string;
  seq: number | null;
  ts: string;
  actor: string;
  actor_user_id: string | null;
  action: string;
  agent_id: string | null;
  enrollment_token_id: string | null;
  organization_id: string | null;
  source_ip: string | null;
  detail: Record<string, unknown>;
};

export type AuditChainVerification = {
  intact: boolean;
  first_broken_event_id: string | null;
};

export type AuditAnchorRecord = {
  id: string;
  created_at: string;
  event_count: number;
  last_event_id: string;
  merkle_root: string;
};

export type AuditAnchorVerification = {
  anchor_id: string;
  intact: boolean;
  reason: string | null;
};

export type AuditPublicationStatus = {
  backend: string | null;
  total_anchors: number;
  published: number;
  pending: number;
  oldest_unpublished_age_seconds: number | null;
  lag_alert: boolean;
  last_error: string | null;
};

export type AuditAnchorPublication = {
  backend: string;
  status: string;
  uri: string | null;
  receipt: Record<string, unknown> | null;
  receipt_sha256: string | null;
  receipt_intact: boolean;
  receipt_reason: string | null;
  attempts: number;
  last_error: string | null;
  published_at: string | null;
};

export type AuditQuery = {
  actor?: string;
  agentId?: string;
  /**
   * Sequence ceiling pinning this query to one snapshot of the chain.
   *
   * The chain only appends, and reading the timeline appends to it, so paging
   * without a ceiling would shift rows onto later pages and show one twice.
   * The first page leaves this unset and adopts the ceiling the server returns.
   */
  beforeSeq?: number;
  dateFrom?: string;
  dateTo?: string;
  eventType?: string;
  organizationId?: string;
  page: number;
};

export type AuditTimelineTone = "verified" | "failed" | "unknown";

export type AuditStatement = {
  detail: string;
  headline: string;
  tone: AuditTimelineTone;
};

function trimmed(value: string | undefined, maxLength = MAX_FILTER_LENGTH): string | undefined {
  const candidate = value?.trim();
  if (!candidate || candidate.length > maxLength) return undefined;
  return candidate;
}

function isoDate(value: string | undefined): string | undefined {
  const candidate = trimmed(value, 10);
  if (!candidate || !/^\d{4}-\d{2}-\d{2}$/.test(candidate)) return undefined;
  const parsed = new Date(`${candidate}T00:00:00Z`);
  return Number.isNaN(parsed.getTime()) ? undefined : candidate;
}

/**
 * Validate raw search parameters into a query the API will accept.
 *
 * Unrecognized event types are dropped rather than forwarded: the server
 * matches `action` exactly, so a typo would otherwise render an empty timeline
 * that looks indistinguishable from "nothing ever happened".
 */
export function parseAuditQuery(
  params: Record<string, string | undefined>,
  knownEventTypes: readonly string[],
): AuditQuery {
  const page = /^\d+$/.test(params.page ?? "") ? Math.max(1, Number(params.page)) : 1;
  const eventType = trimmed(params.event, 100);
  const beforeSeq = /^\d+$/.test(params.before ?? "") ? Number(params.before) : undefined;
  return {
    actor: trimmed(params.actor),
    agentId: trimmed(params.agent, 36),
    beforeSeq: beforeSeq && beforeSeq >= 1 ? beforeSeq : undefined,
    dateFrom: isoDate(params.from),
    dateTo: isoDate(params.to),
    eventType: eventType && knownEventTypes.includes(eventType) ? eventType : undefined,
    organizationId: trimmed(params.organization, 36),
    page,
  };
}

/** Serialize a query back into the page's own URL search string. */
export function auditQueryToSearchParams(query: AuditQuery): URLSearchParams {
  const params = new URLSearchParams();
  if (query.eventType) params.set("event", query.eventType);
  if (query.actor) params.set("actor", query.actor);
  if (query.agentId) params.set("agent", query.agentId);
  if (query.organizationId) params.set("organization", query.organizationId);
  if (query.dateFrom) params.set("from", query.dateFrom);
  if (query.dateTo) params.set("to", query.dateTo);
  // The ceiling only matters once the reader leaves page 1; carrying it on the
  // first page would pin them to a snapshot they never asked for.
  if (query.page > 1 && query.beforeSeq) params.set("before", String(query.beforeSeq));
  if (query.page > 1) params.set("page", String(query.page));
  return params;
}

/**
 * Link to another page of the same snapshot.
 *
 * `snapshotSeq` is the ceiling the server reported for the page being viewed;
 * it is adopted when the query does not already carry one, which is how page 1
 * hands its snapshot to page 2.
 */
export function auditPageHref(query: AuditQuery, page: number, snapshotSeq?: number | null): string {
  const params = auditQueryToSearchParams({
    ...query,
    beforeSeq: query.beforeSeq ?? snapshotSeq ?? undefined,
    page,
  });
  const search = params.toString();
  return search ? `/audit?${search}` : "/audit";
}

export function hasAuditFilters(query: AuditQuery): boolean {
  return Boolean(
    query.actor || query.agentId || query.dateFrom || query.dateTo || query.eventType || query.organizationId,
  );
}

export function auditPageCount(total: number, pageSize = AUDIT_PAGE_SIZE): number {
  if (total <= 0) return 1;
  return Math.ceil(total / pageSize);
}

export function hasNextAuditPage(page: number, total: number, pageSize = AUDIT_PAGE_SIZE): boolean {
  return page * pageSize < total;
}

/**
 * The chain-verification banner.
 *
 * A verification that could not be performed is reported as `unknown`, never as
 * verified — an operator must not read "no problem found" from "not checked".
 */
export function describeChainIntegrity(
  verification: AuditChainVerification | null,
): AuditStatement {
  if (verification === null) {
    return {
      tone: "unknown",
      headline: "Chain verification unavailable",
      detail:
        "The audit chain could not be verified in this request. Treat the timeline as unverified until a check succeeds.",
    };
  }
  if (!verification.intact) {
    return {
      tone: "failed",
      headline: "Audit chain verification FAILED",
      detail: verification.first_broken_event_id
        ? `The chain first breaks at event ${verification.first_broken_event_id}. Events at or after that sequence cannot be trusted; preserve the database and investigate before taking further action.`
        : "The chain does not verify. Preserve the database and investigate before taking further action.",
    };
  }
  return {
    tone: "verified",
    headline: "Audit chain verified",
    detail:
      "Every recorded event links to its predecessor by hash and sequence number. Local verification cannot detect a rewrite of the entire chain — external anchors cover that.",
  };
}

/**
 * The external-publication banner.
 *
 * Publication being disabled is a real posture, not an error: it is reported as
 * `unknown` because an unpublished anchor gives no protection against an
 * attacker who controls the database.
 */
export function describePublication(
  status: AuditPublicationStatus | null,
): AuditStatement {
  if (status === null) {
    return {
      tone: "unknown",
      headline: "Publication status unavailable",
      detail: "External anchor publication could not be queried in this request.",
    };
  }
  if (status.backend === null) {
    return {
      tone: "unknown",
      headline: "External publication disabled",
      detail:
        status.total_anchors === 0
          ? "No external destination is configured and no anchor has been created, so nothing constrains a rewrite by anyone who controls this database."
          : `No external destination is configured, so all ${status.total_anchors} anchor${status.total_anchors === 1 ? "" : "s"} exist only in this database. History can be rewritten by anyone who controls it.`,
    };
  }
  if (status.total_anchors === 0) {
    return {
      tone: "unknown",
      headline: "No anchors to publish yet",
      detail: `${status.backend} is configured, but no anchor has been created, so no external copy of the chain exists.`,
    };
  }
  if (status.lag_alert) {
    return {
      tone: "failed",
      headline: "External publication is lagging",
      detail: `${status.pending} anchor${status.pending === 1 ? "" : "s"} pending publication to ${status.backend}${status.oldest_unpublished_age_seconds === null ? "" : `, oldest ${formatAuditDuration(status.oldest_unpublished_age_seconds)} old`}. Events inside that window have no external copy yet.${status.last_error ? ` Last error: ${status.last_error}` : ""}`,
    };
  }
  return {
    tone: "verified",
    headline: "Anchors published externally",
    detail: `${status.published} of ${status.total_anchors} anchor${status.total_anchors === 1 ? "" : "s"} published to ${status.backend}${status.pending > 0 ? `, ${status.pending} pending` : ""}.`,
  };
}

export function describeAnchorVerification(
  verification: AuditAnchorVerification | null,
): AuditStatement {
  if (verification === null) {
    return {
      tone: "unknown",
      headline: "Not verified",
      detail: "This anchor could not be verified in this request.",
    };
  }
  if (!verification.intact) {
    return {
      tone: "failed",
      headline: "Anchor FAILED verification",
      detail: verification.reason ?? "The recomputed Merkle root does not match the stored anchor.",
    };
  }
  return {
    tone: "verified",
    headline: "Anchor verified",
    detail: "The recomputed Merkle root over the covered events matches the stored anchor.",
  };
}

export function describeReceipt(publication: AuditAnchorPublication): AuditStatement {
  if (!publication.receipt_intact) {
    return {
      tone: "failed",
      headline: "Receipt digest mismatch",
      detail:
        publication.receipt_reason ??
        "The stored receipt does not match its recorded digest, so the receipt row itself was altered.",
    };
  }
  if (publication.status !== "published") {
    return {
      tone: "unknown",
      headline: `Publication ${publication.status}`,
      detail: publication.last_error
        ? `${publication.attempts} attempt${publication.attempts === 1 ? "" : "s"}. Last error: ${publication.last_error}`
        : `${publication.attempts} attempt${publication.attempts === 1 ? "" : "s"} so far, with no external receipt yet.`,
    };
  }
  return {
    tone: "verified",
    headline: "Receipt verified",
    detail: `Published to ${publication.backend}${publication.uri ? ` at ${publication.uri}` : ""}.`,
  };
}

/**
 * True when anything on the page must be surfaced as an integrity failure.
 * Callers use this to decide whether the page leads with an alert.
 */
export function hasIntegrityFailure(...statements: AuditStatement[]): boolean {
  return statements.some((statement) => statement.tone === "failed");
}

export function formatAuditTimestamp(value: string | null, fallback = "Not recorded"): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    month: "short",
    second: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
    year: "numeric",
  }).format(date);
}

export function formatAuditDuration(seconds: number): string {
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

/** Human label for a dotted action name, e.g. `agent.revoked` -> `agent revoked`. */
export function formatAuditAction(action: string): string {
  return action.replaceAll(".", " ").replaceAll("_", " ");
}

/** The sequence number, or an explicit marker for pre-sequence legacy rows. */
export function formatAuditSequence(seq: number | null): string {
  return seq === null ? "legacy" : String(seq);
}

/**
 * Flatten one event's sanitized detail into ordered rows for display.
 *
 * The server already applied the redaction policy before hashing, so these
 * values are the same ones chain and anchor verification cover. Values are
 * stringified here only for rendering.
 */
export function auditDetailRows(detail: Record<string, unknown>): { key: string; value: string }[] {
  return Object.keys(detail)
    .sort()
    .map((key) => {
      const value = detail[key];
      if (value === null) return { key, value: "null" };
      if (Array.isArray(value)) return { key, value: value.length === 0 ? "(empty)" : value.map(String).join(", ") };
      if (typeof value === "object") return { key, value: JSON.stringify(value) };
      return { key, value: String(value) };
    });
}
