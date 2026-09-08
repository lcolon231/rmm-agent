// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pure logic for the session inventory and break-glass surfaces (issue #69).
 *
 * No `next/headers`, no `fetch`, no DOM, so all of it is unit-testable under
 * `node --test`. The server remains the authority on every decision here: this
 * file formats what the server said and validates what the browser is about to
 * send, and never decides whether a session is valid or an activation was
 * legitimate.
 */

export type SessionRecord = {
  id: string;
  created_at: string;
  last_seen_at: string;
  absolute_expires_at: string;
  auth_methods: string;
  source_ip: string | null;
  user_agent: string | null;
  is_break_glass: boolean;
  ended_at: string | null;
  end_reason: string | null;
  is_current: boolean;
};

export type BreakGlassAccountRecord = {
  id: string;
  label: string;
  credential_fingerprint: string;
  created_at: string;
  created_by_email: string | null;
  rotated_at: string | null;
  last_activated_at: string | null;
  activation_count: number;
  disabled_at: string | null;
  disabled_reason: string | null;
};

export type BreakGlassActivationRecord = {
  id: string;
  account_id: string;
  session_id: string | null;
  activated_at: string;
  source_ip: string | null;
  user_agent: string | null;
  reason: string;
  reviewed_at: string | null;
  reviewed_by_email: string | null;
  review_note: string | null;
};

export type BreakGlassStatus = {
  enabled: boolean;
  account_count: number;
  unreviewed_activations: number;
};

export type AdminSessionErrorCode =
  | "invalid-request"
  | "request-rejected"
  | "step-up-required"
  | "break-glass-disabled"
  | "break-glass-cannot-provision"
  | "session-not-managed"
  | "already-reviewed"
  | "not-found"
  | "rate-limited"
  | "unavailable";

const messages: Record<AdminSessionErrorCode, string> = {
  "invalid-request": "That request could not be read. Check the fields and try again.",
  "request-rejected": "The request was rejected.",
  "step-up-required": "Re-authenticate with your security key to continue.",
  "break-glass-disabled": "Break-glass access is turned off for this deployment.",
  "break-glass-cannot-provision":
    "An emergency session cannot create or rotate break-glass credentials. Restore normal administrative access first.",
  "session-not-managed":
    "This session predates session tracking. Sign in again to manage it.",
  "already-reviewed": "That activation has already been reviewed.",
  "not-found": "That record no longer exists.",
  "rate-limited": "Too many attempts. Wait a moment and try again.",
  unavailable: "The request could not be completed. Try again later.",
};

export function adminSessionErrorMessage(value: unknown): string | undefined {
  if (typeof value !== "string" || !(value in messages)) return undefined;
  return messages[value as AdminSessionErrorCode];
}

export function adminSessionErrorCode(
  status: number,
  code?: string | null,
): AdminSessionErrorCode {
  switch (code) {
    case "step_up_required":
    case "mfa_verification_required":
      return "step-up-required";
    case "break_glass_disabled":
    case "break_glass_not_configured":
      return "break-glass-disabled";
    case "break_glass_cannot_provision":
      return "break-glass-cannot-provision";
    case "session_not_managed":
      return "session-not-managed";
    case "activation_already_reviewed":
      return "already-reviewed";
    default:
      break;
  }
  if (status === 404) return "not-found";
  if (status === 429) return "rate-limited";
  if (status === 400 || status === 422) return "invalid-request";
  if (status === 401 || status === 403) return "request-rejected";
  return "unavailable";
}

// --------------------------------------------------------------------------- //
// Presentation
// --------------------------------------------------------------------------- //
/**
 * Turn the stored `amr` string into something a person can act on.
 *
 * "pwd" alone is worth calling out: it means the session never presented a
 * second factor, which is exactly what someone auditing their own devices
 * wants to notice.
 */
export function describeAuthMethods(authMethods: string): string {
  const parts = authMethods.split(",").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0) return "Unknown";
  const labels: Record<string, string> = {
    pwd: "Password",
    webauthn: "Security key",
    recovery_code: "Recovery code",
    break_glass: "Break-glass",
  };
  return parts.map((part) => labels[part] ?? part).join(" + ");
}

export function sessionIsPasswordOnly(session: SessionRecord): boolean {
  const parts = session.auth_methods.split(",").map((part) => part.trim()).filter(Boolean);
  return parts.length > 0 && parts.every((part) => part === "pwd");
}

const endReasonLabels: Record<string, string> = {
  revoked_by_self: "Signed out by you",
  revoked_by_admin: "Ended by an administrator",
  idle_timeout: "Timed out after inactivity",
  absolute_timeout: "Reached its maximum lifetime",
  superseded: "Replaced by a newer sign-in",
  operator_disabled: "Account disabled",
};

export function describeEndReason(reason: string | null): string | undefined {
  if (!reason) return undefined;
  return endReasonLabels[reason] ?? reason;
}

/**
 * A short, non-identifying description of the client.
 *
 * Deliberately coarse. The full user-agent is attacker-influenced text, so it
 * is rendered as a recognisable label rather than injected verbatim into a
 * sentence, and the raw value stays available in the detail line.
 */
export function describeClient(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  const ua = userAgent.toLowerCase();
  const os = ua.includes("windows")
    ? "Windows"
    : ua.includes("mac os") || ua.includes("macintosh")
      ? "macOS"
      : ua.includes("android")
        ? "Android"
        : ua.includes("iphone") || ua.includes("ipad")
          ? "iOS"
          : ua.includes("linux")
            ? "Linux"
            : "Unknown OS";
  const browser = ua.includes("edg/")
    ? "Edge"
    : ua.includes("chrome/") && !ua.includes("chromium")
      ? "Chrome"
      : ua.includes("firefox/")
        ? "Firefox"
        : ua.includes("safari/") && !ua.includes("chrome")
          ? "Safari"
          : "Unknown browser";
  return `${browser} on ${os}`;
}

/** Sort so the current session leads, then most-recently-seen. */
export function orderSessions(sessions: SessionRecord[]): SessionRecord[] {
  return [...sessions].sort((a, b) => {
    if (a.is_current !== b.is_current) return a.is_current ? -1 : 1;
    return Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at);
  });
}

/**
 * Whether an inventory warrants a warning banner.
 *
 * A live break-glass session is the loudest thing that can appear here, so it
 * outranks everything else.
 */
export function inventoryWarning(sessions: SessionRecord[]): string | undefined {
  const live = sessions.filter((session) => session.ended_at === null);
  if (live.some((session) => session.is_break_glass)) {
    return "An emergency break-glass session is active on this account.";
  }
  const passwordOnly = live.filter(sessionIsPasswordOnly).length;
  if (passwordOnly > 0) {
    return `${passwordOnly} active ${
      passwordOnly === 1 ? "session was" : "sessions were"
    } opened with a password alone.`;
  }
  return undefined;
}

// --------------------------------------------------------------------------- //
// Validation
// --------------------------------------------------------------------------- //
function boundedText(value: unknown, min: number, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length < min || trimmed.length > max) return null;
  return trimmed;
}

export function validateReason(value: unknown): string | null {
  return boundedText(value, 3, 500);
}

export function validateLabel(value: unknown): string | null {
  return boundedText(value, 3, 120);
}

export function validateCredential(value: unknown): string | null {
  return boundedText(value, 8, 200);
}
