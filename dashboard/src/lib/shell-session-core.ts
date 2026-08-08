// SPDX-License-Identifier: AGPL-3.0-only
//
// Pure, framework-free logic for interactive shell sessions (issue #61),
// Phase 1. Covers the documented states and the allowlisting of the server's
// session record. No streaming/terminal logic lives here yet — that arrives
// with the live frame relay in a later phase.

export type ShellSessionStatus =
  | "pending"
  | "active"
  | "closed"
  | "denied"
  | "timed_out"
  | "failed";

export type ShellSessionTone = "neutral" | "positive" | "warning" | "danger";

export interface ShellSessionData {
  id: string;
  agent_id: string;
  status: ShellSessionStatus;
  capability_version: string | null;
  close_reason: string | null;
  created_at: string;
  activated_at: string | null;
  last_activity_at: string | null;
  closed_at: string | null;
  absolute_deadline: string | null;
  idle_deadline: string | null;
  output_bytes_limit: number | null;
  output_bytes_total: number;
  frames_in: number;
  frames_out: number;
}

// The agent capability that unlocks the feature; mirrors the server and agent.
export const SHELL_SESSION_CAPABILITY = "shell-session-v1";

const STATUSES: readonly ShellSessionStatus[] = [
  "pending",
  "active",
  "closed",
  "denied",
  "timed_out",
  "failed",
];

const TERMINAL: ReadonlySet<ShellSessionStatus> = new Set([
  "closed",
  "denied",
  "timed_out",
  "failed",
]);

/**
 * Whether an operator may open a shell session against an endpoint, and if not,
 * the documented reason. Fail-closed: anything but a trusted, capable, and
 * permitted endpoint is unavailable.
 */
export type ShellSessionAvailability =
  | "available"
  | "unavailable_untrusted"
  | "unavailable_forbidden"
  | "unsupported";

export function describeShellSessionAvailability(input: {
  trusted: boolean;
  capable: boolean;
  canExecuteScripts: boolean;
}): { availability: ShellSessionAvailability; canOpen: boolean; reason: string } {
  if (!input.trusted) {
    return {
      availability: "unavailable_untrusted",
      canOpen: false,
      reason:
        "This endpoint is quarantined or revoked, so a live shell cannot be opened.",
    };
  }
  if (!input.capable) {
    return {
      availability: "unsupported",
      canOpen: false,
      reason:
        "This endpoint's agent does not support interactive shell sessions.",
    };
  }
  if (!input.canExecuteScripts) {
    return {
      availability: "unavailable_forbidden",
      canOpen: false,
      reason:
        "Opening a shell requires an administrator-granted script-execution scope for this endpoint.",
    };
  }
  return {
    availability: "available",
    canOpen: true,
    reason: "A live shell session can be opened for this endpoint.",
  };
}

export function shellSessionStatePresentation(status: ShellSessionStatus): {
  label: string;
  tone: ShellSessionTone;
  terminal: boolean;
} {
  const map: Record<ShellSessionStatus, { label: string; tone: ShellSessionTone }> = {
    pending: { label: "Waiting for agent", tone: "warning" },
    active: { label: "Live", tone: "positive" },
    closed: { label: "Closed", tone: "neutral" },
    denied: { label: "Denied", tone: "danger" },
    timed_out: { label: "Timed out", tone: "warning" },
    failed: { label: "Failed", tone: "danger" },
  };
  return { ...map[status], terminal: TERMINAL.has(status) };
}

export function isShellSessionStatus(value: unknown): value is ShellSessionStatus {
  return typeof value === "string" && (STATUSES as readonly string[]).includes(value);
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function optionalNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Validate and allowlist the server's session record, discarding any unexpected
 * or secret-adjacent fields. Returns null when the required shape is not met.
 */
export function shellSessionFromUnknown(value: unknown): ShellSessionData | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  if (typeof raw.id !== "string" || typeof raw.agent_id !== "string") {
    return null;
  }
  if (!isShellSessionStatus(raw.status)) {
    return null;
  }
  return {
    id: raw.id,
    agent_id: raw.agent_id,
    status: raw.status,
    capability_version: optionalString(raw.capability_version),
    close_reason: optionalString(raw.close_reason),
    created_at: typeof raw.created_at === "string" ? raw.created_at : "",
    activated_at: optionalString(raw.activated_at),
    last_activity_at: optionalString(raw.last_activity_at),
    closed_at: optionalString(raw.closed_at),
    absolute_deadline: optionalString(raw.absolute_deadline),
    idle_deadline: optionalString(raw.idle_deadline),
    output_bytes_limit: optionalNumber(raw.output_bytes_limit),
    output_bytes_total: optionalNumber(raw.output_bytes_total) ?? 0,
    frames_in: optionalNumber(raw.frames_in) ?? 0,
    frames_out: optionalNumber(raw.frames_out) ?? 0,
  };
}

/** Map a server error code/status to an operator-facing message. */
export function shellSessionOpenErrorMessage(
  code: string | null,
  status: number,
): string {
  if (status === 401 || code === null) {
    if (status === 401) {
      return "Sign in to open a shell session.";
    }
  }
  switch (code) {
    case "shell_session_not_authorized":
      return "Your operator session is not allowed to open a shell for this endpoint.";
    case "agent_not_trusted":
      return "This endpoint is quarantined or revoked, so a shell cannot be opened.";
    case "shell_session_unsupported":
      return "This endpoint's agent does not support interactive shell sessions.";
    case "shell_session_already_active":
      return "A shell session is already active for this endpoint. Close it first.";
    default:
      if (status === 404) {
        return "This endpoint no longer exists.";
      }
      return "The shell session could not be opened. Try again.";
  }
}
