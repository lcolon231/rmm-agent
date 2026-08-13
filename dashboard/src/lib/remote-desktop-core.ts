// SPDX-License-Identifier: AGPL-3.0-only
//
// Pure, framework-free validation and messaging for MeshCentral remote-desktop
// launches (issue #62). MeshCentral is a separate trust boundary: NodeLink only
// authorizes and audits the launch and hands back a short-lived, single-device
// login URL. Every availability decision here is fail-closed.

export type MeshLaunchStatus =
  | "requested"
  | "authorized"
  | "denied"
  | "failed"
  | "closed";

export interface MeshLaunchData {
  id: string;
  agent_id: string;
  status: MeshLaunchStatus;
  meshcentral_node_id: string | null;
  denied_reason: string | null;
  expires_at: string | null;
  created_at: string;
  closed_at: string | null;
  // Secret, single-use, present only on the create response.
  login_url: string | null;
  login_expires_at: string | null;
}

// Availability reason codes returned by the server availability endpoint.
export type RemoteDesktopReason =
  | "available"
  | "provider_disabled"
  | "agent_not_trusted"
  | "not_authorized"
  | "no_mapping"
  | "mapping_unmapped"
  | "mapping_stale"
  | "mapping_conflict";

export interface RemoteDesktopAvailabilityData {
  available: boolean;
  reason: RemoteDesktopReason | string;
  provider_enabled: boolean;
}

const LAUNCH_STATUSES: readonly MeshLaunchStatus[] = [
  "requested",
  "authorized",
  "denied",
  "failed",
  "closed",
];

const REASON_MESSAGES: Record<RemoteDesktopReason, string> = {
  available: "A remote desktop session can be launched for this endpoint.",
  provider_disabled:
    "Remote desktop is not configured on this NodeLink server.",
  agent_not_trusted:
    "This endpoint is quarantined or revoked, so a remote desktop session cannot be launched.",
  not_authorized:
    "Launching remote desktop requires an administrator-granted script-execution scope for this endpoint.",
  no_mapping:
    "This endpoint is not mapped to a MeshCentral device. Ask an administrator to add the mapping.",
  mapping_unmapped:
    "This endpoint's MeshCentral device was removed. Ask an administrator to remap it.",
  mapping_stale:
    "This endpoint's MeshCentral mapping is stale and must be reconciled before launching.",
  mapping_conflict:
    "This endpoint's MeshCentral mapping conflicts with another endpoint and must be resolved.",
};

export function isMeshLaunchStatus(value: unknown): value is MeshLaunchStatus {
  return (
    typeof value === "string" &&
    (LAUNCH_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * Render an availability decision into a fail-closed message. Anything other
 * than an explicit `available` reason cannot launch.
 */
export function describeRemoteDesktopAvailability(input: {
  available: boolean;
  reason: string;
}): { canLaunch: boolean; message: string } {
  const known = REASON_MESSAGES[input.reason as RemoteDesktopReason];
  if (input.available && input.reason === "available") {
    return { canLaunch: true, message: REASON_MESSAGES.available };
  }
  return {
    canLaunch: false,
    message:
      known ??
      "Remote desktop is unavailable for this endpoint right now.",
  };
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * Validate and allowlist the server's launch record, discarding any unexpected
 * or secret-adjacent field. `login_url` is retained only when it is a string,
 * because the create response legitimately returns it once.
 */
export function meshLaunchFromUnknown(value: unknown): MeshLaunchData | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  if (typeof raw.id !== "string" || typeof raw.agent_id !== "string") {
    return null;
  }
  if (!isMeshLaunchStatus(raw.status)) {
    return null;
  }
  return {
    id: raw.id,
    agent_id: raw.agent_id,
    status: raw.status,
    meshcentral_node_id: optionalString(raw.meshcentral_node_id),
    denied_reason: optionalString(raw.denied_reason),
    expires_at: optionalString(raw.expires_at),
    created_at: typeof raw.created_at === "string" ? raw.created_at : "",
    closed_at: optionalString(raw.closed_at),
    login_url: optionalString(raw.login_url),
    login_expires_at: optionalString(raw.login_expires_at),
  };
}

export function remoteDesktopAvailabilityFromUnknown(
  value: unknown,
): RemoteDesktopAvailabilityData | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  if (typeof raw.available !== "boolean" || typeof raw.reason !== "string") {
    return null;
  }
  return {
    available: raw.available,
    reason: raw.reason,
    provider_enabled:
      typeof raw.provider_enabled === "boolean" ? raw.provider_enabled : false,
  };
}

/** Map a server error code/status to an operator-facing message. */
export function remoteDesktopLaunchErrorMessage(
  code: string | null,
  status: number,
): string {
  if (status === 401) {
    return "Sign in to launch a remote desktop session.";
  }
  switch (code) {
    case "remote_desktop_disabled":
      return "Remote desktop is not configured on this NodeLink server.";
    case "remote_desktop_not_authorized":
      return "Your operator session is not allowed to launch remote desktop for this endpoint.";
    case "agent_not_trusted":
      return "This endpoint is quarantined or revoked, so remote desktop cannot be launched.";
    case "remote_desktop_unmapped":
      return "This endpoint is not mapped to a MeshCentral device. Ask an administrator to add the mapping.";
    case "remote_desktop_mapping_stale":
      return "This endpoint's MeshCentral mapping is stale. Ask an administrator to reconcile it.";
    case "remote_desktop_mapping_conflict":
      return "This endpoint's MeshCentral mapping conflicts with another endpoint. Ask an administrator to resolve it.";
    case "remote_desktop_rate_limited":
      return "Too many remote desktop launches. Wait a minute and try again.";
    case "remote_desktop_unavailable":
      return "MeshCentral is currently unavailable. Try again shortly.";
    default:
      if (status === 404) {
        return "This endpoint no longer exists.";
      }
      return "The remote desktop session could not be launched. Try again.";
  }
}
