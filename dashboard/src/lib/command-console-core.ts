// SPDX-License-Identifier: AGPL-3.0-only

export type CommandKind = "powershell" | "shell" | "collect_inventory";

export type CommandStatus =
  | "queued"
  | "dispatched"
  | "running"
  | "succeeded"
  | "failed"
  | "expired";

export type CommandHistoryItem = {
  id: string;
  agent_id: string;
  kind: CommandKind;
  status: CommandStatus;
  envelope_version: string;
  schema_version: number | null;
  signing_key_id: string | null;
  exit_code: number | null;
  stdout_truncated: boolean | null;
  stderr_truncated: boolean | null;
  created_at: string;
  issued_at: string | null;
  dispatched_at: string | null;
  completed_at: string | null;
  expires_at: string | null;
};

export type CommandHistoryData = {
  items: CommandHistoryItem[];
  page: number;
  page_size: number;
  total: number;
  outstanding: number;
  outstanding_limit: number;
};

export type CommandDetailData = CommandHistoryItem & {
  payload: Record<string, unknown>;
  nonce: string | null;
  signature: string;
  stdout: string | null;
  stderr: string | null;
  stdout_total_bytes: number | null;
  stderr_total_bytes: number | null;
};

export type CommandKindDefinition = {
  kind: CommandKind;
  label: string;
  description: string;
  requiresScript: boolean;
};

export const commandKindDefinitions: CommandKindDefinition[] = [
  {
    kind: "powershell",
    label: "PowerShell",
    description: "Run a PowerShell script on the endpoint.",
    requiresScript: true,
  },
  {
    kind: "shell",
    label: "Shell",
    description: "Run a system shell command line on the endpoint.",
    requiresScript: true,
  },
  {
    kind: "collect_inventory",
    label: "Collect inventory",
    description: "Ask the agent to refresh its hardware and software inventory.",
    requiresScript: false,
  },
];

// The signed payload is capped at 60 KiB canonical JSON server-side; leave
// headroom for the JSON wrapping around the script text.
export const MAX_SCRIPT_BYTES = 56 * 1024;

export const ttlOptions: Array<{ seconds: number; label: string }> = [
  { seconds: 300, label: "5 minutes" },
  { seconds: 900, label: "15 minutes" },
  { seconds: 3_600, label: "1 hour" },
  { seconds: 21_600, label: "6 hours" },
  { seconds: 86_400, label: "24 hours" },
];

export type DispatchInput = {
  kind: CommandKind;
  script: string;
  ttl_seconds: number;
};

export function validateDispatchInput(value: unknown): DispatchInput | null {
  if (!value || typeof value !== "object") return null;
  const { kind, script, ttl_seconds: ttl } = value as Record<string, unknown>;
  const definition = commandKindDefinitions.find((d) => d.kind === kind);
  if (!definition) return null;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 1 || ttl > 86_400) {
    return null;
  }
  if (typeof script !== "string") return null;
  const trimmed = script.replace(/\r\n/g, "\n").trim();
  if (definition.requiresScript) {
    if (!trimmed) return null;
    if (new TextEncoder().encode(trimmed).length > MAX_SCRIPT_BYTES) return null;
  } else if (trimmed) {
    // A script on an inventory request would be silently ignored by the
    // agent; refuse it instead of signing dead input.
    return null;
  }
  return { kind: definition.kind, script: trimmed, ttl_seconds: ttl };
}

export function buildDispatchRequestBody(input: DispatchInput): {
  kind: CommandKind;
  payload: Record<string, string>;
  ttl_seconds: number;
} {
  return {
    kind: input.kind,
    payload: input.script ? { script: input.script } : {},
    ttl_seconds: input.ttl_seconds,
  };
}

export type CommandStatusPresentation = {
  label: string;
  tone: "pending" | "active" | "success" | "failure" | "expired";
  terminal: boolean;
};

export function describeCommandStatus(status: CommandStatus): CommandStatusPresentation {
  switch (status) {
    case "queued":
      return { label: "Queued", tone: "pending", terminal: false };
    case "dispatched":
      return { label: "Dispatched", tone: "active", terminal: false };
    case "running":
      return { label: "Running", tone: "active", terminal: false };
    case "succeeded":
      return { label: "Succeeded", tone: "success", terminal: true };
    case "failed":
      return { label: "Failed", tone: "failure", terminal: true };
    case "expired":
      return { label: "Expired", tone: "expired", terminal: true };
  }
}

export function hasActiveCommands(items: CommandHistoryItem[]): boolean {
  return items.some((item) => !describeCommandStatus(item.status).terminal);
}

export function formatByteCount(bytes: number | null): string {
  if (bytes === null) return "Unknown";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

export type StreamName = "stdout" | "stderr";

/** Truthful capture note for one output stream.
 *
 * `truncated === null` means the result predates truncation reporting —
 * unknown, which must never be presented as "complete".
 */
export function describeStreamCapture(
  truncated: boolean | null,
  totalBytes: number | null,
  storedText: string | null,
): string {
  if (truncated === true) {
    return `Truncated: the command produced ${formatByteCount(totalBytes)}; only the first captured portion was stored.`;
  }
  if (truncated === false) return "Complete capture.";
  if (storedText === null || storedText === "") return "No output stored.";
  return "Capture completeness unknown (reported by an older agent).";
}

export function commandPageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}
