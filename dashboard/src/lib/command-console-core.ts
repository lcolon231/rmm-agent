// SPDX-License-Identifier: AGPL-3.0-only

export type CommandKind =
  | "powershell"
  | "shell"
  | "collect_inventory"
  | "scan_updates"
  | "install_updates";

export type CommandStatus =
  | "queued"
  | "dispatched"
  | "running"
  | "result_pending"
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
  agent_completed_at: string | null;
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
  input: "script" | "none" | "update_targets";
};

export const commandKindDefinitions: CommandKindDefinition[] = [
  {
    kind: "powershell",
    label: "PowerShell",
    description: "Run a PowerShell script on the endpoint.",
    input: "script",
  },
  {
    kind: "shell",
    label: "Shell",
    description: "Run a system shell command line on the endpoint.",
    input: "script",
  },
  {
    kind: "collect_inventory",
    label: "Collect inventory",
    description: "Ask the agent to refresh its hardware and software inventory.",
    input: "none",
  },
  {
    kind: "scan_updates",
    label: "Scan for updates",
    description:
      "Run a Windows Update scan; results appear in the endpoint's Windows Updates inventory.",
    input: "none",
  },
  {
    kind: "install_updates",
    label: "Install updates",
    description:
      "Selectively download and install targeted Windows updates on the endpoint.",
    input: "update_targets",
  },
];

export function commandKindDefinitionsForPermission(
  canExecuteScripts: boolean,
): CommandKindDefinition[] {
  return canExecuteScripts
    ? commandKindDefinitions
    : commandKindDefinitions.filter((item) => item.input !== "script");
}

// The signed payload is capped at 60 KiB canonical JSON server-side; leave
// headroom for the JSON wrapping around the script text.
export const MAX_SCRIPT_BYTES = 56 * 1024;
export const MAX_UPDATE_TARGETS = 100;

const KB_TARGET = /^KB[0-9]{4,10}$/i;
const UPDATE_ID_TARGET =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  update_targets: string[];
  install_all: boolean;
  ttl_seconds: number;
};

function normalizeUpdateTargets(value: unknown): string[] | null {
  const raw = typeof value === "string"
    ? value.split(/[\s,;]+/)
    : Array.isArray(value) && value.every((item) => typeof item === "string")
      ? value
      : null;
  if (raw === null) return null;
  const targets: string[] = [];
  for (const item of raw) {
    let target = item.trim();
    if (!target) continue;
    if (/^[0-9]{4,10}$/.test(target)) target = `KB${target}`;
    if (KB_TARGET.test(target)) target = target.toUpperCase();
    else if (UPDATE_ID_TARGET.test(target)) target = target.toLowerCase();
    else return null;
    if (!targets.includes(target)) targets.push(target);
  }
  return targets.length <= MAX_UPDATE_TARGETS ? targets : null;
}

export function validateDispatchInput(value: unknown): DispatchInput | null {
  if (!value || typeof value !== "object") return null;
  const {
    kind,
    script,
    update_targets: rawTargets,
    install_all: rawInstallAll,
    ttl_seconds: ttl,
  } = value as Record<string, unknown>;
  const definition = commandKindDefinitions.find((d) => d.kind === kind);
  if (!definition) return null;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 1 || ttl > 86_400) {
    return null;
  }
  if (typeof script !== "string") return null;
  const trimmed = script.replace(/\r\n/g, "\n").trim();
  let updateTargets: string[] = [];
  let installAll = false;
  if (definition.input === "script") {
    if (!trimmed) return null;
    if (new TextEncoder().encode(trimmed).length > MAX_SCRIPT_BYTES) return null;
  } else if (trimmed) {
    // A script on an inventory request would be silently ignored by the
    // agent; refuse it instead of signing dead input.
    return null;
  }
  if (definition.input === "update_targets") {
    const normalizedTargets = normalizeUpdateTargets(rawTargets ?? []);
    if (normalizedTargets === null) return null;
    updateTargets = normalizedTargets;
    if (rawInstallAll !== undefined && typeof rawInstallAll !== "boolean") return null;
    installAll = rawInstallAll === true;
    if (installAll === (updateTargets.length > 0)) return null;
  } else {
    if (rawInstallAll !== undefined && rawInstallAll !== false) return null;
    const unusedTargets = normalizeUpdateTargets(rawTargets ?? []);
    if (unusedTargets === null || unusedTargets.length > 0) return null;
  }
  return {
    kind: definition.kind,
    script: trimmed,
    update_targets: updateTargets,
    install_all: installAll,
    ttl_seconds: ttl,
  };
}

export function buildDispatchRequestBody(input: DispatchInput): {
  kind: CommandKind;
  payload: Record<string, unknown>;
  ttl_seconds: number;
} {
  let payload: Record<string, unknown> = input.script ? { script: input.script } : {};
  if (input.kind === "install_updates") {
    if (input.install_all) {
      payload = { install_all: true };
    } else {
      payload = {
        kb_ids: input.update_targets.filter((target) => KB_TARGET.test(target)),
        update_ids: input.update_targets.filter((target) => UPDATE_ID_TARGET.test(target)),
      };
    }
  }
  return {
    kind: input.kind,
    payload,
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
    case "result_pending":
      return { label: "Result pending", tone: "active", terminal: false };
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
