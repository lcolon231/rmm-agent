// SPDX-License-Identifier: AGPL-3.0-only

export type CommandKind =
  | "powershell"
  | "shell"
  | "collect_inventory"
  | "scan_updates"
  | "install_updates"
  | "file_upload"
  | "file_download"
  | "registry_read"
  | "registry_write"
  | "registry_delete"
  | "remediation_rollback"
  | "reboot"
  | "shutdown"
  | "cancel_power_action";

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
  input:
    | "script"
    | "none"
    | "update_targets"
    | "file_upload"
    | "file_download"
    | "registry_read"
    | "registry_write"
    | "registry_delete"
    | "rollback"
    | "power_action"
    | "power_cancel";
  adminOnly?: boolean;
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
  {
    kind: "file_upload",
    label: "Upload managed file",
    description: "Atomically write a digest-verified file inside a managed transfer root.",
    input: "file_upload",
    adminOnly: true,
  },
  {
    kind: "file_download",
    label: "Download managed file",
    description: "Read a bounded file from a managed transfer root with digest evidence.",
    input: "file_download",
    adminOnly: true,
  },
  {
    kind: "registry_read",
    label: "Read managed registry value",
    description: "Read a typed value from the managed HKLM or HKCU subtree.",
    input: "registry_read",
    adminOnly: true,
  },
  {
    kind: "registry_write",
    label: "Write managed registry value",
    description: "Write a typed registry value and create local rollback metadata.",
    input: "registry_write",
    adminOnly: true,
  },
  {
    kind: "registry_delete",
    label: "Delete managed registry value",
    description: "Delete one managed registry value after explicit confirmation and backup.",
    input: "registry_delete",
    adminOnly: true,
  },
  {
    kind: "remediation_rollback",
    label: "Restore remediation backup",
    description: "Restore a previous file or registry value from its endpoint-local backup ID.",
    input: "rollback",
    adminOnly: true,
  },
  {
    kind: "reboot",
    label: "Restart endpoint",
    description: "Schedule a delayed Windows restart inside an active maintenance window.",
    input: "power_action",
    adminOnly: true,
  },
  {
    kind: "shutdown",
    label: "Shut down endpoint",
    description: "Schedule a delayed Windows shutdown inside an active maintenance window.",
    input: "power_action",
    adminOnly: true,
  },
  {
    kind: "cancel_power_action",
    label: "Cancel pending power action",
    description: "Cancel a delayed Windows restart or shutdown, if one is pending.",
    input: "power_cancel",
    adminOnly: true,
  },
];

export function commandKindDefinitionsForPermission(
  canExecuteScripts: boolean,
  isAdmin = false,
): CommandKindDefinition[] {
  return commandKindDefinitions.filter(
    (item) => (canExecuteScripts || item.input !== "script") && (isAdmin || !item.adminOnly),
  );
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
  operation_payload?: Record<string, unknown>;
};

const SHA256 = /^[0-9a-f]{64}$/;
const BACKUP_ID = /^[0-9a-f]{32}$/;
const MANAGED_PATH = /^(?:C:\\ProgramData\\NodeLink\\Managed|C:\\Windows\\Temp\\NodeLink)(?:\\[^\\:\r\n]+)*$/i;
const REGISTRY_KEY = /^Software\\NodeLink\\Managed(?:\\[^\\\r\n]+)*$/i;
const RESERVED_WINDOWS_NAMES = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i;

function isManagedPath(value: unknown): value is string {
  if (typeof value !== "string" || !MANAGED_PATH.test(value)) return false;
  return value.slice(3).split("\\").every(
    (segment) => segment !== "" && segment === segment.trimEnd() && !RESERVED_WINDOWS_NAMES.test(segment),
  );
}

export function commandDetailRequiresAdmin(kind: CommandKind): boolean {
  return commandKindDefinitions.find((item) => item.kind === kind)?.adminOnly === true;
}

function validateOperationPayload(
  kind: CommandKind,
  raw: unknown,
): Record<string, unknown> | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const payload = raw as Record<string, unknown>;
  if (kind === "reboot" || kind === "shutdown") {
    const allowed = ["confirm", "reason", "delay_seconds", "user_consent"];
    if (Object.keys(payload).length !== allowed.length || Object.keys(payload).some((key) => !allowed.includes(key))) return null;
    const reason = typeof payload.reason === "string" ? payload.reason.trim() : "";
    const reasonBytes = new TextEncoder().encode(reason).length;
    if (payload.confirm !== true || reasonBytes < 10 || reasonBytes > 512 || /[\u0000-\u001f\u007f]/.test(reason)) return null;
    if (typeof payload.delay_seconds !== "number" || !Number.isInteger(payload.delay_seconds) || payload.delay_seconds < 30 || payload.delay_seconds > 3600) return null;
    if (payload.user_consent !== "confirmed" && payload.user_consent !== "no_user_session") return null;
    return { confirm: true, reason, delay_seconds: payload.delay_seconds, user_consent: payload.user_consent };
  }
  if (kind === "cancel_power_action") {
    if (Object.keys(payload).length !== 2 || payload.confirm !== true || typeof payload.reason !== "string") return null;
    const reason = payload.reason.trim();
    const reasonBytes = new TextEncoder().encode(reason).length;
    if (reasonBytes < 10 || reasonBytes > 512 || /[\u0000-\u001f\u007f]/.test(reason) || !Object.keys(payload).every((key) => ["confirm", "reason"].includes(key))) return null;
    return { confirm: true, reason };
  }
  const path = payload.path;
  if (kind === "file_upload") {
    if (!isManagedPath(path)) return null;
    if (typeof payload.content_base64 !== "string" || payload.content_base64.length > 44_000) return null;
    if (typeof payload.sha256 !== "string" || !SHA256.test(payload.sha256)) return null;
    if (typeof payload.overwrite !== "boolean") return null;
    if (Object.keys(payload).some((key) => !["path", "content_base64", "sha256", "overwrite"].includes(key))) return null;
    return { path, content_base64: payload.content_base64, sha256: payload.sha256, overwrite: payload.overwrite };
  }
  if (kind === "file_download") {
    if (!isManagedPath(path)) return null;
    if (payload.expected_sha256 !== undefined && (typeof payload.expected_sha256 !== "string" || !SHA256.test(payload.expected_sha256))) return null;
    if (Object.keys(payload).some((key) => !["path", "expected_sha256"].includes(key))) return null;
    return { path, ...(payload.expected_sha256 ? { expected_sha256: payload.expected_sha256 } : {}) };
  }
  if (kind === "remediation_rollback") {
    return Object.keys(payload).length === 1 && typeof payload.backup_id === "string" && BACKUP_ID.test(payload.backup_id)
      ? { backup_id: payload.backup_id }
      : null;
  }
  if (["registry_read", "registry_write", "registry_delete"].includes(kind)) {
    const { hive, key, value_name: valueName, view } = payload;
    if ((hive !== "HKLM" && hive !== "HKCU") || typeof key !== "string" || !REGISTRY_KEY.test(key)) return null;
    if (typeof valueName !== "string" || valueName.length > 163 || /[\\\0]/.test(valueName)) return null;
    if (view !== 32 && view !== 64) return null;
    const base = { hive, key, value_name: valueName, view };
    if (kind === "registry_read") {
      return Object.keys(payload).every((name) => ["hive", "key", "value_name", "view"].includes(name)) ? base : null;
    }
    const expected = payload.expected_current_sha256;
    if (expected !== undefined && (typeof expected !== "string" || !SHA256.test(expected))) return null;
    if (kind === "registry_delete") {
      if (payload.confirm !== true || Object.keys(payload).some((name) => !["hive", "key", "value_name", "view", "confirm", "expected_current_sha256"].includes(name))) return null;
      return { ...base, confirm: true, ...(expected ? { expected_current_sha256: expected } : {}) };
    }
    if (!["string", "expand_string", "dword", "qword", "multi_string", "binary"].includes(String(payload.type))) return null;
    if (payload.data === undefined || Object.keys(payload).some((name) => !["hive", "key", "value_name", "view", "type", "data", "expected_current_sha256"].includes(name))) return null;
    if (["string", "expand_string"].includes(String(payload.type)) && (typeof payload.data !== "string" || new TextEncoder().encode(payload.data).length > 16 * 1024)) return null;
    if (payload.type === "dword" && (typeof payload.data !== "number" || !Number.isInteger(payload.data) || payload.data < 0 || payload.data > 0xffff_ffff)) return null;
    if (payload.type === "qword" && (typeof payload.data !== "number" || !Number.isSafeInteger(payload.data) || payload.data < 0)) return null;
    if (payload.type === "multi_string" && (!Array.isArray(payload.data) || payload.data.length > 256 || payload.data.some((item) => typeof item !== "string" || item.includes("\0")))) return null;
    if (payload.type === "binary" && (typeof payload.data !== "string" || payload.data.length > 22_000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(payload.data))) return null;
    return { ...base, type: payload.type, data: payload.data, ...(expected ? { expected_current_sha256: expected } : {}) };
  }
  return null;
}

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
    operation_payload: rawOperationPayload,
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
  const isOperation = !["script", "none", "update_targets"].includes(definition.input);
  const operationPayload = isOperation
    ? validateOperationPayload(definition.kind, rawOperationPayload)
    : undefined;
  if (isOperation && !operationPayload) return null;
  if (
    !isOperation
    && rawOperationPayload !== undefined
    && (
      !rawOperationPayload
      || typeof rawOperationPayload !== "object"
      || Array.isArray(rawOperationPayload)
      || Object.keys(rawOperationPayload as Record<string, unknown>).length > 0
    )
  ) return null;
  return {
    kind: definition.kind,
    script: trimmed,
    update_targets: updateTargets,
    install_all: installAll,
    ttl_seconds: ttl,
    ...(operationPayload ? { operation_payload: operationPayload } : {}),
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
  if (input.operation_payload) payload = input.operation_payload;
  return {
    kind: input.kind,
    payload,
    ttl_seconds: input.ttl_seconds,
  };
}

export type PowerOperationResult = {
  status: "scheduled" | "cancelled" | "none_pending" | "refused" | "invalid" | "unavailable" | "unsupported" | "failed";
  action: "reboot" | "shutdown" | "cancel_power_action";
  delaySeconds: number | null;
  maintenanceWindowId: string | null;
  maintenanceWindowEndsAt: string | null;
  userConsent: "confirmed" | "no_user_session" | null;
  reasonSHA256: string;
  message: string | null;
};

export function powerOperationResultFromUnknown(value: unknown): PowerOperationResult | null {
  if (typeof value !== "string" || !value.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const result = parsed as Record<string, unknown>;
  if (!["scheduled", "cancelled", "none_pending", "refused", "invalid", "unavailable", "unsupported", "failed"].includes(String(result.status))) return null;
  if (!["reboot", "shutdown", "cancel_power_action"].includes(String(result.action))) return null;
  if (typeof result.reason_sha256 !== "string" || !SHA256.test(result.reason_sha256)) return null;
  const delay = result.delay_seconds;
  if (delay !== undefined && (typeof delay !== "number" || !Number.isInteger(delay) || delay < 30 || delay > 3600)) return null;
  const consent = result.user_consent;
  if (consent !== undefined && consent !== "confirmed" && consent !== "no_user_session") return null;
  return {
    status: result.status as PowerOperationResult["status"],
    action: result.action as PowerOperationResult["action"],
    delaySeconds: typeof delay === "number" ? delay : null,
    maintenanceWindowId: typeof result.maintenance_window_id === "string" ? result.maintenance_window_id : null,
    maintenanceWindowEndsAt: typeof result.maintenance_window_ends_at === "string" ? result.maintenance_window_ends_at : null,
    userConsent: consent === "confirmed" || consent === "no_user_session" ? consent : null,
    reasonSHA256: result.reason_sha256,
    message: typeof result.message === "string" ? result.message : null,
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
