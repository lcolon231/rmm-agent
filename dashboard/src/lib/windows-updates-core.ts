// SPDX-License-Identifier: AGPL-3.0-only
//
// Pure logic for presenting the windows_updates inventory section (issue #51).
// It allowlists the server's payload into a bounded, display-safe shape so an
// unexpected or secret-adjacent field can never reach the UI, and derives an
// operator-facing summary. Rendering itself is generic (the section shows under
// its label like every other inventory section); this module is the tested core.

export interface MissingUpdateView {
  title: string;
  kb_id: string | null;
  update_id: string | null;
  classification: string | null;
  product: string | null;
  severity: string | null;
  reboot_required: boolean | null;
  is_downloaded: boolean | null;
  support_url: string | null;
  last_deployment_change: string | null;
  priority_grade: string | null;
}

export interface InstalledUpdateView {
  kb_id: string | null;
  update_id: string | null;
  title: string | null;
  installed_on: string | null;
  installed_by: string | null;
  client_application_id: string | null;
  result_code: number | null;
  hresult: string | null;
}

export interface WindowsUpdatesView {
  scanned_at: string | null;
  reboot_required: boolean | null;
  error_code: string | null;
  history_error_code: string | null;
  missing: MissingUpdateView[];
  installed: InstalledUpdateView[];
}

// These mirror the server's bounded inventory schema. The UI paginates the
// result, but it must retain every valid row so search and selection operate on
// the complete current scan instead of an arbitrary preview.
export const MAX_DISPLAY_MISSING = 512;
export const MAX_DISPLAY_INSTALLED = 1_024;
export const WINDOWS_UPDATE_PAGE_SIZE = 25;
export const WINDOWS_UPDATE_STALE_HOURS = 24;

const KB_ID = /^KB[0-9]{4,10}$/i;

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function integer(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function missingFromUnknown(value: unknown): MissingUpdateView | null {
  if (!isRecord(value)) return null;
  const title = str(value.title);
  if (title === null) return null; // the server model requires a title
  return {
    title,
    kb_id: str(value.kb_id),
    update_id: str(value.update_id),
    classification: str(value.classification),
    product: str(value.product),
    severity: str(value.severity),
    reboot_required: bool(value.reboot_required),
    is_downloaded: bool(value.is_downloaded),
    support_url: str(value.support_url),
    last_deployment_change: str(value.last_deployment_change),
    priority_grade: str(value.priority_grade),
  };
}

function installedFromUnknown(value: unknown): InstalledUpdateView | null {
  if (!isRecord(value)) return null;
  return {
    kb_id: str(value.kb_id),
    update_id: str(value.update_id),
    title: str(value.title),
    installed_on: str(value.installed_on),
    installed_by: str(value.installed_by),
    client_application_id: str(value.client_application_id),
    result_code: integer(value.result_code),
    hresult: str(value.hresult),
  };
}

/** Allowlist the section payload into a display-safe view, or null if unusable. */
export function windowsUpdatesFromUnknown(value: unknown): WindowsUpdatesView | null {
  if (!isRecord(value)) return null;
  const missingRaw = Array.isArray(value.missing) ? value.missing : [];
  const installedRaw = Array.isArray(value.installed) ? value.installed : [];
  const missing = missingRaw
    .map(missingFromUnknown)
    .filter((v): v is MissingUpdateView => v !== null)
    .slice(0, MAX_DISPLAY_MISSING);
  const installed = installedRaw
    .map(installedFromUnknown)
    .filter((v): v is InstalledUpdateView => v !== null)
    .slice(0, MAX_DISPLAY_INSTALLED);
  return {
    scanned_at: str(value.scanned_at),
    reboot_required: bool(value.reboot_required),
    error_code: str(value.error_code),
    history_error_code: str(value.history_error_code),
    missing,
    installed,
  };
}

export interface WindowsUpdatesSummary {
  missingCount: number;
  installedCount: number;
  rebootRequired: boolean;
  headline: string;
}

/** A short operator-facing summary of a scan result. */
export function summarizeWindowsUpdates(view: WindowsUpdatesView): WindowsUpdatesSummary {
  const missingCount = view.missing.length;
  const installedCount = view.installed.length;
  const rebootRequired = view.reboot_required === true;
  let headline: string;
  if (view.error_code) {
    headline = "Scan reported an error";
  } else if (view.history_error_code) {
    headline = `${missingCount} missing update${missingCount === 1 ? "" : "s"} · history unavailable`;
  } else if (missingCount === 0) {
    headline = "No missing updates";
  } else {
    headline = `${missingCount} missing update${missingCount === 1 ? "" : "s"}`;
  }
  if (rebootRequired) {
    headline += " · reboot required";
  }
  return { missingCount, installedCount, rebootRequired, headline };
}

export type WindowsUpdateFilters = {
  query: string;
  classification: string;
  excludeDrivers: boolean;
};

export function normalizedKBID(value: string | null): string | null {
  if (!value) return null;
  const normalized = value.trim().toUpperCase();
  return KB_ID.test(normalized) ? normalized : null;
}

export function isDriverUpdate(update: MissingUpdateView): boolean {
  return [update.classification, update.product, update.title]
    .filter((value): value is string => value !== null)
    .some((value) => /\bdrivers?\b/i.test(value));
}

export function windowsUpdateClassifications(updates: MissingUpdateView[]): string[] {
  return Array.from(
    new Set(updates.map((update) => update.classification).filter((value): value is string => Boolean(value))),
  ).sort((left, right) => left.localeCompare(right));
}

export function filterMissingWindowsUpdates(
  updates: MissingUpdateView[],
  filters: WindowsUpdateFilters,
): MissingUpdateView[] {
  const query = filters.query.trim().toLocaleLowerCase();
  return updates.filter((update) => {
    if (filters.excludeDrivers && isDriverUpdate(update)) return false;
    if (filters.classification && update.classification !== filters.classification) return false;
    if (!query) return true;
    return [
      update.title,
      update.kb_id,
      update.update_id,
      update.classification,
      update.product,
      update.severity,
      update.priority_grade,
    ].some((value) => value?.toLocaleLowerCase().includes(query));
  });
}

export function windowsUpdatePageCount(total: number, pageSize = WINDOWS_UPDATE_PAGE_SIZE): number {
  if (!Number.isInteger(pageSize) || pageSize < 1) return 1;
  return Math.max(1, Math.ceil(Math.max(0, total) / pageSize));
}

export function windowsUpdatePage(
  updates: MissingUpdateView[],
  page: number,
  pageSize = WINDOWS_UPDATE_PAGE_SIZE,
): MissingUpdateView[] {
  const safePage = Math.min(Math.max(1, Math.trunc(page)), windowsUpdatePageCount(updates.length, pageSize));
  const start = (safePage - 1) * pageSize;
  return updates.slice(start, start + pageSize);
}

export type WindowsUpdateSelectionSummary = {
  updateCount: number;
  driverCount: number;
  rebootCount: number;
};

export function summarizeWindowsUpdateSelection(
  updates: MissingUpdateView[],
): WindowsUpdateSelectionSummary {
  return {
    updateCount: updates.length,
    driverCount: updates.filter(isDriverUpdate).length,
    rebootCount: updates.filter((update) => update.reboot_required === true).length,
  };
}

export function windowsUpdateScanIsStale(
  scannedAt: string | null,
  nowMs: number,
  staleHours = WINDOWS_UPDATE_STALE_HOURS,
): boolean {
  if (!scannedAt) return true;
  const scannedMs = new Date(scannedAt).getTime();
  if (Number.isNaN(scannedMs)) return true;
  return nowMs - scannedMs >= staleHours * 60 * 60 * 1_000;
}

export type InstallUpdateOutcome = {
  identifier: string;
  resultCode: number;
  hresult: string | null;
  attempts: number;
};

export type InstallRebootView = {
  policy: string;
  decision: string;
  delaySeconds: number | null;
};

export type InstallUpdatesResultView = {
  status: "success" | "partial" | "failed";
  installedKBs: string[];
  failedKBs: string[];
  results: InstallUpdateOutcome[];
  reboot: InstallRebootView | null;
  rebootRequired: boolean;
  message: string;
};

export function installUpdatesResultFromUnknown(value: unknown): InstallUpdatesResultView | null {
  let parsed = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (!isRecord(parsed)) return null;
  const status = parsed.status;
  if (status !== "success" && status !== "partial" && status !== "failed") return null;
  const stringList = (candidate: unknown): string[] | null => {
    if (!Array.isArray(candidate) || candidate.some((item) => typeof item !== "string")) return null;
    return candidate.slice(0, 100);
  };
  const installedKBs = stringList(parsed.installed_kbs);
  const failedKBs = stringList(parsed.failed_kbs);
  if (installedKBs === null || failedKBs === null || typeof parsed.reboot_required !== "boolean") {
    return null;
  }

  // Per-update outcomes (issue #53) — optional and back-compatible.
  const results: InstallUpdateOutcome[] = [];
  if (parsed.results !== undefined) {
    if (!Array.isArray(parsed.results)) return null;
    for (const item of parsed.results.slice(0, 100)) {
      if (!isRecord(item) || typeof item.identifier !== "string" || typeof item.result_code !== "number") {
        return null;
      }
      results.push({
        identifier: item.identifier,
        resultCode: item.result_code,
        hresult: typeof item.hresult === "string" ? item.hresult : null,
        attempts: typeof item.attempts === "number" ? item.attempts : 1,
      });
    }
  }

  let reboot: InstallRebootView | null = null;
  if (parsed.reboot !== undefined && parsed.reboot !== null) {
    if (!isRecord(parsed.reboot) || typeof parsed.reboot.policy !== "string" || typeof parsed.reboot.decision !== "string") {
      return null;
    }
    reboot = {
      policy: parsed.reboot.policy,
      decision: parsed.reboot.decision,
      delaySeconds: typeof parsed.reboot.delay_seconds === "number" ? parsed.reboot.delay_seconds : null,
    };
  }

  return {
    status,
    installedKBs,
    failedKBs,
    results,
    reboot,
    rebootRequired: parsed.reboot_required,
    message: str(parsed.message) ?? "The agent did not provide a result message.",
  };
}
