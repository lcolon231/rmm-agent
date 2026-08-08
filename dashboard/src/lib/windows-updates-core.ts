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
  classification: string | null;
  product: string | null;
  severity: string | null;
  reboot_required: boolean | null;
  support_url: string | null;
}

export interface InstalledUpdateView {
  kb_id: string | null;
  title: string | null;
  installed_on: string | null;
  installed_by: string | null;
}

export interface WindowsUpdatesView {
  scanned_at: string | null;
  reboot_required: boolean | null;
  error_code: string | null;
  missing: MissingUpdateView[];
  installed: InstalledUpdateView[];
}

// Hard display caps, independent of the server's storage caps, so a large but
// valid section cannot make the UI enumerate thousands of rows.
export const MAX_DISPLAY_MISSING = 500;
export const MAX_DISPLAY_INSTALLED = 500;

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
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
    classification: str(value.classification),
    product: str(value.product),
    severity: str(value.severity),
    reboot_required: bool(value.reboot_required),
    support_url: str(value.support_url),
  };
}

function installedFromUnknown(value: unknown): InstalledUpdateView | null {
  if (!isRecord(value)) return null;
  return {
    kb_id: str(value.kb_id),
    title: str(value.title),
    installed_on: str(value.installed_on),
    installed_by: str(value.installed_by),
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
