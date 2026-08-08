// SPDX-License-Identifier: AGPL-3.0-only

// Pure helpers for the personalized installer download (issue #9). Kept free of
// "@/"-alias imports so the node:test runner can load this module directly.
//
// The download proxies a binary ZIP from the management API, so these helpers
// cover the two things worth testing in isolation: deriving a safe attachment
// filename from the upstream response, and mapping an upstream failure to the
// status + operator-facing message the dashboard route returns.

const FILENAME_STAR = /filename\*=(?:UTF-8'')?([^;]+)/i;
const FILENAME_PLAIN = /filename="?([^";]+)"?/i;

/** Extract the filename from a Content-Disposition header, or null. */
export function parseContentDispositionFilename(
  header: string | null | undefined,
): string | null {
  if (!header) return null;
  const star = header.match(FILENAME_STAR);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      // Malformed percent-encoding — fall back to the plain form below.
    }
  }
  const plain = header.match(FILENAME_PLAIN);
  return plain ? plain[1].trim() : null;
}

/**
 * A safe download filename. Strips path separators and control characters and
 * constrains the charset so the value cannot break the Content-Disposition
 * header or imply a path. Falls back to a site-derived name when the upstream
 * header is missing or unusable.
 */
export function installerDownloadFilename(
  header: string | null | undefined,
  siteId: string,
): string {
  const fallback = `NodeLinkAgentSetup-${siteId}.zip`.replace(/[^A-Za-z0-9._-]/g, "-");
  const raw = parseContentDispositionFilename(header);
  if (!raw) return fallback;
  const safe = raw
    .replace(/[\\/\r\n"]+/g, "")
    .replace(/[^A-Za-z0-9._-]/g, "-")
    .slice(0, 128);
  return safe.length > 0 ? safe : fallback;
}

export type InstallerDownloadFailure = { status: number; message: string };

/**
 * Map an upstream failure to the status + operator-facing message the download
 * route returns. Fail-closed 503 codes from the server get specific guidance so
 * an operator can tell "not configured" from "artifact problem".
 */
export function installerDownloadError(
  status: number,
  code: string | null,
): InstallerDownloadFailure {
  if (status === 401) return { status: 401, message: "Sign in again to continue." };
  if (status === 403) {
    return {
      status: 403,
      message: "Your role cannot download an installer for this site.",
    };
  }
  if (status === 404) return { status: 404, message: "That site no longer exists." };
  switch (code) {
    case "installer_downloads_disabled":
      return {
        status: 503,
        message: "Personalized installer downloads are not enabled on this server.",
      };
    case "installer_artifact_unavailable":
      return {
        status: 503,
        message: "The installer artifact is missing on the server. Contact an administrator.",
      };
    case "installer_artifact_integrity":
      return {
        status: 503,
        message: "The server refused to ship an installer that failed its integrity check.",
      };
    default:
      return { status: 503, message: "The installer download is unavailable right now." };
  }
}
