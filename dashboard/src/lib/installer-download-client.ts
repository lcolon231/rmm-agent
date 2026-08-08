// SPDX-License-Identifier: AGPL-3.0-only

// Browser-side trigger for the personalized installer download (issue #9),
// shared by the standalone download form and the create-token flow. It POSTs to
// the same-origin dashboard route, then streams the returned ZIP to a file
// download. The bundled token lives only inside the blob — nothing secret is
// placed in the URL or browser history. Runs in the browser only.

import { installerDownloadFilename } from "@/lib/installer-download-core";

/**
 * Download the personalized installer package for a site. Returns `null` on
 * success (the browser download has started), or an operator-facing error
 * message describing why it could not be produced.
 */
export async function downloadInstallerPackage(siteId: string): Promise<string | null> {
  let response: Response;
  try {
    response = await fetch(`/api/sites/${encodeURIComponent(siteId)}/installer-package`, {
      method: "POST",
    });
  } catch {
    return "The installer download could not be reached. Check the management service.";
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    return body?.error ?? "The installer download is unavailable right now.";
  }

  const blob = await response.blob();
  const filename = installerDownloadFilename(
    response.headers.get("content-disposition"),
    siteId,
  );
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  return null;
}
