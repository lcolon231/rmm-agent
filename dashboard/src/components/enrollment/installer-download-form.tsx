// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Download, PackageCheck, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { installerDownloadFilename } from "@/lib/installer-download-core";

export function InstallerDownloadForm({
  initialSiteId,
  sites,
}: {
  initialSiteId?: string;
  sites: Array<{ id: string; label: string }>;
}) {
  const [siteId, setSiteId] = useState(initialSiteId ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function download(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setDone(false);
    if (!siteId) {
      setError("Choose a site to package the installer for.");
      return;
    }
    setPending(true);
    try {
      const response = await fetch(
        `/api/sites/${encodeURIComponent(siteId)}/installer-package`,
        { method: "POST" },
      );
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        setError(body?.error ?? "The installer download is unavailable right now.");
        return;
      }
      // Stream the ZIP to a browser download. The token lives only inside the
      // blob; no secret is placed in the URL or the browser history.
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
      setDone(true);
    } catch {
      setError("The installer download could not be reached. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="enrollment-form" onSubmit={download}>
      <section>
        <div className="enrollment-form-heading">
          <span>01</span>
          <div>
            <h2>Choose a site</h2>
            <p>The package enrolls into this site and its token expires quickly.</p>
          </div>
        </div>
        <div className="enrollment-form-grid">
          <label className="span-2">
            Organization / site
            <select
              name="site_id"
              required
              value={siteId}
              onChange={(event) => setSiteId(event.target.value)}
            >
              <option disabled value="">
                Select a site
              </option>
              {sites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>
      <p className="enrollment-form-note">
        <ShieldAlert size={16} /> The download is a ZIP containing the installer and a
        single-use enrollment token. Anyone with the file can enroll one machine to this
        site until the token expires — hand it to the technician directly, and don’t email
        or store it. Each download is recorded for audit.
      </p>
      {error ? (
        <p className="enrollment-form-error" role="alert">
          {error}
        </p>
      ) : null}
      {done ? (
        <p className="enrollment-form-success" role="status">
          <PackageCheck size={16} /> Your personalized installer is downloading. Extract the
          ZIP and run the installer from the extracted folder — no token entry is needed.
        </p>
      ) : null}
      <footer>
        <span>
          <ShieldAlert size={16} /> The token is delivered inside the ZIP, never in a link
          or log.
        </span>
        <button className="primary" disabled={pending || !siteId} type="submit">
          <Download size={16} /> {pending ? "Preparing…" : "Download installer"}
        </button>
      </footer>
    </form>
  );
}
