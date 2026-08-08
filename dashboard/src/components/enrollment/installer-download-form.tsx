// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Download, PackageCheck, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { downloadInstallerPackage } from "@/lib/installer-download-client";

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
      const message = await downloadInstallerPackage(siteId);
      if (message) {
        setError(message);
        return;
      }
      setDone(true);
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
