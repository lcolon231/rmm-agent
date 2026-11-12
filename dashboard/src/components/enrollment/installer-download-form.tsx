// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Download } from "lucide-react";
import { useState } from "react";

import { StatusNote } from "@/components/admin/admin-ui";
import { Card } from "@/components/admin/card";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
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
    <form onSubmit={download} className="grid max-w-[640px] gap-6">
      <Card title="Installer for one site" sub="The package enrolls into this site, and its token expires quickly.">
        <Select
          label="Client / site"
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
        </Select>
        <StatusNote tone="warn" title="Treat the file like a password">
          The ZIP holds the installer and a single-use enrollment token. Anyone with the file can enroll one machine to this site until the token
          expires, so hand it to the technician directly rather than emailing or storing it. Each download is recorded in the audit log.
        </StatusNote>
        {error ? (
          <StatusNote tone="crit" role="alert">
            {error}
          </StatusNote>
        ) : null}
        {done ? (
          <StatusNote tone="ok" role="status">
            Your installer is downloading. Extract the ZIP and run the installer from the extracted folder; no token entry is needed.
          </StatusNote>
        ) : null}
      </Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="m-0 text-xs text-(--muted)">The token travels inside the ZIP, never in a link or log.</p>
        <Button type="submit" variant="primary" icon={Download} disabled={pending || !siteId}>
          {pending ? "Preparing…" : "Download installer"}
        </Button>
      </div>
    </form>
  );
}
