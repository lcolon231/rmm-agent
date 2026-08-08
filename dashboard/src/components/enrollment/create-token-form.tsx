// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Check, Clipboard, Download, KeyRound, PackageCheck, ShieldCheck, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createTokenInputFromForm } from "@/lib/enrollment-core";
import { downloadInstallerPackage } from "@/lib/installer-download-client";
import type { EnrollmentTokenMetadata } from "@/lib/enrollment";

type CreatedToken = EnrollmentTokenMetadata & { token: string };

export function CreateTokenForm({
  initialSiteId,
  sites,
}: {
  initialSiteId?: string;
  sites: Array<{ id: string; label: string }>;
}) {
  const router = useRouter();
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  // The site the just-created token belongs to, so the same page can also
  // package a ready-to-run installer for it (issue #9).
  const [installerSiteId, setInstallerSiteId] = useState("");
  const [installerPending, setInstallerPending] = useState(false);
  const [installerError, setInstallerError] = useState("");
  const [installerDone, setInstallerDone] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const input = createTokenInputFromForm(new FormData(event.currentTarget));
    if (!input) {
      setError("Check the required fields, future expiration, labels, and usage limit.");
      return;
    }
    setPending(true);
    try {
      const response = await fetch("/api/enrollment-tokens", {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as (CreatedToken & { error?: string }) | null;
      if (!response.ok || !body) {
        setError(body?.error ?? "The token could not be created.");
        return;
      }
      setCreated(body);
      setInstallerSiteId(input.site_id);
      setInstallerError("");
      setInstallerDone(false);
    } catch {
      setError("The token could not be created. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  async function downloadInstaller() {
    if (!installerSiteId) return;
    setInstallerError("");
    setInstallerDone(false);
    setInstallerPending(true);
    try {
      const message = await downloadInstallerPackage(installerSiteId);
      if (message) {
        setInstallerError(message);
        return;
      }
      setInstallerDone(true);
    } finally {
      setInstallerPending(false);
    }
  }

  async function copyToken() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setError("Clipboard access was blocked. Select and copy the token text manually.");
    }
  }

  if (created) {
    const installerSiteLabel = sites.find((site) => site.id === installerSiteId)?.label ?? "this site";
    return (
      <section className="token-reveal" aria-labelledby="token-created-title">
        <div className="token-reveal-seal"><ShieldCheck size={28} /></div>
        <div className="token-reveal-copy">
          <span>Issued once · {created.max_uses === 1 ? "single use" : `${created.max_uses} uses`}</span>
          <h2 id="token-created-title">Enrollment token created</h2>
          <p>Copy it now. NodeLink stores only a one-way hash and cannot show this value again.</p>
        </div>
        <div className="token-secret" aria-label="New enrollment token">
          <code>{created.token}</code>
          <button onClick={copyToken} type="button">{copied ? <Check size={17} /> : <Clipboard size={17} />}{copied ? "Copied" : "Copy token"}</button>
        </div>
        {error ? <p className="enrollment-form-error" role="alert">{error}</p> : null}
        <div className="token-command">
          <span>History-safe enrollment command</span>
          <code>rmm-agent enroll --server &quot;https://management.example.com&quot; --token-env &quot;AGENT_ENROLLMENT_TOKEN&quot;</code>
          <small>Set the environment variable through your secret manager or a protected prompt. The token is not inserted into the command.</small>
        </div>
        <div className="token-installer">
          <span><PackageCheck size={15} /> Zero-touch installer for {installerSiteLabel}</span>
          <p>Prefer not to hand over a token at all? Download a ready-to-run installer for this site. It bundles its own short-lived, single-use token, so the technician just extracts the ZIP and runs it — nothing to type. This is separate from the token above.</p>
          {installerError ? <p className="enrollment-form-error" role="alert">{installerError}</p> : null}
          {installerDone ? <p className="enrollment-form-success" role="status"><PackageCheck size={15} /> Installer downloading — extract the ZIP and run the installer from the extracted folder.</p> : null}
          <button onClick={downloadInstaller} disabled={installerPending || !installerSiteId} type="button"><Download size={16} /> {installerPending ? "Preparing…" : "Download installer"}</button>
        </div>
        <div className="token-reveal-actions">
          <button onClick={() => { setCreated(null); setCopied(false); }} type="button"><KeyRound size={16} /> Create another</button>
          <button className="primary" onClick={() => router.replace("/enrollment/tokens")} type="button"><X size={16} /> Done — hide token</button>
        </div>
      </section>
    );
  }

  return (
    <form className="enrollment-form" onSubmit={submit}>
      <section>
        <div className="enrollment-form-heading"><span>01</span><div><h2>Identity and assignment</h2><p>Name the credential and bind it to a specific organization site.</p></div></div>
        <div className="enrollment-form-grid">
          <label>Token name<input maxLength={200} name="name" placeholder="Tampa production rollout" required /></label>
          <label>Organization / site<select name="site_id" required defaultValue={initialSiteId ?? ""}><option disabled value="">Select a site</option>{sites.map((site) => <option key={site.id} value={site.id}>{site.label}</option>)}</select></label>
          <label className="span-2">Description<textarea maxLength={2000} name="description" placeholder="Purpose and intended installer" rows={2} /></label>
          <label>Assigned user ID<input name="assigned_user_id" placeholder="Optional operator UUID" /></label>
          <label>Environment<input maxLength={100} name="environment" placeholder="production" /></label>
        </div>
      </section>
      <section>
        <div className="enrollment-form-heading"><span>02</span><div><h2>Endpoint restrictions</h2><p>Claims must match exactly, ignoring letter case.</p></div></div>
        <div className="enrollment-form-grid">
          <label>Hostname restriction<input maxLength={255} name="hostname_restriction" placeholder="server01.example.local" /></label>
          <label>Agent-name restriction<input maxLength={255} name="agent_name_restriction" placeholder="server-agent-01" /></label>
          <label className="span-2">Labels<input name="labels" placeholder="windows, finance, tier-1" /><small>Comma-separated, up to 20 unique labels.</small></label>
        </div>
      </section>
      <section>
        <div className="enrollment-form-heading"><span>03</span><div><h2>Lifetime and control</h2><p>Short-lived, single-use tokens have the smallest exposure window.</p></div></div>
        <div className="enrollment-form-grid">
          <label>Expires at<input name="expires_at" required type="datetime-local" /></label>
          <label>Maximum uses<input defaultValue="1" max="100" min="1" name="max_uses" required type="number" /></label>
          <label className="span-2">Administrator notes<textarea maxLength={4000} name="notes" placeholder="Internal notes are never sent to the agent." rows={3} /></label>
        </div>
      </section>
      {error ? <p className="enrollment-form-error" role="alert">{error}</p> : null}
      <footer><span><ShieldCheck size={16} /> Plaintext is returned once and never stored.</span><button className="primary" disabled={pending || sites.length === 0} type="submit"><KeyRound size={16} /> {pending ? "Creating…" : "Create enrollment token"}</button></footer>
    </form>
  );
}
