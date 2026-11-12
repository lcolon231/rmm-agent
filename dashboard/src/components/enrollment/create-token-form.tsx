// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Check, Clipboard, Download, KeyRound, PackageCheck, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";

import { StatusNote } from "@/components/admin/admin-ui";
import { Card } from "@/components/admin/card";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/drawer";
import { Input, Select, Textarea } from "@/components/ui/field";
import { createTokenInputFromForm } from "@/lib/enrollment-core";
import { downloadInstallerPackage } from "@/lib/installer-download-client";
import type { EnrollmentTokenMetadata } from "@/lib/enrollment";

type CreatedToken = EnrollmentTokenMetadata & { token: string };

function FormSection({ title, hint, children }: { title: string; hint: string; children: ReactNode }) {
  return (
    <fieldset className="m-0 grid gap-4 border-0 border-b border-(--line) p-0 pb-5 last:border-b-0 last:pb-0">
      <legend className="mb-1 grid gap-0.5 p-0">
        <span className="text-sm font-semibold text-(--ink)">{title}</span>
        <span className="text-xs text-(--muted)">{hint}</span>
      </legend>
      {children}
    </fieldset>
  );
}

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
      <section aria-labelledby="token-created-title" className="grid max-w-[640px] gap-6">
        <Card title="Enrollment token created" sub={`Shown once · ${created.max_uses === 1 ? "single use" : `${created.max_uses} uses`}`}>
          <h2 id="token-created-title" className="sr-only">Enrollment token created</h2>
          <StatusNote tone="warn" title="Copy it now">
            NodeLink keeps only a one-way fingerprint of the token and cannot show it again.
          </StatusNote>
          <div className="grid gap-2" aria-label="New enrollment token" role="group">
            <CodeBlock label="Token">{created.token}</CodeBlock>
            <div>
              <Button icon={copied ? Check : Clipboard} onClick={copyToken}>
                {copied ? "Copied" : "Copy token"}
              </Button>
            </div>
          </div>
          {error ? <StatusNote tone="crit" role="alert">{error}</StatusNote> : null}
          <div className="grid gap-2">
            <h3 className="m-0 text-sm font-semibold text-(--ink)">Enroll without the token appearing in shell history</h3>
            <CodeBlock label="Enrollment command">{'rmm-agent enroll --server "https://management.example.com" --token-env "AGENT_ENROLLMENT_TOKEN"'}</CodeBlock>
            <p className="m-0 text-xs text-(--muted)">
              Set the environment variable through your secret manager or a protected prompt. The token is not inserted into the command.
            </p>
          </div>
        </Card>
        <Card title={`Installer for ${installerSiteLabel}`} sub="Separate from the token above">
          <p className="m-0 text-sm">
            Prefer not to hand over a token at all? Download a ready-to-run installer for this site. It carries its own short-lived, single-use token, so the
            technician just extracts the ZIP and runs it.
          </p>
          {installerError ? <StatusNote tone="crit" role="alert">{installerError}</StatusNote> : null}
          {installerDone ? (
            <StatusNote tone="ok" role="status">
              Installer downloading. Extract the ZIP and run the installer from the extracted folder.
            </StatusNote>
          ) : null}
          <div>
            <Button icon={Download} onClick={downloadInstaller} disabled={installerPending || !installerSiteId}>
              {installerPending ? "Preparing…" : "Download installer"}
            </Button>
          </div>
        </Card>
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            icon={KeyRound}
            onClick={() => {
              setCreated(null);
              setCopied(false);
            }}
          >
            Create another
          </Button>
          <Button variant="primary" icon={PackageCheck} onClick={() => router.replace("/enrollment/tokens")}>
            Done, hide token
          </Button>
        </div>
      </section>
    );
  }

  return (
    <form onSubmit={submit} className="grid max-w-[640px] gap-6">
      <Card title="New enrollment token" sub="Short-lived, single-use tokens leave the smallest window for misuse.">
        <FormSection title="Name and site" hint="Name the token and bind it to one site.">
          <Input label="Token name" maxLength={200} name="name" placeholder="Main office rollout" required />
          <Select label="Client / site" name="site_id" required defaultValue={initialSiteId ?? ""}>
            <option disabled value="">
              Select a site
            </option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.label}
              </option>
            ))}
          </Select>
          <Textarea label="Description" maxLength={2000} name="description" placeholder="What the token is for" rows={2} className="min-h-16" />
          <Input label="Assigned operator ID" name="assigned_user_id" placeholder="Optional operator ID" />
          <Input label="Environment" maxLength={100} name="environment" placeholder="production" />
        </FormSection>
        <FormSection title="Device restrictions" hint="A device must match exactly, ignoring letter case.">
          <Input label="Hostname must be" maxLength={255} name="hostname_restriction" placeholder="server01.example.local" />
          <Input label="Agent name must be" maxLength={255} name="agent_name_restriction" placeholder="server-agent-01" />
          <Input label="Labels" name="labels" placeholder="windows, front-desk" hint="Comma-separated, up to 20 different labels." />
        </FormSection>
        <FormSection title="Lifetime" hint="When the token stops working, and how many devices may use it.">
          <Input label="Expires at" name="expires_at" required type="datetime-local" />
          <Input label="Maximum uses" defaultValue="1" max="100" min="1" name="max_uses" required type="number" />
          <Textarea label="Administrator notes" maxLength={4000} name="notes" placeholder="Never sent to the device." rows={3} />
        </FormSection>
        {error ? <StatusNote tone="crit" role="alert">{error}</StatusNote> : null}
      </Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="m-0 flex items-center gap-2 text-xs text-(--muted)">
          <ShieldCheck size={16} aria-hidden="true" /> The token is shown once and never stored in readable form.
        </p>
        <Button type="submit" variant="primary" icon={KeyRound} disabled={pending || sites.length === 0}>
          {pending ? "Creating…" : "Create enrollment token"}
        </Button>
      </div>
    </form>
  );
}
