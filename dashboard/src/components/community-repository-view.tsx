// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { BadgeCheck, KeyRound, PackageCheck, Store } from "lucide-react";
import { useState } from "react";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { ErrorState } from "@/components/ui/states";
import { FilterBar, SearchField } from "@/components/ui/filter-bar";
import { StatusBadge } from "@/components/ui/status-badge";
import {
  compareSemver,
  effectCapabilitiesOf,
  sameCapabilitySet,
  
  type CommunityInstall,
  type CommunityPackage,
  type CommunityPackageVersion,
  type CommunityPublisher,
} from "@/lib/community-packages-core";
import { formatScriptTimestamp, type OperatorRole } from "@/lib/script-library-core";

type Props = {
  publishers: CommunityPublisher[] | null;
  packages: CommunityPackage[] | null;
  installs: CommunityInstall[] | null;
  initialError: string;
  role: OperatorRole;
};

function requestId(prefix: string): string {
  const random = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID().replaceAll("-", "").slice(0, 20) : String(Date.now());
  return `${prefix}-${random}`;
}

async function send(path: string, body: unknown): Promise<void> {
  const response = await fetch(`/api/community/${path}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.result) throw new Error(payload.error ?? "The change was not confirmed.");
}

function useAction() {
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function run(path: string, body: unknown) {
    setBusy(true); setError("");
    try { await send(path, body); window.location.reload(); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "The change was not confirmed."); setBusy(false); }
  }
  return { busy, error, run };
}

function short(value: string) { return `${value.slice(0, 12)}…`; }

function Capabilities({ values, escalation = [] }: { values: string[]; escalation?: string[] }) {
  return <ul className="flex flex-wrap gap-2 text-xs" aria-label="Declared capabilities">{values.map((item) =>
    <li key={item} className={escalation.includes(item) ? "rounded bg-(--amber-soft) px-2 py-1 text-[#89500b]" : effectCapabilitiesOf([item]).length ? "rounded bg-(--primary-tint) px-2 py-1 text-(--primary-press)" : "rounded bg-(--fog) px-2 py-1"}>
      {item}{escalation.includes(item) ? " (new)" : ""}</li>)}</ul>;
}

function CapabilityAcceptance({ capabilities, accepted, onChange }: {
  capabilities: string[]; accepted: string[]; onChange: (next: string[]) => void;
}) {
  return <fieldset className="grid gap-3 rounded-lg border border-(--line) p-4"><legend>Accept every declared capability</legend>
    {capabilities.map((item) => <label key={item}><input type="checkbox" checked={accepted.includes(item)}
      onChange={(event) => onChange(event.target.checked ? [...accepted, item] : accepted.filter((value) => value !== item))} />{item}</label>)}
  </fieldset>;
}

function ModerationForm({ pkg, version }: { pkg: CommunityPackage; version: CommunityPackageVersion }) {
  const { busy, error, run } = useAction(); const [reason, setReason] = useState(""); const [ack, setAck] = useState(false);
  const path = `packages/${encodeURIComponent(pkg.id)}/versions/${version.version}/moderation`;
  const needsAck = version.capability_escalation.length > 0; const [rejecting, setRejecting] = useState(false);
  return <div className="grid gap-3">
    <label>Moderation reason<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} /></label>
    {needsAck ? <label className="flex items-center gap-2"><input type="checkbox" checked={ack} onChange={(event) => setAck(event.target.checked)} />
      I reviewed the added capabilities: {version.capability_escalation.join(", ")}</label> : null}
    <div><button disabled={busy || reason.trim().length < 3 || needsAck && !ack}
      onClick={() => run(path, { state: "approved", reason, acknowledge_capability_escalation: ack })}>Approve</button>
    <button className="text-(--red)" disabled={busy || reason.trim().length < 3}
      onClick={() => setRejecting(true)}>Reject</button></div><ConfirmDialog open={rejecting} onCancel={() => setRejecting(false)} title="Reject version?" consequence="The version will not be available for installation." confirmLabel="Reject version" busy={busy} error={error || undefined} onConfirm={(confirmedReason) => run(path, { state: "rejected", reason: confirmedReason })} />
    {error ? <p role="alert">{error}</p> : null}
  </div>;
}

function InstallForm({ pkg, version }: { pkg: CommunityPackage; version: CommunityPackageVersion }) {
  const { busy, error, run } = useAction(); const [accepted, setAccepted] = useState<string[]>([]);
  const ready = sameCapabilitySet(accepted, version.capabilities);
  return <div className="grid gap-3">
    <CapabilityAcceptance capabilities={version.capabilities} accepted={accepted} onChange={setAccepted} />
    <div><button disabled={busy || !ready} onClick={() => run("installs", {
      package_id: pkg.id, version: version.version, accepted_capabilities: accepted, request_id: requestId("install"),
    })}>Install into script library</button></div>
    {error ? <p role="alert">{error}</p> : null}
  </div>;
}

function RevokeForm({ path, label }: { path: string; label: string }) {
  const { busy, error, run } = useAction();
  const [open, setOpen] = useState(false); const [validationError, setValidationError] = useState("");
  return <div className="grid gap-3">
    <Button variant="danger" disabled={busy} onClick={() => setOpen(true)}>{label}</Button>
    <ConfirmDialog open={open} onCancel={() => setOpen(false)} title={`${label}?`}
      consequence="Future dispatches relying on this trust are blocked. This cannot be undone."
      confirmLabel={label} busy={busy} error={validationError || error || undefined}
      onConfirm={async (reason) => { if (reason.length < 3 || reason.length > 500) { setValidationError("Use a reason between 3 and 500 characters."); return; } setValidationError(""); await run(path, { request_id: requestId("revoke"), reason }); }} />
    {open ? <p className="text-xs text-(--muted)">Use a reason between 3 and 500 characters.</p> : null}
  </div>;
}
function VersionRow({ pkg, version, role, installed }: {
  pkg: CommunityPackage; version: CommunityPackageVersion; role: OperatorRole; installed: boolean;
}) {
  const admin = role === "admin";
  return <article className="bg-(--paper)">
    <header><code>v{version.version}</code><StatusBadge tone={version.state === "approved" ? "ok" : version.state === "submitted" ? "warn" : "crit"}>
      {version.state === "approved" ? "Approved" : version.state === "submitted" ? "Needs review" : version.state === "rejected" ? "Rejected" : version.state === "revoked" ? "Revoked" : "Blocked"}</StatusBadge><small>Submitted by {version.submitted_by} · {formatScriptTimestamp(version.submitted_at)}</small></header>
    <dl>
      <div><dt>Signer key</dt><dd><code>{version.signing_key_id}</code> <code title={version.signing_key_fingerprint}>{short(version.signing_key_fingerprint)}</code></dd></div>
      <div><dt>Manifest SHA-256</dt><dd><code title={version.manifest_sha256}>{short(version.manifest_sha256)}</code></dd></div>
      <div><dt>Content SHA-256</dt><dd><code title={version.content_sha256}>{short(version.content_sha256)}</code> ({version.content_bytes} bytes)</dd></div>
      {version.moderation ? <div><dt>Moderation</dt><dd>{version.moderation.state} by {version.moderation.moderated_by}</dd></div> : null}
    </dl>
    <Capabilities values={version.capabilities} escalation={version.capability_escalation} />
    {admin && version.state === "submitted" ? <ModerationForm pkg={pkg} version={version} /> : null}
    {admin && version.state === "approved" && !installed ? <InstallForm pkg={pkg} version={version} /> : null}
    {admin && version.state !== "revoked" && version.state !== "blocked"
      ? <RevokeForm path={`packages/${encodeURIComponent(pkg.id)}/versions/${version.version}/revoke`} label="Revoke version" /> : null}
  </article>;
}

function InstallRow({ install, pkg, role }: { install: CommunityInstall; pkg: CommunityPackage | undefined; role: OperatorRole }) {
  const { busy, error, run } = useAction(); const [target, setTarget] = useState(""); const [accepted, setAccepted] = useState<string[]>([]);
  const candidates = (pkg?.versions ?? []).filter((item) => item.state === "approved" && item.version !== install.installed_version);
  const chosen = candidates.find((item) => item.version === target);
  const direction = chosen && compareSemver(chosen.version, install.installed_version) > 0 ? "update" : "rollback";
  return <article className="bg-(--paper)">
    <header><strong>{install.qualified_name}</strong><code>v{install.installed_version}</code>
      <small>Library version {install.library_version} · installed by {install.installed_by}</small></header>
    {role === "admin" && candidates.length ? <div className="grid gap-3">
      <label>Move to version<select value={target} onChange={(event) => { setTarget(event.target.value); setAccepted([]); }}>
        <option value="">Choose an approved version</option>
        {candidates.map((item) => <option key={item.id} value={item.version}>v{item.version}</option>)}</select></label>
      {chosen ? <><Capabilities values={chosen.capabilities} escalation={chosen.capability_escalation} />
        <CapabilityAcceptance capabilities={chosen.capabilities} accepted={accepted} onChange={setAccepted} />
        <div><button disabled={busy || !sameCapabilitySet(accepted, chosen.capabilities)}
          onClick={() => run(`installs/${encodeURIComponent(install.id)}/${direction}`, {
            version: chosen.version, accepted_capabilities: accepted, request_id: requestId(direction),
          })}>{direction === "update" ? "Update" : "Roll back"} to v{chosen.version}</button></div></> : null}
      {error ? <p role="alert">{error}</p> : null}
    </div> : null}
  </article>;
}

function SubmitPanel() {
  const { busy, error, run } = useAction(); const [raw, setRaw] = useState(""); const [parseError, setParseError] = useState("");
  function submit(event: React.FormEvent) {
    event.preventDefault(); setParseError("");
    let body: unknown;
    try { body = JSON.parse(raw); } catch { setParseError("Paste the JSON produced by sign_community_package.py."); return; }
    void run("submissions", body);
  }
  return <form className="grid gap-4 rounded-lg border border-(--line) bg-(--paper) p-5" onSubmit={submit}><header><span>Signed submission</span><h2>Submit a package version</h2></header>
    <div className="grid gap-4 sm:grid-cols-2"><label className="sm:col-span-2">Submission JSON <small>manifest, content, key_id, signature</small>
      <textarea value={raw} onChange={(event) => setRaw(event.target.value)} rows={8} spellCheck={false} /></label></div>
    {parseError || error ? <p role="alert">{parseError || error}</p> : null}
    <footer><button type="submit" disabled={busy || !raw.trim()}>{busy ? "Verifying…" : "Submit for moderation"}</button></footer></form>;
}

function PublisherAdmin({ publishers }: { publishers: CommunityPublisher[] }) {
  const create = useAction(); const key = useAction();
  const [slug, setSlug] = useState(""); const [name, setName] = useState("");
  const [publisherId, setPublisherId] = useState(""); const [keyId, setKeyId] = useState(""); const [pem, setPem] = useState("");
  return <section className="grid gap-4 rounded-lg border border-(--line) bg-(--paper) p-5"><header><span>Admin</span><h2>Publishers and signing keys</h2></header>
    <div className="grid gap-4 sm:grid-cols-2">
      <label>Namespace slug<input value={slug} onChange={(event) => setSlug(event.target.value)} maxLength={64} placeholder="acme" /></label>
      <label>Display name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} /></label>
    </div>
    {create.error ? <p role="alert">{create.error}</p> : null}
    <footer><button disabled={create.busy || !slug || !name} onClick={() => create.run("publishers", { slug, display_name: name })}>Register publisher</button></footer>
    <div className="grid gap-4 sm:grid-cols-2">
      <label>Publisher<select value={publisherId} onChange={(event) => setPublisherId(event.target.value)}>
        <option value="">Choose a publisher</option>
        {publishers.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.slug}</option>)}</select></label>
      <label>Key ID<input value={keyId} onChange={(event) => setKeyId(event.target.value)} maxLength={64} /></label>
      <label className="sm:col-span-2">Ed25519 public key (PEM)<textarea value={pem} onChange={(event) => setPem(event.target.value)} rows={4} spellCheck={false} /></label>
    </div>
    {key.error ? <p role="alert">{key.error}</p> : null}
    <footer><button disabled={key.busy || !publisherId || !keyId || !pem}
      onClick={() => key.run(`publishers/${encodeURIComponent(publisherId)}/keys`, { key_id: keyId, public_key_pem: pem })}>Register key</button></footer>
  </section>;
}

export function CommunityRepositoryView({ publishers, packages, installs, initialError, role }: Props) {
  const [search, setSearch] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const versions = packages?.flatMap((item) => item.versions) ?? [];
  const installedPackages = new Set(installs?.map((item) => item.package_id) ?? []);
  return <PageStack>
    <PageHeader breadcrumb={[{ label: "Automation" }, { label: "Community scripts" }]} title="Community scripts"
      description="Script packages from registered publishers. Installing a version adds it to the script library; it does not run it." actions={role !== "readonly" ? <Button variant="primary" onClick={() => setSubmitting(!submitting)}>Submit a package</Button> : null} />
    <StatRow>
      <StatTile icon={Store} label="Publishers" value={publishers?.length ?? "—"} />
      <StatTile icon={BadgeCheck} label="Approved versions" value={packages ? versions.filter((item) => item.state === "approved").length : "—"} />
      <StatTile icon={PackageCheck} label="Awaiting moderation" value={packages ? versions.filter((item) => item.state === "submitted").length : "—"} />
    </StatRow>
    <div className="grid gap-6 text-sm [&_article]:grid [&_article]:gap-3 [&_article]:rounded-lg [&_article]:border [&_article]:border-(--line) [&_article]:p-4 [&_header]:flex [&_header]:flex-wrap [&_header]:items-center [&_header]:gap-3 [&_h2]:text-base [&_h2]:font-semibold [&_small]:text-xs [&_small]:text-(--muted) [&_label]:grid [&_label]:gap-2 [&_input:not([type=checkbox])]:rounded-lg [&_input:not([type=checkbox])]:border [&_input:not([type=checkbox])]:border-(--line-strong) [&_input:not([type=checkbox])]:p-2 [&_textarea]:rounded-lg [&_textarea]:border [&_textarea]:border-(--line-strong) [&_textarea]:p-3 [&_select]:rounded-lg [&_select]:border [&_select]:border-(--line-strong) [&_select]:p-2 [&_button]:rounded-lg [&_button]:border [&_button]:border-(--line-strong) [&_button]:px-4 [&_button]:py-2 [&_button]:disabled:opacity-50 [&_button]:focus-visible:outline-2 [&_button]:focus-visible:outline-(--focus) [&_code]:font-(family-name:--font-data) [&_dd]:break-all">    {initialError ? <ErrorState title="Repository could not be loaded" body={initialError} /> : <>
      {role !== "readonly" && submitting ? <SubmitPanel /> : null}
      {role === "admin" && publishers ? <PublisherAdmin publishers={publishers} /> : null}
      <section className="grid gap-4 rounded-lg border border-(--line) bg-(--paper) p-5"><header><div><span>Catalog</span><h2>{packages?.length ?? 0} packages</h2></div><small>publisher/name · immutable versions</small></header>
        <FilterBar><SearchField label="Search packages" value={search} onChange={(event) => setSearch(event.target.value)} /></FilterBar>{packages?.length ? packages.filter((pkg) => pkg.qualified_name.toLowerCase().includes(search.toLowerCase())).map((pkg) => <article key={pkg.id} className="bg-(--paper)">
          <header><strong>{pkg.qualified_name}</strong>{pkg.publisher_status === "revoked" ? <StatusBadge tone="crit">Revoked</StatusBadge> : null}</header>
          {pkg.versions.map((version) => <VersionRow key={version.id} pkg={pkg} version={version} role={role} installed={installedPackages.has(pkg.id)} />)}
        </article>) : <p className="text-(--muted)">No packages have been submitted.</p>}
      </section>
      <section className="grid gap-4 rounded-lg border border-(--line) bg-(--paper) p-5"><header><div><span>Installed</span><h2>{installs?.length ?? 0} installs</h2></div><small>Updates and rollbacks append library versions</small></header>
        {installs?.length ? installs.map((install) => <InstallRow key={install.id} install={install} role={role}
          pkg={packages?.find((item) => item.id === install.package_id)} />) : <p className="text-(--muted)">No community packages are installed.</p>}
      </section>
      <section className="grid gap-4 rounded-lg border border-(--line) bg-(--paper) p-5"><header><div><span>Publishers</span><h2>Registered namespaces</h2></div><small>Keys are bound to one namespace forever</small></header>
        {publishers?.length ? publishers.map((publisher) => <article key={publisher.id} className="bg-(--paper)">
          <header><strong>{publisher.slug}</strong><span>{publisher.display_name}</span>
            <StatusBadge tone={publisher.status === "active" ? "ok" : "crit"}>{publisher.status === "active" ? "Active" : "Revoked"}</StatusBadge></header>
          <ul>{publisher.keys.map((key) => <li key={key.key_id}><KeyRound size={14} /><code>{key.key_id}</code>
            <code title={key.fingerprint}>{short(key.fingerprint)}</code><span>{key.status}</span>
            {role === "admin" && key.status === "active" && publisher.status === "active"
              ? <RevokeForm path={`publishers/${encodeURIComponent(publisher.id)}/keys/${encodeURIComponent(key.key_id)}/revoke`} label="Revoke key" /> : null}</li>)}</ul>
          {role === "admin" && publisher.status === "active"
            ? <RevokeForm path={`publishers/${encodeURIComponent(publisher.id)}/revoke`} label="Revoke publisher" /> : null}
        </article>) : <p className="text-(--muted)">No publishers are registered.</p>}
      </section>
    </>}
  </div></PageStack>;
}




