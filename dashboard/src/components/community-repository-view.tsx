// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { BadgeCheck, KeyRound, PackageCheck, ShieldAlert, Store } from "lucide-react";
import { useState } from "react";
import {
  compareSemver,
  effectCapabilitiesOf,
  sameCapabilitySet,
  versionStateLabel,
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
  return <ul className="community-caps" aria-label="Declared capabilities">{values.map((item) =>
    <li key={item} className={escalation.includes(item) ? "escalated" : effectCapabilitiesOf([item]).length ? "effect" : ""}>
      {item}{escalation.includes(item) ? " (new)" : ""}</li>)}</ul>;
}

function CapabilityAcceptance({ capabilities, accepted, onChange }: {
  capabilities: string[]; accepted: string[]; onChange: (next: string[]) => void;
}) {
  return <fieldset className="community-accept"><legend>Accept every declared capability</legend>
    {capabilities.map((item) => <label key={item}><input type="checkbox" checked={accepted.includes(item)}
      onChange={(event) => onChange(event.target.checked ? [...accepted, item] : accepted.filter((value) => value !== item))} />{item}</label>)}
  </fieldset>;
}

function ModerationForm({ pkg, version }: { pkg: CommunityPackage; version: CommunityPackageVersion }) {
  const { busy, error, run } = useAction(); const [reason, setReason] = useState(""); const [ack, setAck] = useState(false);
  const path = `packages/${encodeURIComponent(pkg.id)}/versions/${version.version}/moderation`;
  const needsAck = version.capability_escalation.length > 0;
  return <div className="community-action">
    <label>Moderation reason<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} /></label>
    {needsAck ? <label className="community-ack"><input type="checkbox" checked={ack} onChange={(event) => setAck(event.target.checked)} />
      I reviewed the added capabilities: {version.capability_escalation.join(", ")}</label> : null}
    <div><button disabled={busy || reason.trim().length < 3 || needsAck && !ack}
      onClick={() => run(path, { state: "approved", reason, acknowledge_capability_escalation: ack })}>Approve</button>
    <button className="danger" disabled={busy || reason.trim().length < 3}
      onClick={() => run(path, { state: "rejected", reason })}>Reject</button></div>
    {error ? <p role="alert">{error}</p> : null}
  </div>;
}

function InstallForm({ pkg, version }: { pkg: CommunityPackage; version: CommunityPackageVersion }) {
  const { busy, error, run } = useAction(); const [accepted, setAccepted] = useState<string[]>([]);
  const ready = sameCapabilitySet(accepted, version.capabilities);
  return <div className="community-action">
    <CapabilityAcceptance capabilities={version.capabilities} accepted={accepted} onChange={setAccepted} />
    <div><button disabled={busy || !ready} onClick={() => run("installs", {
      package_id: pkg.id, version: version.version, accepted_capabilities: accepted, request_id: requestId("install"),
    })}>Install into script library</button></div>
    {error ? <p role="alert">{error}</p> : null}
  </div>;
}

function RevokeForm({ path, label }: { path: string; label: string }) {
  const { busy, error, run } = useAction(); const [reason, setReason] = useState("");
  return <div className="community-action">
    <label>{label} reason<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} /></label>
    <div><button className="danger" disabled={busy || reason.trim().length < 3}
      onClick={() => run(path, { request_id: requestId("revoke"), reason })}>{label}</button></div>
    {error ? <p role="alert">{error}</p> : null}
  </div>;
}

function VersionRow({ pkg, version, role, installed }: {
  pkg: CommunityPackage; version: CommunityPackageVersion; role: OperatorRole; installed: boolean;
}) {
  const admin = role === "admin";
  return <article className="community-version">
    <header><code>v{version.version}</code><span className={`script-state ${version.state === "approved" ? "approved" : version.state === "submitted" ? "" : "rejected"}`}>
      {versionStateLabel(version.state)}</span><small>Submitted by {version.submitted_by} · {formatScriptTimestamp(version.submitted_at)}</small></header>
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
  return <article className="community-install">
    <header><strong>{install.qualified_name}</strong><code>v{install.installed_version}</code>
      <small>Library version {install.library_version} · installed by {install.installed_by}</small></header>
    {role === "admin" && candidates.length ? <div className="community-action">
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
  return <form className="script-create-panel" onSubmit={submit}><header><span>Signed submission</span><h2>Submit a package version</h2></header>
    <div className="script-form-grid"><label className="wide">Submission JSON <small>manifest, content, key_id, signature</small>
      <textarea value={raw} onChange={(event) => setRaw(event.target.value)} rows={8} spellCheck={false} /></label></div>
    {parseError || error ? <p role="alert">{parseError || error}</p> : null}
    <footer><button type="submit" disabled={busy || !raw.trim()}>{busy ? "Verifying…" : "Submit for moderation"}</button></footer></form>;
}

function PublisherAdmin({ publishers }: { publishers: CommunityPublisher[] }) {
  const create = useAction(); const key = useAction();
  const [slug, setSlug] = useState(""); const [name, setName] = useState("");
  const [publisherId, setPublisherId] = useState(""); const [keyId, setKeyId] = useState(""); const [pem, setPem] = useState("");
  return <section className="script-create-panel"><header><span>Admin</span><h2>Publishers and signing keys</h2></header>
    <div className="script-form-grid">
      <label>Namespace slug<input value={slug} onChange={(event) => setSlug(event.target.value)} maxLength={64} placeholder="acme" /></label>
      <label>Display name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} /></label>
    </div>
    {create.error ? <p role="alert">{create.error}</p> : null}
    <footer><button disabled={create.busy || !slug || !name} onClick={() => create.run("publishers", { slug, display_name: name })}>Register publisher</button></footer>
    <div className="script-form-grid">
      <label>Publisher<select value={publisherId} onChange={(event) => setPublisherId(event.target.value)}>
        <option value="">Choose a publisher</option>
        {publishers.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.slug}</option>)}</select></label>
      <label>Key ID<input value={keyId} onChange={(event) => setKeyId(event.target.value)} maxLength={64} /></label>
      <label className="wide">Ed25519 public key (PEM)<textarea value={pem} onChange={(event) => setPem(event.target.value)} rows={4} spellCheck={false} /></label>
    </div>
    {key.error ? <p role="alert">{key.error}</p> : null}
    <footer><button disabled={key.busy || !publisherId || !keyId || !pem}
      onClick={() => key.run(`publishers/${encodeURIComponent(publisherId)}/keys`, { key_id: keyId, public_key_pem: pem })}>Register key</button></footer>
  </section>;
}

export function CommunityRepositoryView({ publishers, packages, installs, initialError, role }: Props) {
  const versions = packages?.flatMap((item) => item.versions) ?? [];
  const installedPackages = new Set(installs?.map((item) => item.package_id) ?? []);
  return <>
    <header className="script-page-head"><div><span>Controlled automation</span><h1>Community scripts</h1>
      <p>Signed, moderated script packages from registered publishers. Installing an approved version adds it to the script library; it never grants execution permission.</p></div>
      {role === "readonly" ? <span className="script-role-note">View only</span> : null}</header>
    <section className="script-custody-banner"><ShieldAlert size={23} /><div><strong>Trust is re-checked on every run</strong>
      <span>Publisher key → signed manifest → content digest → moderation → install. Revoking a publisher, key, or version blocks the next dispatch.</span></div></section>
    <section className="script-stats">
      <div><Store /><span><small>Publishers</small><strong>{publishers?.length ?? "—"}</strong></span></div>
      <div><BadgeCheck /><span><small>Approved versions</small><strong>{versions.filter((item) => item.state === "approved").length}</strong></span></div>
      <div><PackageCheck /><span><small>Awaiting moderation</small><strong>{versions.filter((item) => item.state === "submitted").length}</strong></span></div>
    </section>
    {initialError ? <section className="script-unavailable" role="alert"><span>Unavailable</span><h2>Repository could not be loaded</h2><p>{initialError}</p></section> : <>
      {role !== "readonly" ? <SubmitPanel /> : null}
      {role === "admin" && publishers ? <PublisherAdmin publishers={publishers} /> : null}
      <section className="script-register"><header><div><span>Catalog</span><h2>{packages?.length ?? 0} packages</h2></div><small>publisher/name · immutable versions</small></header>
        {packages?.length ? packages.map((pkg) => <article key={pkg.id} className="community-package">
          <header><strong>{pkg.qualified_name}</strong>{pkg.publisher_status === "revoked" ? <span className="script-state rejected">Publisher revoked</span> : null}</header>
          {pkg.versions.map((version) => <VersionRow key={version.id} pkg={pkg} version={version} role={role} installed={installedPackages.has(pkg.id)} />)}
        </article>) : <p className="community-empty">No packages have been submitted.</p>}
      </section>
      <section className="script-register"><header><div><span>Installed</span><h2>{installs?.length ?? 0} installs</h2></div><small>Updates and rollbacks append library versions</small></header>
        {installs?.length ? installs.map((install) => <InstallRow key={install.id} install={install} role={role}
          pkg={packages?.find((item) => item.id === install.package_id)} />) : <p className="community-empty">No community packages are installed.</p>}
      </section>
      <section className="script-register"><header><div><span>Publishers</span><h2>Registered namespaces</h2></div><small>Keys are bound to one namespace forever</small></header>
        {publishers?.length ? publishers.map((publisher) => <article key={publisher.id} className="community-publisher">
          <header><strong>{publisher.slug}</strong><span>{publisher.display_name}</span>
            <span className={`script-state ${publisher.status === "active" ? "approved" : "rejected"}`}>{publisher.status}</span></header>
          <ul>{publisher.keys.map((key) => <li key={key.key_id}><KeyRound size={14} /><code>{key.key_id}</code>
            <code title={key.fingerprint}>{short(key.fingerprint)}</code><span>{key.status}</span>
            {role === "admin" && key.status === "active" && publisher.status === "active"
              ? <RevokeForm path={`publishers/${encodeURIComponent(publisher.id)}/keys/${encodeURIComponent(key.key_id)}/revoke`} label="Revoke key" /> : null}</li>)}</ul>
          {role === "admin" && publisher.status === "active"
            ? <RevokeForm path={`publishers/${encodeURIComponent(publisher.id)}/revoke`} label="Revoke publisher" /> : null}
        </article>) : <p className="community-empty">No publishers are registered.</p>}
      </section>
    </>}
  </>;
}
