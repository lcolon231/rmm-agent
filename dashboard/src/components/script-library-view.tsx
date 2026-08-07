// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { FileCode2, Fingerprint, Library, Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { formatScriptTimestamp, scriptState, type OperatorRole, type ScriptList } from "@/lib/script-library-core";
import { parameterPayload, ScriptParameterEditor, type ParameterDraft } from "@/components/script-parameter-editor";

export function ScriptLibraryView({ initialList, initialError, role }: { initialList: ScriptList | null; initialError: string; role: OperatorRole }) {
  const [open, setOpen] = useState(false); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const [parameters, setParameters] = useState<ParameterDraft[]>([]);
  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); const data = new FormData(event.currentTarget);
    try { const payload = { name: data.get("name"), language: data.get("language"), content: data.get("content"),
      description: data.get("description") || undefined, tags: String(data.get("tags") ?? "").split(",").map((v) => v.trim()).filter(Boolean),
      supported_platforms: data.getAll("platform"), parameters: parameterPayload(parameters) };
      const response = await fetch("/api/scripts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const body = await response.json(); if (!response.ok || !body.script) throw new Error(body.error ?? "Creation was not confirmed.");
      window.location.assign(`/scripts/${encodeURIComponent(body.script.id)}`);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Creation was not confirmed."); setBusy(false); }
  }
  const approved = initialList?.items.filter((item) => scriptState(item) === "approved").length ?? 0;
  const drafts = initialList?.items.filter((item) => scriptState(item) === "draft").length ?? 0;
  return <>
    <header className="script-page-head"><div><span>Controlled automation</span><h1>Script library</h1><p>Immutable, reviewable source artifacts for technicians. Library access never grants execution permission.</p></div>
      {role !== "readonly" ? <button onClick={() => setOpen((value) => !value)}><Plus size={17} />New script</button> : <span className="script-role-note">View only</span>}</header>
    <section className="script-custody-banner"><Fingerprint size={23} /><div><strong>Content custody is visible at every step</strong><span>Canonical content → SHA-256 digest → final review. A changed script always becomes a new version.</span></div></section>
    <section className="script-stats"><div><Library /><span><small>Library records</small><strong>{initialList?.total ?? "—"}</strong></span></div><div><ShieldCheck /><span><small>Latest approved</small><strong>{approved}</strong></span></div><div><FileCode2 /><span><small>Draft review</small><strong>{drafts}</strong></span></div></section>
    {open ? <form className="script-create-panel" onSubmit={create}><header><span>Immutable version 1</span><h2>Register a script</h2></header><div className="script-form-grid">
      <label>Name<input name="name" required maxLength={200} /></label><label>Language<select name="language"><option value="powershell">PowerShell</option><option value="shell">POSIX shell</option></select></label>
      <label className="wide">Description<input name="description" maxLength={2000} /></label><label>Tags <small>comma-separated</small><input name="tags" placeholder="remediation, windows.service" /></label>
      <fieldset><legend>Supported platforms</legend><label><input type="checkbox" name="platform" value="windows" defaultChecked />Windows</label><label><input type="checkbox" name="platform" value="linux" />Linux</label><label><input type="checkbox" name="platform" value="macos" />macOS</label></fieldset>
      <label className="wide">Script content<textarea name="content" required rows={10} maxLength={57344} spellCheck={false} /></label><ScriptParameterEditor value={parameters} onChange={setParameters} /></div>
      {error ? <p role="alert">{error}</p> : null}<footer><button type="button" onClick={() => setOpen(false)}>Cancel</button><button disabled={busy} type="submit">{busy ? "Registering…" : "Register immutable draft"}</button></footer></form> : null}
    {initialError ? <section className="script-unavailable" role="alert"><span>Unavailable</span><h2>Library could not be loaded</h2><p>{initialError}</p></section>
      : initialList?.items.length === 0 ? <section className="script-unavailable"><span>Ready</span><h2>No scripts registered</h2><p>An operator can register the first immutable draft.</p></section>
      : <section className="script-register"><header><div><span>Custody register</span><h2>{initialList?.items.length} visible scripts</h2></div><small>Latest version state</small></header>
        <div className="script-register-list">{initialList?.items.map((script) => { const state = scriptState(script); return <Link href={`/scripts/${encodeURIComponent(script.id)}`} key={script.id} className="script-register-row"><span className={`script-state-dot ${state}`} /><div><strong>{script.name}</strong><small>{script.latest.description ?? "No description"}</small></div><span className="script-language">{script.latest.language}</span><code>v{script.latest_version}</code><code>{script.latest.content_sha256.slice(0, 12)}…</code><span className={`script-state ${state}`}>{state}</span><time>{formatScriptTimestamp(script.updated_at)}</time></Link>; })}</div></section>}
  </>;
}
