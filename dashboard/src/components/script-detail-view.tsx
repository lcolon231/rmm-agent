// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { Archive, Check, Copy, FilePlus2, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";

import { scriptBadge } from "@/lib/automation-presentation-core";
import { draftsFromParameters, parameterPayload, ScriptParameterEditor } from "@/components/script-parameter-editor";
import { languageLabel, platformsLabel } from "@/components/script-library-view";
import {
  formatScriptTimestamp, scriptParameterValueSetFromUnknown, scriptState,
  type OperatorRole, type ScriptItem, type ScriptParameter, type ScriptParameterValueSet,
} from "@/lib/script-library-core";

import { PageHeader, PageStack } from "./shell/page-header";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { cx } from "./ui/cx";
import { CodeBlock, DefinitionList } from "./ui/drawer";
import { Input, Select, Textarea } from "./ui/field";
import { cardClass } from "./ui/stat-tile";
import { StatusBadge, toneStyles, type StatusTone } from "./ui/status-badge";
import { TabNav } from "./ui/tab-nav";

export type ScriptDetailTab = "source" | "parameters" | "versions";

type Dialog = "approved" | "rejected" | "deprecate" | null;

const KIND_LABEL: Record<string, string> = { string: "Text", number: "Number", boolean: "Yes or no", choice: "Choice", secret: "Secret" };

function Card({ title, sub, action, children }: { title: string; sub?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden")}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
        <div className="grid gap-0.5">
          <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
          {sub ? <p className="m-0 text-xs text-(--muted)">{sub}</p> : null}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function Note({ tone, title, children }: { tone: StatusTone; title: string; children: ReactNode }) {
  const { surface, text, icon: Icon } = toneStyles[tone];
  return (
    <div role="status" className={cx("flex items-start gap-3 rounded-[10px] px-5 py-4", surface)}>
      <Icon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", text)} />
      <p className="m-0 grid gap-0.5">
        <span className={cx("font-semibold", text)}>{title}</span>
        <span className="text-(--slate)">{children}</span>
      </p>
    </div>
  );
}

function ParameterInput({ parameter }: { parameter: ScriptParameter }) {
  const hint = `${KIND_LABEL[parameter.kind] ?? parameter.kind} · ${parameter.required ? "required" : parameter.has_default ? `default: ${String(parameter.default_value)}` : "optional"}`;
  if (parameter.kind === "boolean") return <Select label={parameter.label} hint={hint} name={parameter.key} required={parameter.required}><option value="">{parameter.has_default ? "Use default" : "Choose…"}</option><option value="true">Yes</option><option value="false">No</option></Select>;
  if (parameter.kind === "choice") return <Select label={parameter.label} hint={hint} name={parameter.key} required={parameter.required}><option value="">{parameter.has_default ? "Use default" : "Choose…"}</option>{parameter.choices?.map((choice) => <option key={choice} value={choice}>{choice}</option>)}</Select>;
  return <Input label={parameter.label} hint={hint} name={parameter.key} type={parameter.kind === "secret" ? "password" : parameter.kind === "number" ? "number" : "text"} required={parameter.required} minLength={parameter.min_length ?? undefined} maxLength={parameter.max_length ?? undefined} min={parameter.minimum ?? undefined} max={parameter.maximum ?? undefined} autoComplete={parameter.kind === "secret" ? "new-password" : undefined} placeholder={parameter.has_default ? "Use version default" : undefined} />;
}

function StateNote({ script }: { script: ScriptItem }) {
  const review = script.latest.review;
  if (script.deprecated_at) {
    return <Note tone="off" title="Disabled">Retired by {script.deprecated_by ?? "an admin"} on {formatScriptTimestamp(script.deprecated_at)}. It is kept for the record, and no new versions or run values can be added.</Note>;
  }
  if (!review) {
    return <Note tone="warn" title="Needs review">An admin must review this version. Until it is approved, values for its parameters cannot be prepared for a run. Read the source below before you approve.</Note>;
  }
  if (review.state === "rejected") {
    return <Note tone="crit" title="Rejected">Rejected by {review.reviewed_by} on {formatScriptTimestamp(review.created_at)}. A review is final, so a fix is saved as a new version.</Note>;
  }
  return <Note tone="ok" title="Approved">Approved by {review.reviewed_by} on {formatScriptTimestamp(review.created_at)}. This version can never be changed.</Note>;
}

export function ScriptDetailView({ initialScript, latestContent, role, tab = "source" }: { initialScript: ScriptItem; latestContent: string; role: OperatorRole; tab?: ScriptDetailTab }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [dialogError, setDialogError] = useState("");
  const [showVersion, setShowVersion] = useState(false);
  const latest = initialScript.latest;
  const state = scriptState(initialScript);
  const badge = scriptBadge(state);
  const [parameters, setParameters] = useState(() => draftsFromParameters(latest.parameters));
  const [prepared, setPrepared] = useState<ScriptParameterValueSet | null>(null);
  const base = `/scripts/${encodeURIComponent(initialScript.id)}`;
  const canReview = role === "admin" && !latest.review && !initialScript.deprecated_at;
  const canVersion = role !== "readonly" && !initialScript.deprecated_at;

  async function mutate(path: string, payload: unknown): Promise<string | null> {
    setBusy(true); setError("");
    try {
      const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "The change was not confirmed.");
      router.refresh();
      return null;
    } catch (caught) {
      return caught instanceof Error ? caught.message : "The change was not confirmed.";
    } finally { setBusy(false); }
  }

  async function addVersion(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    try {
      const failure = await mutate(`/api/scripts/${encodeURIComponent(initialScript.id)}/versions`, {
        language: data.get("language"), content: data.get("content"),
        description: data.get("description") || undefined,
        tags: String(data.get("tags") ?? "").split(",").map((value) => value.trim()).filter(Boolean),
        supported_platforms: data.getAll("platform"), parameters: parameterPayload(parameters),
      });
      if (failure) setError(failure);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Parameter definitions are invalid."); }
  }

  async function prepareValues(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setPrepared(null);
    const form = event.currentTarget; const data = new FormData(form);
    const values: Record<string, string | number | boolean> = {};
    for (const parameter of latest.parameters) {
      const raw = data.get(parameter.key); if (raw === null || raw === "") continue;
      values[parameter.key] = parameter.kind === "number" ? Number(raw)
        : parameter.kind === "boolean" ? raw === "true" : String(raw);
    }
    try {
      const response = await fetch(`/api/scripts/${encodeURIComponent(initialScript.id)}/versions/${latest.version}/parameter-value-sets`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: crypto.randomUUID(), values }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Parameter values were not prepared.");
      const evidence = scriptParameterValueSetFromUnknown(body.parameter_set);
      if (!evidence) throw new Error("The service returned invalid parameter evidence.");
      setPrepared(evidence); form.reset();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Parameter values were not prepared.");
    } finally { setBusy(false); }
  }

  async function confirm(reason: string) {
    setDialogError("");
    const failure = dialog === "deprecate"
      ? await mutate(`/api/scripts/${encodeURIComponent(initialScript.id)}/deprecate`, { expected_record_version: initialScript.record_version, request_id: crypto.randomUUID(), reason })
      : await mutate(`/api/scripts/${encodeURIComponent(initialScript.id)}/versions/${latest.version}/review`, { state: dialog, reason });
    if (failure) setDialogError(`${failure} Nothing was changed.`);
    else setDialog(null);
  }

  const versionForm = showVersion ? (
    <Card title={`New version ${initialScript.latest_version + 1}`} sub="The current version stays as it is. The new version waits for an admin to review it.">
      <form onSubmit={addVersion}>
        <div className="grid gap-4 px-5 py-5">
          <div className="grid gap-4 min-[720px]:grid-cols-2">
            <Select label="Language" name="language" defaultValue={latest.language}><option value="powershell">PowerShell</option><option value="shell">Shell</option></Select>
            <Input label="Tags" name="tags" hint="Separate with commas" defaultValue={latest.tags.join(", ")} />
          </div>
          <Input label="Description" name="description" maxLength={2000} defaultValue={latest.description ?? ""} />
          <fieldset className="m-0 flex flex-wrap gap-x-6 gap-y-2 border-0 p-0">
            <legend className="mb-1.5 text-[13px] font-semibold text-(--slate)">Runs on</legend>
            {(["windows", "linux", "macos"] as const).map((platform) => <label key={platform} className="flex items-center gap-2 text-sm"><input type="checkbox" name="platform" value={platform} defaultChecked={latest.supported_platforms.includes(platform)} />{platformsLabel([platform])}</label>)}
          </fieldset>
          <Textarea label="Script" name="content" required rows={10} maxLength={57344} defaultValue={latestContent} spellCheck={false} className="font-(family-name:--font-data) text-[13px]" />
          <ScriptParameterEditor value={parameters} onChange={setParameters} />
        </div>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-(--line) px-5 py-4">
          <Button onClick={() => setShowVersion(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save new version"}</Button>
        </footer>
      </form>
    </Card>
  ) : null;

  const newVersionButton = canVersion
    ? <Button icon={FilePlus2} aria-expanded={showVersion} onClick={() => setShowVersion((value) => !value)} variant={canReview ? "secondary" : "primary"}>New version</Button>
    : null;

  const sourceTab = (
    <>
      <StateNote script={initialScript} />
      <Card
        title="Source (read-only)"
        sub={`Version ${latest.version} · ${languageLabel(latest.language)}`}
        action={<Button variant="quiet" size="compact" icon={Copy} onClick={() => navigator.clipboard.writeText(latestContent)}>Copy</Button>}
      >
        <div className="p-5"><CodeBlock label={`Source of version ${latest.version}`}>{latestContent}</CodeBlock></div>
      </Card>
      <Card title="Fingerprint" sub="The SHA-256 of the exact source above. Any change gives a different fingerprint.">
        <div className="px-5 py-4">
          <DefinitionList items={[
            { term: "Version", value: `v${latest.version}` },
            { term: "SHA-256", value: <span className="font-(family-name:--font-data) text-[13px] break-all">{latest.content_sha256}</span> },
            { term: "Size", value: `${latest.content_bytes.toLocaleString()} bytes` },
            { term: "Language", value: languageLabel(latest.language) },
            { term: "Runs on", value: platformsLabel(latest.supported_platforms) },
          ]} />
        </div>
      </Card>
    </>
  );

  const parametersTab = (
    <>
      <Card title="Parameters" sub={`${latest.parameters.length} parameter${latest.parameters.length === 1 ? "" : "s"} saved with version ${latest.version}. The script reads each one as NL_PARAM_Key.`}>
        {latest.parameters.length === 0 ? <p className="m-0 px-5 py-4 text-sm text-(--muted)">This version does not ask for any values.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-left text-sm">
              <caption className="sr-only">Parameters</caption>
              <thead className="bg-(--fog)"><tr>{["Name", "Type", "Required", "Default", "What it is for"].map((heading) => <th key={heading} scope="col" className="px-5 py-2.5 text-xs font-semibold text-(--muted)">{heading}</th>)}</tr></thead>
              <tbody>
                {latest.parameters.map((parameter) => (
                  <tr key={parameter.key} className="border-t border-(--line) text-(--slate)">
                    <td className="px-5 py-3"><PrimaryParam parameter={parameter} /></td>
                    <td className="px-5 py-3">{KIND_LABEL[parameter.kind] ?? parameter.kind}</td>
                    <td className="px-5 py-3">{parameter.required ? "Required" : "Optional"}</td>
                    <td className="px-5 py-3">{parameter.kind === "secret" ? "Not allowed for secrets" : parameter.has_default ? <span className="font-(family-name:--font-data) text-[13px]">{String(parameter.default_value)}</span> : <span className="text-(--muted)">—</span>}</td>
                    <td className="px-5 py-3">{parameter.description ?? <span className="text-(--muted)">No description</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {role !== "readonly" && state === "approved" && latest.parameters.length > 0 ? (
        <Card title="Prepare values for a run" sub="Values are encrypted and expire after 24 hours. Secret values are never shown again.">
          <form onSubmit={prepareValues}>
            <div className="grid gap-4 px-5 py-5 min-[720px]:grid-cols-2">{latest.parameters.map((parameter) => <ParameterInput key={parameter.key} parameter={parameter} />)}</div>
            {prepared ? (
              <output className="mx-5 mb-4 flex items-start gap-3 rounded-lg bg-(--success-soft) px-4 py-3">
                <ShieldCheck size={18} aria-hidden="true" className="mt-0.5 shrink-0 text-(--success)" />
                <span className="grid gap-0.5"><strong className="text-(--success)">Values prepared</strong><span className="text-xs text-(--slate)">Set <span className="font-(family-name:--font-data)">{prepared.id.slice(0, 8)}</span> · expires {formatScriptTimestamp(prepared.expires_at)} · fingerprint <span className="font-(family-name:--font-data)">{prepared.values_fingerprint.slice(0, 12)}…</span></span></span>
              </output>
            ) : null}
            <footer className="flex justify-end border-t border-(--line) px-5 py-4"><Button type="submit" disabled={busy}>{busy ? "Encrypting…" : "Encrypt values for a run"}</Button></footer>
          </form>
        </Card>
      ) : null}
    </>
  );

  const versionsTab = (
    <Card title="Version ledger" sub="Newest first. A saved version is never overwritten." action={canReview ? newVersionButton : null}>
      <ol className="m-0 list-none p-0">
        {(initialScript.versions ?? [latest]).map((version) => {
          const versionBadge = scriptBadge(version.review?.state ?? "draft");
          return (
            <li key={version.id} className="grid gap-1.5 border-t border-(--line) px-5 py-4 first:border-t-0">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-semibold text-(--ink)">v{version.version}</span>
                <StatusBadge tone={versionBadge.tone}>{versionBadge.label}</StatusBadge>
                <span className="ml-auto text-xs text-(--muted)">{formatScriptTimestamp(version.created_at)}</span>
              </div>
              <p className="m-0 text-sm text-(--slate)">{version.description ?? "No description"}</p>
              <p className="m-0 text-xs text-(--muted)">
                Saved by <span className="font-(family-name:--font-data)">{version.created_by}</span> · {languageLabel(version.language)} · {version.parameters.length} parameter{version.parameters.length === 1 ? "" : "s"} · {version.content_bytes.toLocaleString()} bytes
                {version.review ? <> · {version.review.state === "approved" ? "Approved" : "Rejected"} by <span className="font-(family-name:--font-data)">{version.review.reviewed_by}</span> on {formatScriptTimestamp(version.review.created_at)}</> : null}
              </p>
              <p className="m-0 text-xs text-(--muted)">Fingerprint <span className="font-(family-name:--font-data) break-all">{version.content_sha256}</span></p>
            </li>
          );
        })}
      </ol>
    </Card>
  );

  const record: Array<[string, string]> = [
    [`Script added by ${initialScript.created_by}`, formatScriptTimestamp(initialScript.created_at)],
    ...(latest.version > 1 ? [[`Version ${latest.version} saved by ${latest.created_by}`, formatScriptTimestamp(latest.created_at)] as [string, string]] : []),
    ...(latest.review ? [[`Version ${latest.version} ${latest.review.state} by ${latest.review.reviewed_by}`, formatScriptTimestamp(latest.review.created_at)] as [string, string]] : []),
    ...(initialScript.deprecated_at ? [[`Retired by ${initialScript.deprecated_by ?? "an admin"}`, formatScriptTimestamp(initialScript.deprecated_at)] as [string, string]] : []),
  ];

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Automation" }, { label: "Script library", href: "/scripts" }, { label: initialScript.name }]}
        title={initialScript.name}
        status={<StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>}
        description={`${(latest.description ?? "No description").replace(/[.\s]+$/, "")}. A saved version can never be changed; a change becomes a new version.`}
        actions={canReview ? (
          <>
            <Button variant="danger" disabled={busy} onClick={() => { setDialogError(""); setDialog("rejected"); }}>Reject</Button>
            <Button variant="primary" icon={Check} disabled={busy} onClick={() => { setDialogError(""); setDialog("approved"); }}>Approve version</Button>
          </>
        ) : newVersionButton}
      />
      {error ? <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm text-(--red)">{error} Nothing was changed.</p> : null}
      <TabNav
        label="Script sections"
        tabs={[
          { label: "Source", href: base, current: tab === "source" },
          { label: "Parameters", href: `${base}?tab=parameters`, current: tab === "parameters" },
          { label: "Version ledger", href: `${base}?tab=versions`, current: tab === "versions" },
        ]}
      />
      <div className="grid grid-cols-1 items-start gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="grid min-w-0 gap-6">
          {versionForm}
          {tab === "parameters" ? parametersTab : tab === "versions" ? versionsTab : sourceTab}
        </div>
        <aside className="grid gap-6">
          <Card title="At a glance">
            <div className="px-5 py-4">
              <DefinitionList items={[
                { term: "State", value: <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge> },
                { term: "Version", value: `v${initialScript.latest_version}` },
                { term: "Language", value: languageLabel(latest.language) },
                { term: "Runs on", value: platformsLabel(latest.supported_platforms) },
                { term: "Fingerprint", value: <span title={latest.content_sha256} className="font-(family-name:--font-data) text-[13px]">{latest.content_sha256.slice(0, 12)}…</span> },
                { term: "Last change", value: formatScriptTimestamp(initialScript.updated_at) },
              ]} />
              {role === "readonly" ? <p className="m-0 mt-4 text-xs text-(--muted)">You have view-only access: you can read the source and its history.</p> : null}
              <p className="m-0 mt-4 text-xs text-(--muted)">Saving or reviewing a script does not run it on any device.</p>
            </div>
          </Card>
          <Card title="Record" sub="Who did what, and when">
            <ul className="m-0 list-none p-0">
              {record.map(([what, when]) => (
                <li key={what} className="flex flex-wrap justify-between gap-x-4 gap-y-0.5 border-t border-(--line) px-5 py-3 text-sm first:border-t-0">
                  <span className="text-(--slate)">{what}</span><span className="text-xs text-(--muted)">{when}</span>
                </li>
              ))}
            </ul>
          </Card>
          {role === "admin" && !initialScript.deprecated_at ? (
            <Card title="Retire this script" sub="Permanent. The script and its history are kept for the record.">
              <div className="p-5"><Button variant="danger" icon={Archive} disabled={busy} onClick={() => { setDialogError(""); setDialog("deprecate"); }}>Retire script</Button></div>
            </Card>
          ) : null}
        </aside>
      </div>
      <ConfirmDialog
        open={dialog === "approved"}
        onCancel={() => setDialog(null)}
        onConfirm={confirm}
        title={`Approve version ${latest.version}?`}
        consequence="Check the source and fingerprint first. A review is final and cannot be changed; after approval, operators can prepare values for a run."
        confirmLabel="Approve version"
        busy={busy}
        error={dialogError || undefined}
      />
      <ConfirmDialog
        open={dialog === "rejected"}
        onCancel={() => setDialog(null)}
        onConfirm={confirm}
        title="Reject this version?"
        consequence={`Version ${latest.version} is marked rejected. A review is final, so a fix has to be saved as a new version.`}
        confirmLabel="Reject version"
        busy={busy}
        error={dialogError || undefined}
      />
      <ConfirmDialog
        open={dialog === "deprecate"}
        onCancel={() => setDialog(null)}
        onConfirm={confirm}
        title={`Retire ${initialScript.name}?`}
        consequence="This cannot be undone. No new versions or run values can be added, and the script stays in the library as a record."
        confirmLabel="Retire script"
        busy={busy}
        error={dialogError || undefined}
      />
    </PageStack>
  );
}

function PrimaryParam({ parameter }: { parameter: ScriptParameter }) {
  return (
    <span className="grid gap-0.5">
      <span className="font-(family-name:--font-data) text-[13px] font-semibold text-(--ink)">{parameter.key}</span>
      <span className="text-xs text-(--muted)">{parameter.label}</span>
    </span>
  );
}
