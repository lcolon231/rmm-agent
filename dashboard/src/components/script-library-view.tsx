// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { Archive, CircleAlert, CircleCheck, Clock, FileCode2, Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { scriptBadge, sortScriptsByAttention, type ScriptStateKey } from "@/lib/automation-presentation-core";
import { formatScriptTimestamp, scriptState, type OperatorRole, type ScriptItem, type ScriptList } from "@/lib/script-library-core";
import { parameterPayload, ScriptParameterEditor, type ParameterDraft } from "@/components/script-parameter-editor";

import { PageHeader, PageStack } from "./shell/page-header";
import { Button, ButtonLink } from "./ui/button";
import { cx } from "./ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "./ui/data-table";
import { DefinitionList, Drawer } from "./ui/drawer";
import { Input, Select, Textarea } from "./ui/field";
import { FilterBar, FilterChip, SearchField } from "./ui/filter-bar";
import { cardClass, StatRow, StatTile } from "./ui/stat-tile";
import { EmptyState, ErrorState } from "./ui/states";
import { StatusBadge } from "./ui/status-badge";

type Filter = "all" | ScriptStateKey;

const CHIPS: Array<{ label: string; value: Filter }> = [
  { label: "All", value: "all" },
  { label: "Needs review", value: "draft" },
  { label: "Approved", value: "approved" },
  { label: "Rejected", value: "rejected" },
  { label: "Disabled", value: "deprecated" },
];

const LANGUAGE: Record<string, string> = { powershell: "PowerShell", shell: "Shell" };
const PLATFORM: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };

export function languageLabel(language: string) {
  return LANGUAGE[language] ?? language;
}

export function platformsLabel(platforms: readonly string[]) {
  return platforms.map((platform) => PLATFORM[platform] ?? platform).join(", ") || "None listed";
}

function shortHash(value: string) {
  return `${value.slice(0, 12)}…`;
}

function CreatePanel({ onClose }: { onClose: () => void }) {
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
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
  return (
    <section aria-label="New script" className={cx(cardClass, "overflow-hidden")}>
      <header className="grid gap-0.5 border-b border-(--line) px-5 py-4">
        <h2 className="m-0 text-base font-semibold text-(--ink)">New script</h2>
        <p className="m-0 text-xs text-(--muted)">It is saved as version 1 and waits for an admin to review it. Saving a script does not run it anywhere.</p>
      </header>
      <form onSubmit={create}>
        <div className="grid gap-4 px-5 py-5">
          <div className="grid gap-4 min-[720px]:grid-cols-2">
            <Input label="Name" name="name" required maxLength={200} />
            <Select label="Language" name="language"><option value="powershell">PowerShell</option><option value="shell">Shell</option></Select>
          </div>
          <Input label="Description" name="description" maxLength={2000} />
          <Input label="Tags" name="tags" hint="Separate with commas" placeholder="printing, windows" />
          <fieldset className="m-0 flex flex-wrap gap-x-6 gap-y-2 border-0 p-0">
            <legend className="mb-1.5 text-[13px] font-semibold text-(--slate)">Runs on</legend>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="platform" value="windows" defaultChecked />Windows</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="platform" value="linux" />Linux</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="platform" value="macos" />macOS</label>
          </fieldset>
          <Textarea label="Script" name="content" required rows={10} maxLength={57344} spellCheck={false} className="font-(family-name:--font-data) text-[13px]" />
          <ScriptParameterEditor value={parameters} onChange={setParameters} />
          {error ? <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm text-(--red)">{error} Nothing was saved.</p> : null}
        </div>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-(--line) px-5 py-4">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save for review"}</Button>
        </footer>
      </form>
    </section>
  );
}

function ScriptDrawer({ script, onClose }: { script: ScriptItem | null; onClose: () => void }) {
  if (!script) return null;
  const latest = script.latest;
  const badge = scriptBadge(scriptState(script));
  const review = latest.review;
  return (
    <Drawer
      open
      onClose={onClose}
      context="Script library"
      title={script.name}
      sub={latest.description ?? "No description"}
      record={review
        ? `Version ${latest.version} ${review.state} by ${review.reviewed_by} · ${formatScriptTimestamp(review.created_at)}`
        : `Version ${latest.version} saved by ${latest.created_by} · ${formatScriptTimestamp(latest.created_at)}`}
      footer={<ButtonLink href={`/scripts/${encodeURIComponent(script.id)}`} variant="primary">Open script</ButtonLink>}
    >
      <div><StatusBadge tone={badge.tone}>{badge.label}</StatusBadge></div>
      <DefinitionList
        items={[
          { term: "Version", value: `v${script.latest_version}` },
          { term: "Language", value: languageLabel(latest.language) },
          { term: "Runs on", value: platformsLabel(latest.supported_platforms) },
          { term: "Parameters", value: String(latest.parameters.length) },
          { term: "Fingerprint", value: <span className="font-(family-name:--font-data) text-[13px] break-all">{latest.content_sha256}</span> },
          { term: "Size", value: `${latest.content_bytes.toLocaleString()} bytes` },
          { term: "Last change", value: formatScriptTimestamp(script.updated_at) },
        ]}
      />
      <p className="m-0 text-xs text-(--muted)">Open the script to read its source and full version history.</p>
    </Drawer>
  );
}

export function ScriptLibraryView({ initialList, initialError, role }: { initialList: ScriptList | null; initialError: string; role: OperatorRole }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ScriptItem | null>(null);

  const items = initialList?.items ?? [];
  const count = (state: ScriptStateKey) => items.filter((item) => scriptState(item) === state).length;
  const partial = initialList !== null && initialList.total > items.length;
  const scope = partial ? `Of the first ${items.length} loaded` : undefined;
  const needle = search.trim().toLowerCase();
  const rows = sortScriptsByAttention(
    items.filter((item) => (filter === "all" || scriptState(item) === filter) && (!needle || item.name.toLowerCase().includes(needle))),
    scriptState,
  );

  const columns: Column<ScriptItem>[] = [
    { key: "script", header: "Script", cell: (item) => <PrimaryCell title={item.name} sub={item.latest.description ?? "No description"} /> },
    { key: "state", header: "State", cell: (item) => { const badge = scriptBadge(scriptState(item)); return <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>; } },
    { key: "language", header: "Language", cell: (item) => languageLabel(item.latest.language) },
    { key: "version", header: "Version", cell: (item) => `v${item.latest_version}` },
    { key: "fingerprint", header: "Fingerprint", cell: (item) => <span title={item.latest.content_sha256} className="font-(family-name:--font-data) text-[13px]">{shortHash(item.latest.content_sha256)}</span> },
    { key: "changed", header: "Last change", cell: (item) => <PrimaryCell title={formatScriptTimestamp(item.updated_at)} sub={<span className="font-(family-name:--font-data)">{item.latest.created_by}</span>} /> },
  ];

  const filtered = filter !== "all" || Boolean(needle);
  const state = initialError || initialList === null ? (
    <ErrorState title="The script library could not be loaded" body={initialError || "The library response could not be verified. No script records are shown."} onRetry={() => router.refresh()} />
  ) : rows.length === 0 ? (
    filtered
      ? <EmptyState title="No scripts match" body="Try a different name, or clear the filters." actionLabel="Clear filters" onAction={() => { setFilter("all"); setSearch(""); }} />
      : <EmptyState icon={FileCode2} title="No scripts yet" body="An operator can add the first script. It waits for an admin to review it." />
  ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Automation" }, { label: "Script library" }]}
        title="Script library"
        description="Scripts for client devices. An admin reviews each version, and a saved version can never be changed: a change becomes a new version."
        actions={role !== "readonly"
          ? <Button variant="primary" icon={Plus} aria-expanded={open} onClick={() => setOpen((value) => !value)}>New script</Button>
          : <span className="text-[13px] text-(--muted)">View only</span>}
      />
      <StatRow>
        <StatTile icon={CircleCheck} tone="ok" label="Approved" value={initialList ? count("approved") : "—"} sub={scope ?? "Reviewed by an admin"} />
        <StatTile icon={Clock} tone={initialList && count("draft") ? "warn" : "info"} label="Needs review" value={initialList ? count("draft") : "—"} sub={scope ?? "Waiting for an admin"} />
        <StatTile icon={CircleAlert} tone={initialList && count("rejected") ? "crit" : "info"} label="Rejected" value={initialList ? count("rejected") : "—"} sub={scope ?? "Latest version was rejected"} />
        <StatTile icon={Archive} tone="off" label="Disabled" value={initialList ? count("deprecated") : "—"} sub={scope ?? "Retired, kept for the record"} />
      </StatRow>
      {open ? <CreatePanel onClose={() => setOpen(false)} /> : null}
      <DataTable
        caption="Scripts"
        columns={columns}
        rows={rows}
        rowKey={(item) => item.id}
        rowLabel={(item) => `Preview ${item.name}`}
        onRowSelect={setSelected}
        state={state}
        filters={initialList ? (
          <FilterBar>
            <SearchField label="Search scripts by name" placeholder="Search by name" value={search} maxLength={100} onChange={(event) => setSearch(event.target.value)} />
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {CHIPS.map((chip) => (
                <FilterChip key={chip.value} selected={filter === chip.value} count={chip.value === "all" ? items.length : count(chip.value)} onClick={() => setFilter(chip.value)}>
                  {chip.label}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        ) : null}
        footer={initialList && rows.length > 0
          ? <TableFooter shown={rows.length} total={initialList.total} sortNote={partial ? "needs review first among those loaded" : "needs review first"} />
          : null}
      />
      <ScriptDrawer script={selected} onClose={() => setSelected(null)} />
    </PageStack>
  );
}
