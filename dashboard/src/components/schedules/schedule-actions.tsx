// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Pause, Play, Plus, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useRef, useState } from "react";

import type { ScheduledTaskItem, ScheduledTaskTargetType } from "@/lib/scheduled-tasks-core";
import { NO_SCHEDULE_SOURCES, schedulableScripts, type ScheduleSources } from "@/lib/schedule-form-core";
import { scriptVersionFromUnknown, type ScriptLanguage, type ScriptReviewState, type ScriptVersion } from "@/lib/script-library-core";

import { Button } from "../ui/button";
import { CodeBlock, Drawer } from "../ui/drawer";
import { Input, Select, Textarea } from "../ui/field";
import { ConfirmDialog } from "../ui/confirm-dialog";

/** Pause/resume, run now and delete for one schedule; shown in its drawer. */
export function ScheduleActions({ task, onDeleted }: { task: ScheduledTaskItem; onDeleted?: () => void }) {
  const router = useRouter();
  const [toggling, setToggling] = useState(false);
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const handleToggle = async () => {
    setToggling(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/schedules/${task.id}/toggle`, { method: "POST" });
      if (!res.ok) throw new Error("The schedule was not changed.");
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setMessage(error.message || "The schedule was not changed.");
    } finally {
      setToggling(false);
    }
  };

  const handleRunNow = async () => {
    setRunning(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/schedules/${task.id}/run-now`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "The schedule did not run. Nothing was sent.");
      setMessage(`Sent to ${data.dispatched} device${data.dispatched === 1 ? "" : "s"}.`);
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setMessage(error.message || "The schedule did not run. Nothing was sent.");
    } finally {
      setRunning(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/schedules/${task.id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("The schedule was not deleted.");
      setConfirming(false);
      onDeleted?.();
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setConfirming(false);
      setMessage(error.message || "The schedule was not deleted.");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="grid w-full gap-3">
      {message ? <p role="status" className="m-0 text-sm text-(--slate)">{message}</p> : null}
      <div className="flex flex-wrap gap-2">
        <Button icon={Play} disabled={running || !task.enabled} onClick={handleRunNow}>Run now</Button>
        <Button icon={task.enabled ? Pause : Play} disabled={toggling} onClick={handleToggle}>{task.enabled ? "Pause schedule" : "Resume schedule"}</Button>
        <Button variant="danger" icon={Trash2} disabled={deleting} onClick={() => setConfirming(true)}>Delete</Button>
      </div>
      {confirming ? <ConfirmDialog open title={`Delete ${task.name}?`} consequence="Future runs stop. Existing task records remain. This cannot be undone. The reason entered here is not sent by this API." confirmLabel="Delete schedule" busy={deleting} onCancel={() => setConfirming(false)} onConfirm={handleDelete} /> : null}
    </div>
  );
}

type Source = "library" | "custom";

/** The picked library script, while its version body loads and once it has. */
type Picked = { scriptId: string } & ({ state: "loading" } | { state: "error"; message: string } | { state: "ready"; version: ScriptVersion });

const REVIEW_LABEL: Record<ScriptReviewState, string> = { approved: "Approved", rejected: "Rejected" };

function LoadFailure({ children }: { children: string }) {
  return <p role="alert" className="m-0 text-sm text-(--red)">{children}</p>;
}

function TargetPicker({ targetType, targetId, onChange, sources }: {
  targetType: ScheduledTaskTargetType; targetId: string; onChange: (id: string) => void; sources: ScheduleSources;
}) {
  if (targetType === "site") {
    if (!sources.sites) return <LoadFailure>Sites could not be loaded, so a site cannot be chosen. Reload the page to try again.</LoadFailure>;
    return (
      <Select label="Site" required value={targetId} onChange={(e) => onChange(e.target.value)}>
        <option value="">Choose a site</option>
        {sources.sites.map((group) => (
          <optgroup key={group.client} label={group.client}>
            {group.options.map((site) => <option key={site.id} value={site.id}>{site.label}</option>)}
          </optgroup>
        ))}
      </Select>
    );
  }
  if (!sources.endpoints) return <LoadFailure>Endpoints could not be loaded, so an endpoint cannot be chosen. Reload the page to try again.</LoadFailure>;
  return (
    <Select label="Endpoint" required value={targetId} onChange={(e) => onChange(e.target.value)}>
      <option value="">Choose an endpoint</option>
      {sources.endpoints.map((endpoint) => <option key={endpoint.id} value={endpoint.id}>{endpoint.label}</option>)}
    </Select>
  );
}

function LibraryPreview({ picked }: { picked: Picked | null }) {
  if (!picked) return null;
  if (picked.state === "loading") return <p role="status" className="m-0 text-sm text-(--muted)">Loading the script…</p>;
  if (picked.state === "error") return <LoadFailure>{picked.message}</LoadFailure>;
  const { version } = picked;
  return (
    <div className="grid gap-2 rounded-lg border border-(--line) p-3">
      <p className="m-0 text-[13px] text-(--slate)">Version {version.version} · {version.review ? REVIEW_LABEL[version.review.state] : "Not reviewed"}</p>
      <details>
        <summary className="cursor-pointer text-[13px] font-semibold text-(--slate)">Show script</summary>
        <div className="mt-2"><CodeBlock label="Script body (read-only)">{version.content ?? ""}</CodeBlock></div>
      </details>
    </div>
  );
}

/** "New schedule": the primary action; the form opens in a drawer. */
export function NewScheduleButton({ sources = NO_SCHEDULE_SOURCES }: { sources?: ScheduleSources }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetType, setTargetType] = useState<ScheduledTaskTargetType>("agent");
  const [targetId, setTargetId] = useState("");
  const [cronExpression, setCronExpression] = useState("0 * * * *");
  const [timezone, setTimezone] = useState("UTC");
  const [kind, setKind] = useState<ScriptLanguage>("powershell");
  const [source, setSource] = useState<Source>("library");
  const [commandText, setCommandText] = useState("");
  const [picked, setPicked] = useState<Picked | null>(null);
  // Only the latest pick may land; an earlier, slower response is dropped.
  const pickRequest = useRef(0);
  const formId = useId();

  const scripts = schedulableScripts(sources.scripts ?? [], kind);

  const pickScript = async (scriptId: string) => {
    const request = ++pickRequest.current;
    const item = scripts.find((candidate) => candidate.id === scriptId);
    if (!item) {
      setPicked(null);
      return;
    }
    if (!name.trim()) setName(item.name);
    setPicked({ scriptId, state: "loading" });
    let next: Picked;
    try {
      const res = await fetch(`/api/schedules/script-source/${encodeURIComponent(item.id)}/${item.latest_version}`);
      const data = await res.json();
      const version = res.ok ? scriptVersionFromUnknown(data) : null;
      next = version && typeof version.content === "string"
        ? { scriptId, state: "ready", version }
        : { scriptId, state: "error", message: data.error || "The script could not be loaded." };
    } catch {
      next = { scriptId, state: "error", message: "The script could not be loaded." };
    }
    if (request === pickRequest.current) setPicked(next);
  };

  const handleKindChange = (next: ScriptLanguage) => {
    setKind(next);
    // A pick the new kind no longer lists is dropped, and a still-loading
    // response for it is ignored. The name stays: it may be the operator's.
    if (picked && !schedulableScripts(sources.scripts ?? [], next).some((item) => item.id === picked.scriptId)) {
      pickRequest.current += 1;
      setPicked(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    // A library schedule runs the picked version's exact body, so the kind
    // and payload come from that version, never from the form.
    let run: { kind: ScriptLanguage; text: string; script_version_id?: string };
    if (source === "custom") {
      run = { kind, text: commandText };
    } else if (picked?.state === "ready") {
      run = { kind: picked.version.language, text: picked.version.content ?? "", script_version_id: picked.version.id };
    } else {
      setError("Choose a library script and wait for it to load.");
      return;
    }
    setLoading(true);
    const payload = run.kind === "powershell" ? { script: run.text } : { command: run.text };

    try {
      const res = await fetch("/api/schedules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          description: description || null,
          enabled: true,
          target_type: targetType,
          target_id: targetId,
          cron_expression: cronExpression,
          timezone,
          kind: run.kind,
          ...(run.script_version_id ? { script_version_id: run.script_version_id } : {}),
          payload,
          concurrency_policy: "skip",
          misfire_policy: "run_once",
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || data.error || "The schedule was not created.");

      setOpen(false);
      setName("");
      setDescription("");
      setTargetId("");
      setCommandText("");
      setPicked(null);
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setError(error.message || "The schedule was not created.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Button variant="primary" icon={Plus} onClick={() => setOpen(true)}>New schedule</Button>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        context="Schedules"
        title="New schedule"
        sub="It is active as soon as it is saved. A device still busy with the same kind of command is skipped for that run."
        footer={
          <>
            <Button type="submit" form={formId} variant="primary" disabled={loading}>{loading ? "Saving…" : "Save schedule"}</Button>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
          </>
        }
      >
        <form id={formId} onSubmit={handleSubmit} className="grid gap-4">
          {error ? <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm text-(--red)">{error} Nothing was saved.</p> : null}
          <Input label="Name" required placeholder="Weekly disk cleanup" value={name} onChange={(e) => setName(e.target.value)} />
          <Input label="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} />
          <Select label="Applies to" value={targetType} onChange={(e) => { setTargetType(e.target.value as ScheduledTaskTargetType); setTargetId(""); }}>
            <option value="agent">One device</option>
            <option value="site">Every device at a site</option>
          </Select>
          <TargetPicker targetType={targetType} targetId={targetId} onChange={setTargetId} sources={sources} />
          <Input label="When it runs (cron)" hint="Minute, hour, day, month, weekday. 0 * * * * is every hour." required placeholder="0 * * * *"
            value={cronExpression} onChange={(e) => setCronExpression(e.target.value)} className="font-(family-name:--font-data) text-[13px]" />
          <Select label="Time zone" value={timezone} onChange={(e) => setTimezone(e.target.value)}>
            <option value="UTC">UTC</option>
            <option value="America/New_York">America/New_York (EDT/EST)</option>
            <option value="America/Chicago">America/Chicago (CDT/CST)</option>
            <option value="America/Los_Angeles">America/Los_Angeles (PDT/PST)</option>
            <option value="Europe/London">Europe/London (BST/GMT)</option>
          </Select>
          <Select label="Kind" value={kind} onChange={(e) => handleKindChange(e.target.value as ScriptLanguage)}>
            <option value="powershell">PowerShell</option>
            <option value="shell">Shell</option>
          </Select>
          <fieldset className="m-0 grid gap-2 border-0 p-0">
            <legend className="mb-1.5 p-0 text-[13px] font-semibold text-(--slate)">Source</legend>
            <div className="flex flex-wrap gap-4 text-sm text-(--ink)">
              <label className="flex items-center gap-2"><input type="radio" name={`${formId}-source`} checked={source === "library"} onChange={() => setSource("library")} />From script library</label>
              <label className="flex items-center gap-2"><input type="radio" name={`${formId}-source`} checked={source === "custom"} onChange={() => setSource("custom")} />Write my own</label>
            </div>
          </fieldset>
          {source === "custom" ? (
            <Textarea label="Command or script" required rows={5} placeholder="Get-Process | Where-Object WorkingSet -gt 100MB" value={commandText}
              onChange={(e) => setCommandText(e.target.value)} spellCheck={false} className="font-(family-name:--font-data) text-[13px]" />
          ) : sources.scripts === null ? (
            <LoadFailure>The script library could not be loaded. Choose Write my own, or reload the page to try again.</LoadFailure>
          ) : scripts.length === 0 ? (
            <p className="m-0 rounded-lg border border-(--line) px-4 py-3 text-sm text-(--slate)">
              No approved {kind === "powershell" ? "PowerShell" : "Shell"} scripts can be scheduled. Switch the kind, choose Write my own, or get a script approved in the Script library. Scripts with required parameters cannot be scheduled yet.
            </p>
          ) : (
            <>
              <Select label="Library script" required hint="Only approved scripts are listed. The schedule keeps running this version even if the script changes later."
                value={picked?.scriptId ?? ""} onChange={(e) => void pickScript(e.target.value)}>
                <option value="">Choose a script</option>
                {scripts.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </Select>
              <LibraryPreview picked={picked} />
            </>
          )}
        </form>
      </Drawer>
    </>
  );
}

