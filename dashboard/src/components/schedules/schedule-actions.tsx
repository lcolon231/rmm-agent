// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Pause, Play, Plus, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";

import type { ScheduledTaskItem } from "@/lib/scheduled-tasks-core";

import { Button } from "../ui/button";
import { Drawer } from "../ui/drawer";
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

/** "New schedule": the primary action; the form opens in a drawer. */
export function NewScheduleButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetType, setTargetType] = useState<"agent" | "site">("agent");
  const [targetId, setTargetId] = useState("");
  const [cronExpression, setCronExpression] = useState("0 * * * *");
  const [timezone, setTimezone] = useState("UTC");
  const [kind, setKind] = useState("powershell");
  const [commandText, setCommandText] = useState("");
  const formId = useId();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const payload = kind === "powershell" ? { script: commandText } : { command: commandText };

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
          kind,
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
          <Select label="Applies to" value={targetType} onChange={(e) => setTargetType(e.target.value as "agent" | "site")}>
            <option value="agent">One device</option>
            <option value="site">Every device at a site</option>
          </Select>
          <Input label={targetType === "site" ? "Site ID" : "Device ID"} required value={targetId} onChange={(e) => setTargetId(e.target.value)}
            className="font-(family-name:--font-data) text-[13px]" />
          <Input label="When it runs (cron)" hint="Minute, hour, day, month, weekday. 0 * * * * is every hour." required placeholder="0 * * * *"
            value={cronExpression} onChange={(e) => setCronExpression(e.target.value)} className="font-(family-name:--font-data) text-[13px]" />
          <Select label="Time zone" value={timezone} onChange={(e) => setTimezone(e.target.value)}>
            <option value="UTC">UTC</option>
            <option value="America/New_York">America/New_York (EDT/EST)</option>
            <option value="America/Chicago">America/Chicago (CDT/CST)</option>
            <option value="America/Los_Angeles">America/Los_Angeles (PDT/PST)</option>
            <option value="Europe/London">Europe/London (BST/GMT)</option>
          </Select>
          <Select label="Kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="powershell">PowerShell</option>
            <option value="shell">Shell</option>
          </Select>
          <Textarea label="Command or script" required rows={5} placeholder="Get-Process | Where-Object WorkingSet -gt 100MB" value={commandText}
            onChange={(e) => setCommandText(e.target.value)} spellCheck={false} className="font-(family-name:--font-data) text-[13px]" />
        </form>
      </Drawer>
    </>
  );
}

