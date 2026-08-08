// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Calendar, Play, Plus, Power, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import type { ScheduledTaskItem } from "@/lib/scheduled-tasks-core";

export function ScheduleRowActions({ task }: { task: ScheduledTaskItem }) {
  const router = useRouter();
  const [toggling, setToggling] = useState(false);
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const handleToggle = async () => {
    setToggling(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/schedules/${task.id}/toggle`, { method: "POST" });
      if (!res.ok) throw new Error("Failed to toggle schedule");
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setMessage(error.message || "Toggle failed");
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
      if (!res.ok) throw new Error(data.error || "Failed to trigger schedule");
      setMessage(`Dispatched to ${data.dispatched} agent(s)`);
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setMessage(error.message || "Run failed");
    } finally {
      setRunning(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm(`Are you sure you want to delete schedule "${task.name}"?`)) return;
    setDeleting(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/schedules/${task.id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete schedule");
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setMessage(error.message || "Delete failed");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="schedule-row-actions">
      {message ? <small className="schedule-status-msg">{message}</small> : null}
      <button
        type="button"
        className={`schedule-btn toggle ${task.enabled ? "enabled" : "disabled"}`}
        disabled={toggling}
        onClick={handleToggle}
        title={task.enabled ? "Disable schedule" : "Enable schedule"}
      >
        <Power size={14} />
        <span>{task.enabled ? "Enabled" : "Disabled"}</span>
      </button>
      <button
        type="button"
        className="schedule-btn run-now"
        disabled={running || !task.enabled}
        onClick={handleRunNow}
        title="Run now"
      >
        <Play size={14} />
        <span>Run now</span>
      </button>
      <button
        type="button"
        className="schedule-btn delete"
        disabled={deleting}
        onClick={handleDelete}
        title="Delete schedule"
      >
        <Trash2 size={14} />
      </button>
    </div>
  );
}

export function CreateScheduleButton() {
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
      if (!res.ok) throw new Error(data.detail || data.error || "Failed to create schedule");

      setOpen(false);
      setName("");
      setDescription("");
      setTargetId("");
      setCommandText("");
      router.refresh();
    } catch (err: unknown) {
      const error = err as Error;
      setError(error.message || "Create failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <button type="button" className="enrollment-btn-primary" onClick={() => setOpen(true)}>
        <Plus size={16} />
        <span>Create schedule</span>
      </button>

      {open ? (
        <div className="schedule-modal-overlay">
          <div className="schedule-modal">
            <header>
              <h2><Calendar size={18} /> New recurring task schedule</h2>
              <button type="button" className="close-btn" onClick={() => setOpen(false)}>×</button>
            </header>
            <form onSubmit={handleSubmit}>
              {error ? <div className="schedule-error-banner">{error}</div> : null}

              <label>
                <span>Schedule name</span>
                <input
                  type="text"
                  required
                  placeholder="e.g. Daily Disk Cleanup"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>

              <label>
                <span>Description (optional)</span>
                <input
                  type="text"
                  placeholder="Briefly state purpose"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </label>

              <div className="form-row">
                <label>
                  <span>Target scope</span>
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value as "agent" | "site")}
                  >
                    <option value="agent">Single Agent</option>
                    <option value="site">Entire Site</option>
                  </select>
                </label>

                <label>
                  <span>Target ID (Agent or Site UUID)</span>
                  <input
                    type="text"
                    required
                    placeholder="UUID string"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                  />
                </label>
              </div>

              <div className="form-row">
                <label>
                  <span>Cron expression</span>
                  <input
                    type="text"
                    required
                    placeholder="0 * * * *"
                    value={cronExpression}
                    onChange={(e) => setCronExpression(e.target.value)}
                  />
                </label>

                <label>
                  <span>Timezone</span>
                  <select value={timezone} onChange={(e) => setTimezone(e.target.value)}>
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">America/New_York (EDT/EST)</option>
                    <option value="America/Chicago">America/Chicago (CDT/CST)</option>
                    <option value="America/Los_Angeles">America/Los_Angeles (PDT/PST)</option>
                    <option value="Europe/London">Europe/London (BST/GMT)</option>
                  </select>
                </label>
              </div>

              <div className="form-row">
                <label>
                  <span>Execution kind</span>
                  <select value={kind} onChange={(e) => setKind(e.target.value)}>
                    <option value="powershell">PowerShell</option>
                    <option value="shell">Shell / CMD</option>
                  </select>
                </label>
              </div>

              <label>
                <span>Command / Script content</span>
                <textarea
                  required
                  rows={4}
                  placeholder="Get-Process | Where-Object WorkingSet -gt 100MB"
                  value={commandText}
                  onChange={(e) => setCommandText(e.target.value)}
                />
              </label>

              <footer>
                <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="enrollment-btn-primary" disabled={loading}>
                  {loading ? "Creating..." : "Save Schedule"}
                </button>
              </footer>
            </form>
          </div>
        </div>
      ) : null}
    </>
  );
}
