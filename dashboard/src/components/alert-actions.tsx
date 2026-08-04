// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { CheckCircle2, MessageSquareText, UserRoundCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import type { AlertAssignee, MonitoringAlertDetail } from "@/lib/monitoring-core";

type ActionName = "acknowledge" | "assign" | "comments" | "resolve";
type AlertActionTarget = Pick<
  MonitoringAlertDetail,
  "id" | "state" | "version" | "assigned_to_operator_id"
>;

export function AlertActions({
  alert,
  assignees,
  canManage,
}: {
  alert: AlertActionTarget;
  assignees: AlertAssignee[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [currentAlert, setCurrentAlert] = useState(alert);
  const [comment, setComment] = useState("");
  const [assigneeId, setAssigneeId] = useState(alert.assigned_to_operator_id ?? "");
  const [busy, setBusy] = useState<ActionName | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function run(action: ActionName, includeComment = true) {
    setBusy(action);
    setError("");
    setMessage("");
    try {
      const response = await fetch(`/api/alerts/${encodeURIComponent(alert.id)}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: crypto.randomUUID().replaceAll("-", ""),
          expected_version: currentAlert.version,
          ...(includeComment && comment.trim() ? { comment: comment.trim() } : {}),
          ...(action === "assign" ? { assigned_to_operator_id: assigneeId || null } : {}),
        }),
      });
      const body = await response.json().catch(() => null) as {
        alert?: MonitoringAlertDetail;
        error?: string;
      } | null;
      if (!response.ok || !body?.alert) throw new Error(body?.error ?? "The update failed.");
      setCurrentAlert({
        id: body.alert.id,
        state: body.alert.state,
        version: body.alert.version,
        assigned_to_operator_id: body.alert.assigned_to_operator_id,
      });
      setAssigneeId(body.alert.assigned_to_operator_id ?? "");
      setComment("");
      setMessage({
        acknowledge: "Alert acknowledged.", assign: "Assignment updated.",
        comments: "Comment added.", resolve: "Alert resolved.",
      }[action]);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The update failed.");
    } finally {
      setBusy(null);
    }
  }

  if (!canManage) {
    return <p className="alert-readonly-note">Read-only access: an operator or administrator can update this alert.</p>;
  }

  return (
    <section
      className="alert-action-panel"
      aria-busy={Boolean(busy)}
      aria-labelledby="alert-actions-title"
    >
      <header>
        <div><span>Technician controls</span><h2 id="alert-actions-title">Update alert</h2></div>
        <small>Current version {currentAlert.version}</small>
      </header>
      <label>
        <span>Assignment</span>
        <select value={assigneeId} onChange={(event) => setAssigneeId(event.target.value)} disabled={Boolean(busy)}>
          <option value="">Unassigned</option>
          {assignees.map((assignee) => <option key={assignee.id} value={assignee.id}>{assignee.email}</option>)}
        </select>
      </label>
      <label>
        <span>Technician note</span>
        <textarea
          value={comment}
          onChange={(event) => setComment(event.target.value)}
          maxLength={2000}
          placeholder="Add investigation context or resolution evidence…"
          disabled={Boolean(busy)}
        />
        <small>{comment.length}/2,000 characters</small>
      </label>
      <div className="alert-action-buttons">
        {currentAlert.state === "open" ? (
          <button type="button" onClick={() => run("acknowledge")} disabled={Boolean(busy)}>
            <CheckCircle2 size={16} />{busy === "acknowledge" ? "Saving…" : "Acknowledge"}
          </button>
        ) : null}
        <button type="button" onClick={() => run("assign")} disabled={Boolean(busy)}>
          <UserRoundCheck size={16} />{busy === "assign" ? "Saving…" : "Save assignment"}
        </button>
        <button type="button" onClick={() => run("comments")} disabled={Boolean(busy) || !comment.trim()}>
          <MessageSquareText size={16} />{busy === "comments" ? "Saving…" : "Add comment"}
        </button>
        {currentAlert.state !== "resolved" ? (
          <button type="button" className="resolve" onClick={() => run("resolve")} disabled={Boolean(busy) || !comment.trim()}>
            <CheckCircle2 size={16} />{busy === "resolve" ? "Resolving…" : "Resolve alert"}
          </button>
        ) : null}
      </div>
      {message ? <p className="alert-action-success" role="status">{message}</p> : null}
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </section>
  );
}
