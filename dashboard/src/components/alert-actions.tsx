// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { Check, CircleCheck, MessageSquareText, UserRoundCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { createContext, useContext, useState, type ReactNode } from "react";

import type { AlertAssignee, MonitoringAlertDetail } from "@/lib/monitoring-core";

import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { cx } from "./ui/cx";
import { Select, Textarea } from "./ui/field";
import { cardClass } from "./ui/stat-tile";

type ActionName = "acknowledge" | "assign" | "comments" | "resolve";
type AlertActionTarget = Pick<MonitoringAlertDetail, "id" | "state" | "version" | "assigned_to_operator_id">;

const COMMENT_LIMIT = 2000;

const DONE: Record<ActionName, string> = {
  acknowledge: "Alert acknowledged.",
  assign: "Assignment updated.",
  comments: "Note added.",
  resolve: "Alert resolved.",
};

type AlertActionState = {
  alert: AlertActionTarget;
  assignees: AlertAssignee[];
  canManage: boolean;
  comment: string;
  setComment: (value: string) => void;
  assigneeId: string;
  setAssigneeId: (value: string) => void;
  busy: ActionName | null;
  message: string;
  error: string;
  /** Which action the error belongs to. */
  failed: ActionName | null;
  /** Resolves true when the server confirmed the change. */
  run: (action: ActionName, commentOverride?: string) => Promise<boolean>;
};

const AlertActionContext = createContext<AlertActionState | null>(null);

function useAlertActions(): AlertActionState {
  const value = useContext(AlertActionContext);
  if (!value) throw new Error("Alert actions must be inside AlertActionsProvider.");
  return value;
}

/**
 * Shares one alert version, note and busy state between the header buttons
 * and the "Update alert" card, so a note typed in the card goes with
 * Acknowledge exactly as before.
 */
export function AlertActionsProvider({
  alert,
  assignees,
  canManage,
  children,
}: {
  alert: AlertActionTarget;
  assignees: AlertAssignee[];
  canManage: boolean;
  children: ReactNode;
}) {
  const router = useRouter();
  const [currentAlert, setCurrentAlert] = useState(alert);
  const [comment, setComment] = useState("");
  const [assigneeId, setAssigneeId] = useState(alert.assigned_to_operator_id ?? "");
  const [busy, setBusy] = useState<ActionName | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [failed, setFailed] = useState<ActionName | null>(null);

  async function run(action: ActionName, commentOverride?: string) {
    const note = (commentOverride ?? comment).trim();
    setBusy(action);
    setError("");
    setFailed(null);
    setMessage("");
    try {
      if (note.length > COMMENT_LIMIT) throw new Error(`Keep the note to ${COMMENT_LIMIT.toLocaleString("en-US")} characters.`);
      const response = await fetch(`/api/alerts/${encodeURIComponent(currentAlert.id)}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: crypto.randomUUID().replaceAll("-", ""),
          expected_version: currentAlert.version,
          ...(note ? { comment: note } : {}),
          ...(action === "assign" ? { assigned_to_operator_id: assigneeId || null } : {}),
        }),
      });
      const body = (await response.json().catch(() => null)) as { alert?: MonitoringAlertDetail; error?: string } | null;
      if (!response.ok || !body?.alert) throw new Error(body?.error ?? "The update failed.");
      setCurrentAlert({
        id: body.alert.id,
        state: body.alert.state,
        version: body.alert.version,
        assigned_to_operator_id: body.alert.assigned_to_operator_id,
      });
      setAssigneeId(body.alert.assigned_to_operator_id ?? "");
      setComment("");
      setMessage(DONE[action]);
      router.refresh();
      return true;
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The update failed.");
      setFailed(action);
      return false;
    } finally {
      setBusy(null);
    }
  }

  return (
    <AlertActionContext.Provider
      value={{ alert: currentAlert, assignees, canManage, comment, setComment, assigneeId, setAssigneeId, busy, message, error, failed, run }}
    >
      {children}
    </AlertActionContext.Provider>
  );
}

/** Header actions: Acknowledge (primary) and the high-risk Resolve alert. */
export function AlertHeaderActions() {
  const { alert, canManage, busy, error, failed, run } = useAlertActions();
  const [resolving, setResolving] = useState(false);
  if (!canManage) return null;

  async function resolve(reason: string) {
    if (await run("resolve", reason)) setResolving(false);
  }

  return (
    <>
      {alert.state === "open" ? (
        <Button variant="primary" icon={Check} onClick={() => void run("acknowledge")} disabled={Boolean(busy)}>
          {busy === "acknowledge" ? "Saving…" : "Acknowledge"}
        </Button>
      ) : null}
      {alert.state !== "resolved" ? (
        <Button variant="danger" icon={CircleCheck} onClick={() => setResolving(true)} disabled={Boolean(busy)}>
          Resolve alert
        </Button>
      ) : null}
      <ConfirmDialog
        open={resolving}
        onCancel={() => setResolving(false)}
        onConfirm={resolve}
        title="Mark this alert as resolved?"
        consequence="Only resolve it once the problem is fixed. If the check fails again, the alert opens again. Your reason is saved as a note on the alert."
        confirmLabel={busy === "resolve" ? "Resolving…" : "Resolve alert"}
        busy={busy === "resolve"}
        error={failed === "resolve" ? error : undefined}
      />
    </>
  );
}

/** Assignment and notes. Read-only operators see why the controls are missing. */
export function AlertWorkPanel() {
  const { assignees, canManage, comment, setComment, assigneeId, setAssigneeId, busy, message, error, failed, run } = useAlertActions();

  if (!canManage) {
    return (
      <p className={cx(cardClass, "m-0 px-5 py-4 text-sm text-(--muted)")}>
        You have read-only access. An operator or administrator can acknowledge, assign or resolve this alert.
      </p>
    );
  }

  return (
    <section aria-labelledby="alert-actions-title" aria-busy={Boolean(busy)} className={cx(cardClass, "overflow-hidden")}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
        <div className="grid gap-0.5">
          <h2 id="alert-actions-title" className="m-0 text-base font-semibold text-(--ink)">
            Update alert
          </h2>
          <p className="m-0 text-xs text-(--muted)">A note typed here is saved with Acknowledge, an assignment change, or on its own.</p>
        </div>
      </header>
      <div className="grid gap-4 px-5 py-4">
        <Select label="Assigned to" value={assigneeId} onChange={(event) => setAssigneeId(event.target.value)} disabled={Boolean(busy)}>
          <option value="">Nobody</option>
          {assignees.map((assignee) => (
            <option key={assignee.id} value={assignee.id}>
              {assignee.email}
            </option>
          ))}
        </Select>
        <Textarea
          label="Note"
          hint={`${comment.length.toLocaleString("en-US")} of ${COMMENT_LIMIT.toLocaleString("en-US")} characters`}
          value={comment}
          onChange={(event) => setComment(event.target.value)}
          maxLength={COMMENT_LIMIT}
          placeholder="What you checked, or what you changed"
          disabled={Boolean(busy)}
        />
        <div className="flex flex-wrap gap-2">
          <Button icon={UserRoundCheck} onClick={() => void run("assign")} disabled={Boolean(busy)}>
            {busy === "assign" ? "Saving…" : "Save assignment"}
          </Button>
          <Button icon={MessageSquareText} onClick={() => void run("comments")} disabled={Boolean(busy) || !comment.trim()}>
            {busy === "comments" ? "Saving…" : "Add note"}
          </Button>
        </div>
        {message ? (
          <p role="status" className="m-0 text-sm font-semibold text-(--success)">
            {message}
          </p>
        ) : null}
        {error && failed !== "resolve" ? (
          <p role="alert" className="m-0 text-sm text-(--red)">
            {error}
          </p>
        ) : null}
      </div>
    </section>
  );
}
