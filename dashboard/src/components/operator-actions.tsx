// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { LogOut, ShieldCheck, ShieldOff } from "lucide-react";
import { useState } from "react";

import { ActionDialog, StatusNote, useReportModal } from "@/components/admin/admin-ui";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Input, Select, Textarea } from "@/components/ui/field";
import { reasonProblem } from "@/lib/admin-screens-core";
import {
  canGrantScriptPermission,
  permissionReasonBounds,
  validateScriptPermissionInput,
  validateScriptPermissionRevokeInput,
  type OperatorRecord,
  type ScriptPermissionScope,
} from "@/lib/operator-management-core";

type OperatorMutationResponse = {
  error?: string;
  operator?: OperatorRecord;
};

export const REASON_LABEL = "Reason (kept in the audit record)";
export const REASON_HINT = `Required, ${permissionReasonBounds.min} to ${permissionReasonBounds.max} characters.`;

function notChanged(message: string) {
  return `${message} Nothing was changed.`;
}

/** Grant or change a script-execution grant. Scope, target and reason are sent to the API. */
function GrantScriptPermission({
  onUpdated,
  operator,
}: {
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
}) {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<ScriptPermissionScope>(operator.script_execution_scope ?? "global");
  const [scopeTarget, setScopeTarget] = useState(operator.script_execution_scope_id ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const actionLabel = operator.script_execution_scope ? "Change script permission" : "Grant script permission";

  function input() {
    return validateScriptPermissionInput(
      { reason, scope, scope_id: scope === "global" ? undefined : scopeTarget },
      operator.role,
    );
  }

  function show() {
    setScope(operator.script_execution_scope ?? "global");
    setScopeTarget(operator.script_execution_scope_id ?? "");
    setReason("");
    setError("");
    setOpen(true);
  }

  async function confirm() {
    const body = input();
    if (!body) {
      setError("Choose a valid scope and target, then enter an audit reason between 3 and 500 characters.");
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(`/api/operators/${encodeURIComponent(operator.id)}/script-permission`, {
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
        method: "PUT",
      });
      const result = await response.json().catch(() => null) as OperatorMutationResponse | null;
      if (!response.ok || !result?.operator) {
        setError(notChanged(result?.error ?? "The script-permission change could not be completed."));
        return;
      }
      onUpdated(result.operator);
      setOpen(false);
    } catch {
      setError(notChanged("The script-permission change is unavailable. Check the management service."));
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button icon={ShieldCheck} onClick={show}>
        {actionLabel}
      </Button>
      <ActionDialog
        open={open}
        onClose={() => setOpen(false)}
        title={`${actionLabel} for ${operator.email}?`}
        description="Script permission is separate from role. Without a grant, this operator cannot run scripts."
        confirmLabel={actionLabel}
        confirmDisabled={!input()}
        onConfirm={confirm}
        busy={pending}
        error={error || undefined}
        icon={ShieldCheck}
      >
        <Select label="Scope" value={scope} onChange={(event) => setScope(event.target.value as ScriptPermissionScope)} disabled={pending}>
          <option value="global">Global: every managed device</option>
          <option value="site">Site: one site ID</option>
          <option value="agent">Agent: one device ID</option>
        </Select>
        {scope !== "global" ? (
          <Input
            label={scope === "site" ? "Site ID" : "Agent ID"}
            maxLength={36}
            minLength={1}
            required
            value={scopeTarget}
            onChange={(event) => setScopeTarget(event.target.value)}
            disabled={pending}
            className="font-(family-name:--font-data)"
          />
        ) : null}
        <Textarea
          label={REASON_LABEL}
          hint={REASON_HINT}
          maxLength={permissionReasonBounds.max}
          required
          rows={3}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          disabled={pending}
        />
      </ActionDialog>
    </>
  );
}

/** High-risk: returns the operator to no script permission. The reason is sent to the API. */
function RevokeScriptPermission({
  onUpdated,
  operator,
}: {
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  useReportModal(open);

  async function confirm(reason: string) {
    const problem = reasonProblem(reason);
    const body = validateScriptPermissionRevokeInput({ reason });
    if (problem || !body) {
      setError(problem ?? "Enter an audit reason between 3 and 500 characters.");
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(`/api/operators/${encodeURIComponent(operator.id)}/script-permission/revoke`, {
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const result = await response.json().catch(() => null) as OperatorMutationResponse | null;
      if (!response.ok || !result?.operator) {
        setError(notChanged(result?.error ?? "The script-permission change could not be completed."));
        return;
      }
      onUpdated(result.operator);
      setOpen(false);
    } catch {
      setError(notChanged("The script-permission change is unavailable. Check the management service."));
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button
        variant="danger"
        icon={ShieldOff}
        onClick={() => {
          setError("");
          setOpen(true);
        }}
      >
        Revoke script permission
      </Button>
      <ConfirmDialog
        open={open}
        onCancel={() => setOpen(false)}
        onConfirm={confirm}
        title={`Revoke script permission for ${operator.email}?`}
        consequence="The operator can no longer run scripts on any device until an administrator grants permission again."
        confirmLabel="Revoke permission"
        busy={pending}
        error={error || undefined}
      />
    </>
  );
}

export function ScriptPermissionAction({
  mode,
  onUpdated,
  operator,
}: {
  mode: "grant" | "revoke";
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
}) {
  if (mode === "revoke") return <RevokeScriptPermission onUpdated={onUpdated} operator={operator} />;
  if (!canGrantScriptPermission(operator.role)) {
    return <p className="m-0 text-xs text-(--muted)">Read-only operators cannot hold script permission.</p>;
  }
  return <GrantScriptPermission onUpdated={onUpdated} operator={operator} />;
}

/**
 * High-risk: invalidates every session issued to the operator. The API takes
 * no reason, so this dialog does not ask for one or claim to record one.
 */
export function SignOutEverywhereAction({
  isCurrentOperator,
  operator,
}: {
  isCurrentOperator: boolean;
  operator: OperatorRecord;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pending, setPending] = useState(false);

  async function revokeSessions() {
    setPending(true);
    setError("");
    try {
      const response = await fetch(`/api/operators/${encodeURIComponent(operator.id)}/revoke-tokens`, { method: "POST" });
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { error?: string } | null;
        setError(notChanged(body?.error ?? "Sessions could not be revoked."));
        return;
      }
      setOpen(false);
      if (isCurrentOperator) {
        window.location.assign("/login");
        return;
      }
      setNotice("All sessions revoked.");
    } catch {
      setError(notChanged("Session revocation is unavailable. Check the management service."));
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button
        variant="danger"
        onClick={() => {
          setError("");
          setNotice("");
          setOpen(true);
        }}
      >
        Sign out everywhere
      </Button>
      {notice ? (
        <div className="basis-full">
          <StatusNote tone="ok" role="status" title={notice} />
        </div>
      ) : null}
      <ConfirmDialog
        open={open}
        onCancel={() => setOpen(false)}
        title={`Sign ${operator.email} out everywhere?`}
        consequence={`Every session issued to this operator stops working.${isCurrentOperator ? " This includes your current session." : ""} The API does not store this reason.`}
        confirmLabel={pending ? "Signing out…" : "Sign out everywhere"}
        onConfirm={revokeSessions}
        busy={pending}
        error={error || undefined}
      />
    </>
  );
}
