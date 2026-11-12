// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import { useState } from "react";
import { ActionDialog } from "./admin/admin-ui";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { Select } from "./ui/field";
import { operatorRoleLabel, validateOperatorRoleChangeInput, validateOperatorStatusChangeInput, type OperatorRecord, type OperatorRole } from "@/lib/operator-management-core";

type Props = { isCurrentOperator: boolean; onUpdated: (operator: OperatorRecord) => void; operator: OperatorRecord };
export function OperatorRoleAction(props: Props) { return <AccountAction {...props} kind="role" />; }
export function OperatorStatusAction(props: Props) { return <AccountAction {...props} kind="status" />; }
function AccountAction({ operator, onUpdated, isCurrentOperator, kind }: Props & { kind: "role" | "status" }) {
  const [stage, setStage] = useState<"closed" | "compose" | "confirm">("closed");
  const [role, setRole] = useState<OperatorRole>(operator.role);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const disabling = !operator.disabled;
  const label = kind === "role" ? "Change role" : disabling ? "Disable operator" : "Re-enable operator";
  async function confirm(reason: string) {
    const input = kind === "role" ? validateOperatorRoleChangeInput({ role, reason }) : validateOperatorStatusChangeInput({ disabled: disabling, reason });
    if (!input || (kind === "role" && role === operator.role)) { setError("Select a different role where applicable and enter a reason between 3 and 500 characters."); return; }
    setPending(true); setError("");
    try {
      const response = await fetch(`/api/operators/${encodeURIComponent(operator.id)}/${kind === "role" ? "role" : "disabled"}`, { body: JSON.stringify(input), headers: { "Content-Type": "application/json" }, method: "PUT" });
      const body = await response.json().catch(() => null) as { error?: string; operator?: OperatorRecord } | null;
      if (!response.ok || !body?.operator) { setError(body?.error ?? "The operator could not be changed."); return; }
      onUpdated(body.operator); setStage("closed");
      if (isCurrentOperator) window.location.assign("/login");
    } catch { setError("Account management is unavailable. Check the management service."); }
    finally { setPending(false); }
  }
  return <>
    <Button variant={kind === "status" && disabling ? "danger" : "secondary"} size="compact" onClick={() => { setError(""); setRole(operator.role); setStage(kind === "role" ? "compose" : "confirm"); }}>{kind === "role" ? label : disabling ? "Disable" : "Re-enable"}</Button>
    <ActionDialog open={stage === "compose"} onClose={() => setStage("closed")} title="Change operator role" description={`Choose a new role for ${operator.email}. Existing sessions will be invalidated.`} confirmLabel="Review change" confirmDisabled={role === operator.role} onConfirm={() => setStage("confirm")}>
      <Select label="New role" value={role} onChange={(event) => setRole(event.target.value as OperatorRole)}><option value="readonly">Read-only</option><option value="operator">Technician</option><option value="admin">Administrator</option></Select>
      {role === "readonly" ? <p>Any current script permission will be revoked.</p> : null}
    </ActionDialog>
    <ConfirmDialog open={stage === "confirm"} onCancel={() => setStage("closed")} onConfirm={confirm} title={`${label}?`} consequence={kind === "role" ? `Change ${operator.email} from ${operatorRoleLabel(operator.role)} to ${operatorRoleLabel(role)} and invalidate existing sessions.` : disabling ? `Disable ${operator.email} and invalidate existing sessions. The server refuses changes that remove the final active administrator.` : `Restore sign-in access for ${operator.email}. Existing sessions remain invalid.`} confirmLabel={label} busy={pending} error={error || undefined} />
  </>;
}
