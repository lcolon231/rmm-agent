// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowLeft,
  CircleOff,
  RotateCcw,
  ShieldAlert,
  UserRoundCog,
  X,
} from "lucide-react";
import { useId, useRef, useState } from "react";

import {
  operatorRoleLabel,
  permissionReasonBounds,
  validateOperatorRoleChangeInput,
  validateOperatorStatusChangeInput,
  type OperatorRecord,
  type OperatorRole,
} from "@/lib/operator-management-core";

type OperatorMutationResponse = {
  error?: string;
  operator?: OperatorRecord;
};

export function OperatorRoleAction({
  isCurrentOperator,
  onUpdated,
  operator,
}: {
  isCurrentOperator: boolean;
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const roleId = useId();
  const reasonId = useId();
  const [stage, setStage] = useState<"compose" | "confirm">("compose");
  const [role, setRole] = useState<OperatorRole>(operator.role);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  function open() {
    setStage("compose");
    setRole(operator.role);
    setReason("");
    setError("");
    dialog.current?.showModal();
  }

  function review(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (role === operator.role) {
      setError("Select a role different from the operator's current role.");
      return;
    }
    if (!validateOperatorRoleChangeInput({ role, reason })) {
      setError("Select a valid role and enter an audit reason between 3 and 500 characters.");
      return;
    }
    setError("");
    setStage("confirm");
  }

  async function confirm() {
    const input = validateOperatorRoleChangeInput({ role, reason });
    if (!input || role === operator.role) {
      setStage("compose");
      setError("The role selection changed. Review it again.");
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(
        `/api/operators/${encodeURIComponent(operator.id)}/role`,
        {
          body: JSON.stringify(input),
          headers: { "Content-Type": "application/json" },
          method: "PUT",
        },
      );
      const body = await response.json().catch(() => null) as OperatorMutationResponse | null;
      if (!response.ok || !body?.operator) {
        setError(body?.error ?? "The operator role could not be changed.");
        return;
      }
      onUpdated(body.operator);
      dialog.current?.close();
      if (isCurrentOperator) window.location.assign("/login");
    } catch {
      setError("Role management is unavailable. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button className="operator-action secondary" onClick={open} type="button">
        <UserRoundCog aria-hidden="true" size={14} /> Change role
      </button>
      <dialog className="operator-dialog" ref={dialog}>
        <form onSubmit={review}>
          <header>
            <div>
              <span>Audited identity change</span>
              <h2>{stage === "compose" ? "Change operator role" : "Confirm role change"}</h2>
            </div>
            <button aria-label="Close dialog" onClick={() => dialog.current?.close()} type="button">
              <X aria-hidden="true" size={18} />
            </button>
          </header>

          {stage === "compose" ? (
            <div className="operator-dialog-body">
              <p>
                Change the global role for <strong>{operator.email}</strong>. All existing
                sessions will be invalidated.
              </p>
              <label htmlFor={roleId}>
                New role
                <select
                  id={roleId}
                  onChange={(event) => setRole(event.target.value as OperatorRole)}
                  value={role}
                >
                  <option value="readonly">Read-only</option>
                  <option value="operator">Technician</option>
                  <option value="admin">Administrator</option>
                </select>
              </label>
              {role === "readonly" ? (
                <p className="operator-scope-note">
                  Read-only operators cannot hold script permission. Any current grant
                  will be revoked as part of this change.
                </p>
              ) : null}
              <label htmlFor={reasonId}>
                Audit reason
                <textarea
                  id={reasonId}
                  maxLength={permissionReasonBounds.max}
                  minLength={permissionReasonBounds.min}
                  onChange={(event) => setReason(event.target.value)}
                  required
                  rows={4}
                  value={reason}
                />
                <small>
                  Required, 3-500 characters. The reason is recorded in the audit log.
                </small>
              </label>
            </div>
          ) : (
            <div className="operator-confirm">
              <UserRoundCog aria-hidden="true" size={25} />
              <div>
                <span>Review before applying</span>
                <h3>{operatorRoleLabel(operator.role)} to {operatorRoleLabel(role)}</h3>
                <dl>
                  <div><dt>Operator</dt><dd>{operator.email}</dd></div>
                  <div><dt>New role</dt><dd>{operatorRoleLabel(role)}</dd></div>
                  <div><dt>Sessions</dt><dd>Invalidate all existing sessions</dd></div>
                  <div><dt>Audit reason</dt><dd>{reason.trim()}</dd></div>
                </dl>
              </div>
            </div>
          )}

          {error ? (
            <section className="operator-error-summary" role="alert">
              <strong>Role was not changed</strong><p>{error}</p>
            </section>
          ) : null}
          <footer>
            {stage === "confirm" ? (
              <button onClick={() => setStage("compose")} type="button">
                <ArrowLeft aria-hidden="true" size={14} /> Edit
              </button>
            ) : (
              <button onClick={() => dialog.current?.close()} type="button">Cancel</button>
            )}
            {stage === "compose" ? (
              <button className="primary" type="submit">Review change</button>
            ) : (
              <button className="primary" disabled={pending} onClick={confirm} type="button">
                {pending ? "Applying..." : "Change role"}
              </button>
            )}
          </footer>
        </form>
      </dialog>
    </>
  );
}

export function OperatorStatusAction({
  isCurrentOperator,
  onUpdated,
  operator,
}: {
  isCurrentOperator: boolean;
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const reasonId = useId();
  const [stage, setStage] = useState<"compose" | "confirm">("compose");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const disabling = !operator.disabled;
  const actionLabel = disabling ? "Disable operator" : "Re-enable operator";

  function open() {
    setStage("compose");
    setReason("");
    setError("");
    dialog.current?.showModal();
  }

  function review(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!validateOperatorStatusChangeInput({ disabled: disabling, reason })) {
      setError("Enter an audit reason between 3 and 500 characters.");
      return;
    }
    setError("");
    setStage("confirm");
  }

  async function confirm() {
    const input = validateOperatorStatusChangeInput({ disabled: disabling, reason });
    if (!input) {
      setStage("compose");
      setError("The account-state change needs to be reviewed again.");
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(
        `/api/operators/${encodeURIComponent(operator.id)}/disabled`,
        {
          body: JSON.stringify(input),
          headers: { "Content-Type": "application/json" },
          method: "PUT",
        },
      );
      const body = await response.json().catch(() => null) as OperatorMutationResponse | null;
      if (!response.ok || !body?.operator) {
        setError(body?.error ?? "The operator account state could not be changed.");
        return;
      }
      onUpdated(body.operator);
      dialog.current?.close();
      if (isCurrentOperator) window.location.assign("/login");
    } catch {
      setError("Account-state management is unavailable. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  const StatusIcon = disabling ? CircleOff : RotateCcw;
  return (
    <>
      <button
        className={disabling ? "operator-action danger" : "operator-action secondary"}
        onClick={open}
        type="button"
      >
        <StatusIcon aria-hidden="true" size={14} /> {disabling ? "Disable" : "Re-enable"}
      </button>
      <dialog className="operator-dialog" ref={dialog}>
        <form onSubmit={review}>
          <header>
            <div>
              <span>Audited account change</span>
              <h2>{stage === "compose" ? actionLabel : `Confirm ${actionLabel.toLowerCase()}`}</h2>
            </div>
            <button aria-label="Close dialog" onClick={() => dialog.current?.close()} type="button">
              <X aria-hidden="true" size={18} />
            </button>
          </header>

          {stage === "compose" ? (
            <div className="operator-dialog-body">
              <p>
                {disabling
                  ? <>Disable <strong>{operator.email}</strong> and invalidate every issued session.</>
                  : <>Restore sign-in access for <strong>{operator.email}</strong>. Existing sessions remain invalid.</>}
              </p>
              {disabling && operator.role === "admin" ? (
                <p className="operator-scope-note">
                  NodeLink will refuse this change if it would remove the final active administrator.
                </p>
              ) : null}
              <label htmlFor={reasonId}>
                Audit reason
                <textarea
                  id={reasonId}
                  maxLength={permissionReasonBounds.max}
                  minLength={permissionReasonBounds.min}
                  onChange={(event) => setReason(event.target.value)}
                  required
                  rows={4}
                  value={reason}
                />
                <small>Required, 3-500 characters. The reason is recorded in the audit log.</small>
              </label>
            </div>
          ) : (
            <div className="operator-confirm">
              <ShieldAlert aria-hidden="true" size={25} />
              <div>
                <span>Review before applying</span>
                <h3>{actionLabel}</h3>
                <dl>
                  <div><dt>Operator</dt><dd>{operator.email}</dd></div>
                  <div><dt>New state</dt><dd>{disabling ? "Disabled" : "Active"}</dd></div>
                  <div><dt>Sessions</dt><dd>Invalidate all existing sessions</dd></div>
                  <div><dt>Audit reason</dt><dd>{reason.trim()}</dd></div>
                </dl>
              </div>
            </div>
          )}

          {error ? (
            <section className="operator-error-summary" role="alert">
              <strong>Account state was not changed</strong><p>{error}</p>
            </section>
          ) : null}
          <footer>
            {stage === "confirm" ? (
              <button onClick={() => setStage("compose")} type="button">
                <ArrowLeft aria-hidden="true" size={14} /> Edit
              </button>
            ) : (
              <button onClick={() => dialog.current?.close()} type="button">Cancel</button>
            )}
            {stage === "compose" ? (
              <button className="primary" type="submit">Review change</button>
            ) : (
              <button
                className={disabling ? "danger" : "primary"}
                disabled={pending}
                onClick={confirm}
                type="button"
              >
                {pending ? "Applying..." : actionLabel}
              </button>
            )}
          </footer>
        </form>
      </dialog>
    </>
  );
}
