// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  LogOut,
  ShieldCheck,
  ShieldOff,
  X,
} from "lucide-react";
import { useId, useRef, useState } from "react";

import {
  canGrantScriptPermission,
  permissionReasonBounds,
  scriptPermissionScopeLabel,
  validateScriptPermissionInput,
  validateScriptPermissionRevokeInput,
  type OperatorRecord,
  type ScriptPermissionScope,
} from "@/lib/operator-management-core";

type OperatorMutationResponse = {
  error?: string;
  operator?: OperatorRecord;
};

type ScriptPermissionActionProps = {
  mode: "grant" | "revoke";
  onUpdated: (operator: OperatorRecord) => void;
  operator: OperatorRecord;
};

export function ScriptPermissionAction({
  mode,
  onUpdated,
  operator,
}: ScriptPermissionActionProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const reasonId = useId();
  const scopeId = useId();
  const targetId = useId();
  const [stage, setStage] = useState<"compose" | "confirm">("compose");
  const [scope, setScope] = useState<ScriptPermissionScope>(
    operator.script_execution_scope ?? "global",
  );
  const [scopeTarget, setScopeTarget] = useState(
    operator.script_execution_scope_id ?? "",
  );
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const eligible = canGrantScriptPermission(operator.role);
  const isGrant = mode === "grant";

  function open() {
    setStage("compose");
    setError("");
    setReason("");
    setScope(operator.script_execution_scope ?? "global");
    setScopeTarget(operator.script_execution_scope_id ?? "");
    dialog.current?.showModal();
  }

  function review(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = isGrant
      ? validateScriptPermissionInput({
          reason,
          scope,
          scope_id: scope === "global" ? undefined : scopeTarget,
        }, operator.role)
      : validateScriptPermissionRevokeInput({ reason });
    if (!input) {
      setError(isGrant
        ? "Choose a valid scope and target, then enter an audit reason between 3 and 500 characters."
        : "Enter an audit reason between 3 and 500 characters.");
      return;
    }
    setError("");
    setStage("confirm");
  }

  async function confirm() {
    const input = isGrant
      ? validateScriptPermissionInput({
          reason,
          scope,
          scope_id: scope === "global" ? undefined : scopeTarget,
        }, operator.role)
      : validateScriptPermissionRevokeInput({ reason });
    if (!input) {
      setStage("compose");
      setError("The permission settings changed. Review them again.");
      return;
    }

    setPending(true);
    setError("");
    const endpoint = `/api/operators/${encodeURIComponent(operator.id)}/script-permission${isGrant ? "" : "/revoke"}`;
    try {
      const response = await fetch(endpoint, {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: isGrant ? "PUT" : "POST",
      });
      const body = await response.json().catch(() => null) as OperatorMutationResponse | null;
      if (!response.ok || !body?.operator) {
        setError(body?.error ?? "The script-permission change could not be completed.");
        return;
      }
      onUpdated(body.operator);
      dialog.current?.close();
    } catch {
      setError("The script-permission change is unavailable. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  if (isGrant && !eligible) {
    return (
      <span className="operator-ineligible">
        <button disabled type="button"><ShieldCheck aria-hidden="true" size={14} /> Grant</button>
        <small>Read-only operators cannot hold script permission.</small>
      </span>
    );
  }

  const actionLabel = isGrant
    ? operator.script_execution_scope ? "Change permission" : "Grant permission"
    : "Revoke permission";

  return (
    <>
      <button
        className={isGrant ? "operator-action" : "operator-action danger"}
        onClick={open}
        type="button"
      >
        {isGrant
          ? <ShieldCheck aria-hidden="true" size={14} />
          : <ShieldOff aria-hidden="true" size={14} />}
        {actionLabel}
      </button>
      <dialog className="operator-dialog" ref={dialog}>
        <form onSubmit={review}>
          <header>
            <div>
              <span>Audited privilege change</span>
              <h2>{stage === "compose" ? actionLabel : `Confirm ${actionLabel.toLowerCase()}`}</h2>
            </div>
            <button
              aria-label="Close dialog"
              onClick={() => dialog.current?.close()}
              type="button"
            >
              <X aria-hidden="true" size={18} />
            </button>
          </header>

          {stage === "compose" ? (
            <div className="operator-dialog-body">
              <p>
                Compose the change for <strong>{operator.email}</strong>. Script permission is independent of role and remains default-deny without an explicit grant.
              </p>
              {isGrant ? (
                <>
                  <label htmlFor={scopeId}>
                    Permission scope
                    <select
                      id={scopeId}
                      onChange={(event) => setScope(event.target.value as ScriptPermissionScope)}
                      value={scope}
                    >
                      <option value="global">Global — every managed endpoint</option>
                      <option value="site">Site — one site ID</option>
                      <option value="agent">Agent — one endpoint ID</option>
                    </select>
                  </label>
                  {scope !== "global" ? (
                    <label htmlFor={targetId}>
                      {scope === "site" ? "Site ID" : "Agent ID"}
                      <input
                        id={targetId}
                        maxLength={36}
                        minLength={1}
                        onChange={(event) => setScopeTarget(event.target.value)}
                        required
                        value={scopeTarget}
                      />
                    </label>
                  ) : (
                    <p className="operator-scope-note">
                      Global scope has no target ID. The request omits <code>scope_id</code>.
                    </p>
                  )}
                </>
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
                  Required, {permissionReasonBounds.min}–{permissionReasonBounds.max} characters. The reason is recorded in the audit log.
                </small>
              </label>
            </div>
          ) : (
            <div className="operator-confirm">
              <ShieldCheck aria-hidden="true" size={25} />
              <div>
                <span>Review before applying</span>
                <h3>{isGrant ? `${scriptPermissionScopeLabel(scope)} script permission` : "Return to default deny"}</h3>
                <dl>
                  <div><dt>Operator</dt><dd>{operator.email}</dd></div>
                  {isGrant ? <div><dt>Scope</dt><dd>{scriptPermissionScopeLabel(scope)}</dd></div> : null}
                  {isGrant && scope !== "global" ? <div><dt>Target</dt><dd><code>{scopeTarget.trim()}</code></dd></div> : null}
                  <div><dt>Audit reason</dt><dd>{reason.trim()}</dd></div>
                </dl>
              </div>
            </div>
          )}

          {error ? (
            <section className="operator-error-summary" role="alert" aria-labelledby={`${reasonId}-error`}>
              <strong id={`${reasonId}-error`}>Permission was not changed</strong>
              <p>{error}</p>
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
                className={isGrant ? "primary" : "danger"}
                disabled={pending}
                onClick={confirm}
                type="button"
              >
                {pending ? "Applying…" : actionLabel}
              </button>
            )}
          </footer>
        </form>
      </dialog>
    </>
  );
}

export function SignOutEverywhereAction({
  isCurrentOperator,
  operator,
}: {
  isCurrentOperator: boolean;
  operator: OperatorRecord;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pending, setPending] = useState(false);

  async function revokeSessions() {
    setPending(true);
    setError("");
    try {
      const response = await fetch(
        `/api/operators/${encodeURIComponent(operator.id)}/revoke-tokens`,
        { method: "POST" },
      );
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { error?: string } | null;
        setError(body?.error ?? "Sessions could not be revoked.");
        return;
      }
      dialog.current?.close();
      if (isCurrentOperator) {
        window.location.assign("/login");
        return;
      }
      setNotice("All sessions revoked.");
    } catch {
      setError("Session revocation is unavailable. Check the management service.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button className="operator-action secondary" onClick={() => dialog.current?.showModal()} type="button">
        <LogOut aria-hidden="true" size={14} /> Sign out everywhere
      </button>
      {notice ? <small className="operator-action-notice" role="status"><CheckCircle2 aria-hidden="true" size={13} /> {notice}</small> : null}
      <dialog className="operator-dialog compact" ref={dialog}>
        <header>
          <div><span>Session security</span><h2>Sign out everywhere?</h2></div>
          <button aria-label="Close dialog" onClick={() => dialog.current?.close()} type="button"><X aria-hidden="true" size={18} /></button>
        </header>
        <div className="operator-dialog-body">
          <p>
            This invalidates every session issued to <strong>{operator.email}</strong>.
            The operator account remains {operator.disabled ? "disabled" : "active"}.
          </p>
          <p>This action is audited and cannot be undone. The operator can sign in again with the current password.</p>
        </div>
        {error ? (
          <section className="operator-error-summary" role="alert">
            <strong>Sessions were not revoked</strong><p>{error}</p>
          </section>
        ) : null}
        <footer>
          <button onClick={() => dialog.current?.close()} type="button">Cancel</button>
          <button className="danger" disabled={pending} onClick={revokeSessions} type="button">
            <KeyRound aria-hidden="true" size={14} /> {pending ? "Revoking…" : "Revoke all sessions"}
          </button>
        </footer>
      </dialog>
    </>
  );
}
