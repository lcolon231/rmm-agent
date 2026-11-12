// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ManagedSurface, useReasonConfirmation } from "./admin/managed-surface";
import { PageHeader } from "./shell/page-header";
import { StatRow, StatTile } from "./ui/stat-tile";
import { CheckCircle2, KeyRound, RefreshCw, ShieldAlert, Siren } from "lucide-react";
import type { FormEvent } from "react";
import { useCallback, useState } from "react";

import {
  adminSessionErrorMessage,
  describeClient,
  type BreakGlassAccountRecord,
  type BreakGlassActivationRecord,
  type BreakGlassStatus,
} from "@/lib/admin-sessions-core";

type BreakGlassViewProps = {
  initialError: string;
  initialAccounts: BreakGlassAccountRecord[] | null;
  initialActivations: BreakGlassActivationRecord[] | null;
  initialStatus: BreakGlassStatus | null;
};

/**
 * Provisioning and review for emergency access (issue #69).
 *
 * The screen is deliberately uncomfortable. A break-glass credential is the one
 * thing in the deployment that authenticates with no second factor, so the page
 * leads with what is outstanding rather than with what can be created: an
 * unreviewed activation is an open incident and appears above everything else.
 */
export function BreakGlassView({
  initialError,
  initialAccounts,
  initialActivations,
  initialStatus,
}: BreakGlassViewProps) {
  const [accounts, setAccounts] = useState(initialAccounts ?? []);
  const [activations, setActivations] = useState(initialActivations ?? []);
  const [status, setStatus] = useState(initialStatus);
  const confirmation = useReasonConfirmation();
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  /** Shown exactly once, immediately after minting or rotating. */
  const [issued, setIssued] = useState<{ label: string; credential: string } | null>(null);

  const failFrom = useCallback(async (response: Response) => {
    const body = await response.json().catch(() => null) as
      | { error?: string; code?: string }
      | null;
    setError(
      body?.error
        ?? adminSessionErrorMessage(body?.code)
        ?? "That request could not be completed. Try again.",
    );
  }, []);

  const refresh = useCallback(async () => {
    const [accountsResponse, activationsResponse] = await Promise.all([
      fetch("/api/auth/break-glass", { method: "GET" }),
      fetch("/api/auth/break-glass/activations", { method: "GET" }),
    ]);
    if (accountsResponse.ok) {
      setAccounts(await accountsResponse.json() as BreakGlassAccountRecord[]);
    }
    if (activationsResponse.ok) {
      const rows = await activationsResponse.json() as BreakGlassActivationRecord[];
      setActivations(rows);
      setStatus((previous) => previous
        ? { ...previous, unreviewed_activations: rows.filter((row) => !row.reviewed_at).length }
        : previous);
    }
  }, []);

  function begin() {
    setError("");
    setNotice("");
    setIsBusy(true);
  }

  async function createAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const label = String(data.get("label") ?? "").trim();
    const reason = String(data.get("reason") ?? "").trim();
    begin();
    setIssued(null);
    try {
      const response = await fetch("/api/auth/break-glass", {
        body: JSON.stringify({ label, reason }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      const body = await response.json() as {
        account: BreakGlassAccountRecord;
        credential: string;
      };
      form.reset();
      setIssued({ label: body.account.label, credential: body.credential });
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function rotate(account: BreakGlassAccountRecord, reason: string) {
    begin();
    setIssued(null);
    try {
      const response = await fetch(`/api/auth/break-glass/${account.id}/rotate`, {
        body: JSON.stringify({ reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      const body = await response.json() as { credential: string };
      setIssued({ label: account.label, credential: body.credential });
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function setDisabled(account: BreakGlassAccountRecord, disabled: boolean, reason: string) {
    begin();
    try {
      const response = await fetch(`/api/auth/break-glass/${account.id}/disabled`, {
        body: JSON.stringify({ disabled, reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "PUT",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice(disabled ? "Credential disabled." : "Credential re-enabled.");
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function review(activation: BreakGlassActivationRecord, note: string) {
    begin();
    try {
      const response = await fetch(
        `/api/auth/break-glass/activations/${activation.id}/review`,
        {
          body: JSON.stringify({ note: note.trim() }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice("Activation reviewed.");
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  const unreviewed = activations.filter((row) => !row.reviewed_at);

  return (
    <ManagedSurface><section>
<PageHeader breadcrumb={[{ label: "Administration" }, { label: "Break-glass" }]} title="Emergency access" description="Manage emergency credentials and review recorded activations." /><StatRow><StatTile icon={KeyRound} label="Credentials" value={initialAccounts ? accounts.length : "—"} /><StatTile icon={Siren} label="Awaiting review" value={initialActivations ? unreviewed.length : "—"} /><StatTile icon={ShieldAlert} label="Disabled" value={initialAccounts ? accounts.filter((account) => account.disabled_at).length : "—"} /></StatRow>

      {status && !status.enabled ? (
        <p className="" role="status">
          Break-glass is turned off for this deployment. Existing credentials are
          retained but cannot be activated.
        </p>
      ) : null}

      {unreviewed.length > 0 ? (
        <p className="" role="alert">
          <Siren aria-hidden="true" size={16} />{" "}
          {unreviewed.length} emergency {unreviewed.length === 1 ? "activation" : "activations"}
          {" "}awaiting review.
        </p>
      ) : null}

      {error ? <p className="" role="alert">{error}</p> : null}
      {notice ? <p className="" role="status">{notice}</p> : null}

      {issued ? (
        <div className="" role="status">
          <p>
            <strong>Save this now.</strong> It is shown once and cannot be
            retrieved again. Print it, seal it, and record where the envelope is
            stored. Any previous credential for &ldquo;{issued.label}&rdquo; has
            stopped working.
          </p>
          <ul><li><code>{issued.credential}</code></li></ul>
        </div>
      ) : null}

      <h2>Activations</h2>
      {activations.length === 0 ? (
        <p>No activation records are loaded.</p>
      ) : (
        <ul className="">
          {activations.map((activation) => (
            <li key={activation.id}>
              <div>
                <strong>
                  {new Date(activation.activated_at).toLocaleString()}
                  {activation.reviewed_at
                    ? <span className="">Reviewed</span>
                    : <span className="">Open</span>}
                </strong>
                <small>
                  {describeClient(activation.user_agent)}
                  {activation.source_ip ? ` · ${activation.source_ip}` : ""}
                  {" · "}
                  {activation.reason}
                  {activation.reviewed_by_email
                    ? ` · reviewed by ${activation.reviewed_by_email}`
                    : ""}
                </small>
              </div>
              {activation.reviewed_at ? (
                <CheckCircle2 aria-label="Reviewed" size={16} />
              ) : (
                <button disabled={isBusy} onClick={() => confirmation.ask("Review emergency activation?", "Your findings are submitted for this activation.", (note) => review(activation, note))} type="button">
                  Review
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <h2>Credentials</h2>
      {accounts.length === 0 ? (
        <p className="">
          <ShieldAlert aria-hidden="true" size={16} /> No emergency credential is
          provisioned. 
        </p>
      ) : (
        <ul className="">
          {accounts.map((account) => (
            <li key={account.id}>
              <div>
                <strong>
                  {account.label}
                  {account.disabled_at
                    ? <span className="">Disabled</span>
                    : null}
                </strong>
                <small>
                  Fingerprint <code>{account.credential_fingerprint.slice(0, 16)}</code>
                  {" · used "}{account.activation_count}{" "}
                  {account.activation_count === 1 ? "time" : "times"}
                  {account.rotated_at
                    ? ` · rotated ${new Date(account.rotated_at).toLocaleDateString()}`
                    : ""}
                </small>
              </div>
              <div className="">
                <button disabled={isBusy} onClick={() => confirmation.ask("Rotate emergency credential?", "The previous credential stops working immediately. Save the replacement securely.", (reason) => rotate(account, reason))} type="button">
                  <RefreshCw size={14} /> Rotate
                </button>
                <button
                  disabled={isBusy}
                  onClick={() => confirmation.ask(account.disabled_at ? "Enable emergency account?" : "Disable emergency account?", "This changes whether the credential can start an emergency session.", (reason) => setDisabled(account, account.disabled_at === null, reason))}
                  type="button"
                >
                  {account.disabled_at ? "Enable" : "Disable"}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <h2>Provision a credential</h2>
      <form onSubmit={createAccount}>
        <label htmlFor="bg-label">Where the envelope will be stored</label>
        <input
          autoComplete="off"
          id="bg-label"
          maxLength={120}
          name="label"
          placeholder="Safe, London office"
          required
          type="text"
        />
        <label htmlFor="bg-reason">Reason</label>
        <input
          autoComplete="off"
          id="bg-reason"
          maxLength={500}
          name="reason"
          placeholder="Initial emergency provisioning"
          required
          type="text"
        />
        <button disabled={isBusy} type="submit">
          <KeyRound size={16} /> Create emergency credential
        </button>
      </form>
    {confirmation.dialog}</section></ManagedSurface>
  );
}
