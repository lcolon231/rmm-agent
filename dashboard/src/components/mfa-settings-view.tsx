// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ManagedSurface, useReasonConfirmation } from "./admin/managed-surface";
import { PageHeader } from "./shell/page-header";
import { StatRow, StatTile } from "./ui/stat-tile";
import { KeyRound, LifeBuoy, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import type { FormEvent } from "react";
import { useCallback, useState } from "react";

import {
  ceremonyErrorCode,
  mfaErrorMessage,
  toAssertionPayload,
  toCreationOptions,
  toRegistrationPayload,
  toRequestOptions,
  type MfaCredentialRecord,
  type MfaStatus,
} from "@/lib/mfa-core";
import { useWebAuthnSupport } from "@/lib/use-webauthn-support";

type MfaSettingsViewProps = {
  initialError: string;
  initialStatus: MfaStatus | null;
};

/**
 * Self-service security-key management (issue #67).
 *
 * The page renders the server's `status` payload and never infers state of its
 * own: `step_up_satisfied` in particular is the server's judgement about the
 * *current session*, so the prompt to re-assert appears exactly when a
 * subsequent request would actually be refused, rather than after the operator
 * has already tried and failed.
 */
export function MfaSettingsView({ initialError, initialStatus }: MfaSettingsViewProps) {
  const [status, setStatus] = useState(initialStatus);
  const confirmation = useReasonConfirmation();
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const supported = useWebAuthnSupport();

  const failFrom = useCallback(async (response: Response) => {
    const body = await response.json().catch(() => null) as
      | { error?: string; code?: string }
      | null;
    setError(
      body?.error
        ?? mfaErrorMessage(body?.code)
        ?? "That request could not be completed. Try again.",
    );
  }, []);

  const refresh = useCallback(async () => {
    const response = await fetch("/api/auth/mfa/status", { method: "GET" });
    if (response.ok) {
      setStatus(await response.json() as MfaStatus);
    }
  }, []);

  function begin() {
    setError("");
    setNotice("");
    setIsBusy(true);
  }

  async function addDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "").trim();
    begin();
    try {
      const optionsResponse = await fetch("/api/auth/mfa/credentials/options", {
        method: "POST",
      });
      if (!optionsResponse.ok) {
        await failFrom(optionsResponse);
        return;
      }
      const credential = await navigator.credentials.create({
        publicKey: toCreationOptions(await optionsResponse.json()),
      }) as PublicKeyCredential | null;
      if (!credential) {
        setError(mfaErrorMessage("cancelled") ?? "");
        return;
      }
      const response = await fetch("/api/auth/mfa/credentials", {
        body: JSON.stringify(toRegistrationPayload(credential, name)),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      form.reset();
      setNotice(`Registered "${name}".`);
      await refresh();
    } catch (error) {
      setError(mfaErrorMessage(ceremonyErrorCode(error)) ?? "");
    } finally {
      setIsBusy(false);
    }
  }

  /**
   * Re-assert an authenticator to refresh this session's step-up.
   *
   * Offered as an explicit action rather than run automatically: an unexpected
   * security-key prompt is exactly what a user should be suspicious of, so it
   * only ever appears in response to something they clicked.
   */
  async function stepUp() {
    begin();
    try {
      const optionsResponse = await fetch("/api/auth/mfa/step-up/options", {
        method: "POST",
      });
      if (!optionsResponse.ok) {
        await failFrom(optionsResponse);
        return;
      }
      const credential = await navigator.credentials.get({
        publicKey: toRequestOptions(await optionsResponse.json()),
      }) as PublicKeyCredential | null;
      if (!credential) {
        setError(mfaErrorMessage("cancelled") ?? "");
        return;
      }
      const response = await fetch("/api/auth/mfa/step-up/verify", {
        body: JSON.stringify(toAssertionPayload(credential)),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice("Confirmed. You can now change your security settings.");
      await refresh();
    } catch (error) {
      setError(mfaErrorMessage(ceremonyErrorCode(error)) ?? "");
    } finally {
      setIsBusy(false);
    }
  }

  async function renameDevice(credential: MfaCredentialRecord) {
    const name = window.prompt("New name for this security key", credential.name);
    if (name === null || name.trim() === credential.name) {
      return;
    }
    begin();
    try {
      const response = await fetch(`/api/auth/mfa/credentials/${credential.id}`, {
        body: JSON.stringify({ name: name.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "PUT",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice("Security key renamed.");
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function revokeDevice(credential: MfaCredentialRecord, reason: string) {
    begin();
    try {
      const response = await fetch(`/api/auth/mfa/credentials/${credential.id}/revoke`, {
        body: JSON.stringify({ reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice(`Removed "${credential.name}".`);
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function mintRecoveryCodes() {
    begin();
    setRecoveryCodes(null);
    try {
      const response = await fetch("/api/auth/mfa/recovery-codes", { method: "POST" });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      const body = await response.json() as { codes: string[] };
      // Shown once and never fetched again — the server does not keep them.
      setRecoveryCodes(body.codes);
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  if (!status) {
    return (
      <section className="operator-access-denied" role="alert">
        <ShieldAlert aria-hidden="true" size={28} />
        <span>Security settings unavailable</span>
        <h1>Your multi-factor state could not be loaded</h1>
        <p>{error || "The NodeLink API did not answer. Nothing was changed."}</p>
      </section>
    );
  }

  const stepUpNeeded = status.enrolled && !status.step_up_satisfied;

  return (
    <ManagedSurface><section>
<PageHeader breadcrumb={[{ label: "Administration" }, { label: "Security" }]} title="Security keys and MFA" description="Manage your sign-in methods and recovery codes." /><StatRow><StatTile icon={ShieldCheck} label="Registered keys" value={status.credentials.length} /><StatTile icon={ShieldCheck} label="Enrolled" value={status.enrolled ? "Yes" : "No"} /><StatTile icon={ShieldAlert} label="Fresh verification" value={status.step_up_satisfied ? "Satisfied" : "Required"} /></StatRow>

      {status.enforcement === "off" ? (
        <p className="" role="status">
          Multi-factor authentication is turned off for this deployment. Existing keys
          are kept but are not required or usable until it is re-enabled.
        </p>
      ) : null}

      {status.enrollment_required && !status.enrolled ? (
        <p className="" role="alert">
          <ShieldAlert aria-hidden="true" size={16} /> Your role requires a security key.
          Register one below.
        </p>
      ) : null}

      {error ? <p className="" role="alert">{error}</p> : null}
      {notice ? <p className="" role="status">{notice}</p> : null}

      {stepUpNeeded ? (
        <div className="">
          <p>
            Changing security settings needs a fresh confirmation from one of your keys.
            {status.session_methods.includes("recovery_code")
              ? " You signed in with a recovery code, which cannot confirm these changes — register a replacement key first, then confirm with it."
              : ""}
          </p>
          <button disabled={isBusy || !supported} onClick={stepUp} type="button">
            <ShieldCheck size={16} /> Confirm with a security key
          </button>
        </div>
      ) : null}

      <h2>Registered keys</h2>
      {status.credentials.length === 0 ? (
        <p>No security keys are registered on this account yet.</p>
      ) : (
        <ul className="">
          {status.credentials.map((credential) => (
            <li key={credential.id}>
              <div>
                <strong>{credential.name}</strong>
                <small>
                  Added {new Date(credential.created_at).toLocaleDateString()}
                  {credential.last_used_at
                    ? ` · last used ${new Date(credential.last_used_at).toLocaleDateString()}`
                    : " · never used"}
                  {credential.backup_state ? " · synced passkey" : ""}
                </small>
              </div>
              <div className="">
                <button
                  disabled={isBusy || stepUpNeeded}
                  onClick={() => renameDevice(credential)}
                  type="button"
                >
                  Rename
                </button>
                <button
                  disabled={isBusy || stepUpNeeded}
                  onClick={() => confirmation.ask("Remove security key?", "This key will no longer authenticate this account.", (reason) => revokeDevice(credential, reason))}
                  type="button"
                >
                  <Trash2 size={14} /> Remove
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <h2>Add a key</h2>
      {!supported ? (
        <p className="" role="alert">{mfaErrorMessage("unsupported-browser")}</p>
      ) : null}
      <form onSubmit={addDevice}>
        <label htmlFor="device-name">Device name</label>
        <input
          autoComplete="off"
          id="device-name"
          maxLength={64}
          name="name"
          placeholder="YubiKey 5C"
          required
          type="text"
        />
        <button
          disabled={isBusy || !supported || status.enforcement === "off"}
          type="submit"
        >
          <KeyRound size={16} /> Register security key
        </button>
      </form>

      <h2>Recovery codes</h2>
      <p>
        {status.recovery_codes_remaining} unused{" "}
        {status.recovery_codes_remaining === 1 ? "code" : "codes"} remaining. A recovery
        code gets you back in if you lose your key, and lets you register a replacement
        — it deliberately cannot change your security settings on its own.
      </p>
      {recoveryCodes ? (
        <div className="" role="status">
          <p>
            <strong>Save these now.</strong> They are shown once and cannot be retrieved
            again. Any codes from a previous batch have stopped working.
          </p>
          <ul>
            {recoveryCodes.map((code) => <li key={code}><code>{code}</code></li>)}
          </ul>
        </div>
      ) : null}
      <button
        disabled={isBusy || !status.enrolled || stepUpNeeded}
        onClick={() => confirmation.ask("Replace recovery codes?", "All previous recovery codes stop working. This API does not store the reason.", mintRecoveryCodes)}
        type="button"
      >
        <LifeBuoy size={16} /> Generate new recovery codes
      </button>
    {confirmation.dialog}</section></ManagedSurface>
  );
}
