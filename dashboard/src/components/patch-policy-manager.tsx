// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { LoaderCircle, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import styles from "./patch-policy-manager.module.css";

import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import {
  formatPatchScope,
  type PatchApprovalPolicy,
  type PatchDefaultAction,
  type PatchScope,
  type RebootPolicy,
} from "@/lib/patch-policies-core";

const scopeOptions: Array<{ value: PatchScope; label: string }> = [
  { value: "global", label: "Global (all managed endpoints)" },
  { value: "client", label: "Client" },
  { value: "site", label: "Site" },
  { value: "agent", label: "Endpoint" },
];

export function PatchPolicyManager({
  initialPolicies,
  canAdmin,
}: {
  initialPolicies: PatchApprovalPolicy[];
  canAdmin: boolean;
}) {
  const router = useRouter();
  const [policies, setPolicies] = useState(initialPolicies);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<PatchScope>("global");
  const [scopeId, setScopeId] = useState("");
  const [defaultAction, setDefaultAction] = useState<PatchDefaultAction>("deny");
  const [requireWindow, setRequireWindow] = useState(false);
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicy>("never");
  const [rebootDelay, setRebootDelay] = useState(300);
  const [rebootRequiresNoUser, setRebootRequiresNoUser] = useState(true);
  const [maxAttempts, setMaxAttempts] = useState(2);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function responseBody<T>(response: Response): Promise<T> {
    const body = await response.json().catch(() => null) as (T & { error?: string }) | null;
    if (!response.ok || !body) throw new Error(body?.error ?? "The change could not be confirmed.");
    return body;
  }

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    setError("");
    try {
      const response = await fetch("/api/patch-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          scope,
          scope_id: scope === "global" ? null : scopeId.trim(),
          enabled: true,
          rules: [],
          default_action: defaultAction,
          require_maintenance_window: requireWindow,
          reboot_policy: rebootPolicy,
          reboot_delay_seconds: rebootDelay,
          reboot_requires_no_user: rebootRequiresNoUser,
          max_install_attempts: maxAttempts,
        }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => [...current, body.policy].sort((a, b) => a.name.localeCompare(b.name)));
      setName("");
      setScopeId("");
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be created.");
    } finally {
      setBusy(null);
    }
  }

  async function toggle(policy: PatchApprovalPolicy) {
    setBusy(`toggle:${policy.id}`);
    setError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !policy.enabled }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => current.map((item) => (item.id === policy.id ? body.policy : item)));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be updated.");
    } finally {
      setBusy(null);
    }
  }

  async function remove(policy: PatchApprovalPolicy) {
    if (!window.confirm(`Delete ${policy.name}? Endpoints it governs revert to Exempt.`)) return;
    setBusy(`delete:${policy.id}`);
    setError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
      });
      await responseBody<{ deleted: true }>(response);
      setPolicies((current) => current.filter((item) => item.id !== policy.id));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be deleted.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      {canAdmin ? (
        <section className="enrollment-panel">
          <header>
            <div>
              <span>New policy</span>
              <h2>Create a patch approval policy</h2>
              <small>New policies apply the default action to every update.</small>
            </div>
            <Plus aria-hidden="true" size={19} />
          </header>
          <form className={styles.form} onSubmit={create}>
            <fieldset className={styles.group}>
              <legend>Policy settings</legend>
              <div className={styles.grid}>
                <label className={styles.field}>
                  <span>Policy name</span>
                  <input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} placeholder="e.g. Workstation baseline" required />
                </label>
                <label className={styles.field}>
                  <span>Scope</span>
                  <select value={scope} onChange={(e) => setScope(e.target.value as PatchScope)}>
                    {scopeOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </label>
                {scope !== "global" ? (
                  <label className={styles.field}>
                    <span>{formatPatchScope(scope)} ID</span>
                    <input value={scopeId} onChange={(e) => setScopeId(e.target.value)} maxLength={36} placeholder="Target ID" required />
                  </label>
                ) : null}
                <label className={styles.field}>
                  <span>Default action</span>
                  <select value={defaultAction} onChange={(e) => setDefaultAction(e.target.value as PatchDefaultAction)}>
                    <option value="deny">Deny unmatched updates</option>
                    <option value="approve">Approve unmatched updates</option>
                  </select>
                </label>
              </div>
              <label className={styles.check}>
                <input type="checkbox" checked={requireWindow} onChange={(e) => setRequireWindow(e.target.checked)} />
                <span>Require an active maintenance window to install</span>
              </label>
            </fieldset>
            <fieldset className={styles.group}>
              <legend>Installation &amp; reboot</legend>
              <div className={styles.grid}>
                <label className={styles.field}>
                  <span>Reboot policy</span>
                  <select value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value as RebootPolicy)}>
                    <option value="never">Never</option>
                    <option value="if_required">If required</option>
                    <option value="forced">Forced</option>
                  </select>
                </label>
                <label className={styles.field}>
                  <span>Reboot delay (seconds)</span>
                  <input type="number" min={60} max={3600} value={rebootDelay} onChange={(e) => setRebootDelay(Number(e.target.value))} />
                </label>
                <label className={styles.field}>
                  <span>Max install attempts</span>
                  <input type="number" min={1} max={5} value={maxAttempts} onChange={(e) => setMaxAttempts(Number(e.target.value))} />
                </label>
              </div>
              <label className={styles.check}>
                <input type="checkbox" checked={rebootRequiresNoUser} onChange={(e) => setRebootRequiresNoUser(e.target.checked)} />
                <span>Only reboot when no user is signed in</span>
              </label>
            </fieldset>
            <div className={styles.footer}>
              <p>The policy will be enabled when created.</p>
              <button className={styles.submit} type="submit" disabled={busy === "create"}>
                {busy === "create" ? <LoaderCircle aria-hidden="true" className="spin" size={15} /> : <Plus aria-hidden="true" size={16} />}
                Create policy
              </button>
            </div>
          </form>
        </section>
      ) : null}

      <section className="enrollment-panel">
        <header><div><span>Policy register</span><h2>{policies.length} policies</h2><small>Current revisions only; each edit appends an auditable version.</small></div><ShieldCheck size={19} /></header>
        {policies.length ? (
          <div className="enrollment-table-wrap">
            <table>
              <thead><tr><th>Policy</th><th>Scope</th><th>Status</th><th>Default</th><th>Rules</th><th>Revision</th><th>Created (UTC)</th>{canAdmin ? <th>Actions</th> : null}</tr></thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td><strong>{policy.name}</strong><code>{policy.id}</code></td>
                    <td><strong>{formatPatchScope(policy.scope)}</strong><code>{policy.scope_id ?? "All managed endpoints"}</code></td>
                    <td><span className={`monitoring-status ${policy.enabled ? "enabled" : "disabled"}`}>{policy.enabled ? "Enabled" : "Disabled"}</span></td>
                    <td>{policy.default_action === "approve" ? "Approve" : "Deny"}</td>
                    <td>{policy.rule_count}</td>
                    <td><code>v{policy.current_version}</code></td>
                    <td>{formatMonitoringTimestamp(policy.created_at)}</td>
                    {canAdmin ? (
                      <td>
                        <div className={styles.actions}>
                          <button type="button" onClick={() => toggle(policy)} disabled={Boolean(busy)}>{policy.enabled ? "Disable" : "Enable"}</button>
                          <button className={styles.delete} type="button" onClick={() => remove(policy)} disabled={Boolean(busy)}><Trash2 aria-hidden="true" size={13} /> Delete</button>
                        </div>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="enrollment-empty"><ShieldCheck size={24} /><h3>No patch approval policies yet</h3><p>{canAdmin ? "Create a policy so governed endpoints leave the Exempt state." : "Until a policy is created, Windows Update installs proceed without an approval gate."}</p></div>
        )}
      </section>
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </>
  );
}
