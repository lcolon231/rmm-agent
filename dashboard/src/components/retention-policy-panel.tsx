// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Archive, KeyRound, ShieldAlert, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useId, useState } from "react";

import { Button, Input, Select, cardClass, cx } from "./ui";
import {
  RETENTION_CATEGORY_LABELS,
  RETENTION_CATEGORY_NAMES,
  RETENTION_SOURCE_LABELS,
  conflictChanges,
  draftFromPolicy,
  formatRetention,
  retentionErrorMessage,
  shortenedCategories,
  validateDraft,
  type DraftMode,
  type RetentionCategory,
  type RetentionCategoryName,
  type RetentionChange,
  type RetentionDraft,
  type RetentionPolicy,
  type RetentionValues,
} from "@/lib/retention-policy-core";
import { performStepUp as defaultStepUp, type StepUpResult } from "@/lib/step-up-client";

type Write = { method: "PUT" | "DELETE"; body: Record<string, unknown> };
type PendingConfirmation = { write: Write; kind: "save" | "reset"; shortened: RetentionCategory[]; next: RetentionValues };
type FieldErrors = Partial<Record<RetentionCategoryName, string>>;

type RetentionPolicyPanelProps = {
  clientId: string;
  initialPolicy: RetentionPolicy;
  /** Injected for tests; defaults to the WebAuthn step-up ceremony. */
  performStepUp?: () => Promise<StepUpResult>;
};

function bounds(entry: RetentionCategory): string {
  return entry.maximum === 0
    ? `At least ${formatRetention(entry.minimum, entry.unit)}`
    : `${formatRetention(entry.minimum, entry.unit)} – ${formatRetention(entry.maximum, entry.unit)}`;
}

function savedValue(value: number | null, unit: RetentionCategory["unit"]): string {
  return value === null ? "Not set" : formatRetention(value, unit);
}

function auditLink(event: string, clientId: string): string {
  return `/audit?${new URLSearchParams({ event, organization: clientId })}`;
}

function allInherited(): RetentionValues {
  return Object.fromEntries(RETENTION_CATEGORY_NAMES.map((name) => [name, null])) as RetentionValues;
}

/**
 * A client's retention policy (issue #311): what is kept, why, and within which
 * platform bounds, with an editor for client admins.
 *
 * Every save carries `expected_version`, so a concurrent change is reported
 * (409) rather than overwritten. Any save that shortens a category's effective
 * retention must be confirmed first, because the next sweep deletes the data.
 * Edit controls follow the server's `can_edit` hint; the server still enforces
 * the role, step-up and bounds on every write.
 */
export function RetentionPolicyPanel({ clientId, initialPolicy, performStepUp = defaultStepUp }: RetentionPolicyPanelProps) {
  const [policy, setPolicy] = useState(initialPolicy);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<RetentionDraft>(() => draftFromPolicy(initialPolicy));
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [confirmation, setConfirmation] = useState<PendingConfirmation | null>(null);
  const [stepUpWrite, setStepUpWrite] = useState<Write | null>(null);
  const [conflict, setConflict] = useState<{ changes: RetentionChange[]; setBy: string | null } | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const headingId = useId();
  const endpoint = `/api/clients/${encodeURIComponent(clientId)}/retention-policy`;
  const hasOverrides = policy.categories.some((entry) => entry.override !== null);

  function startEditing() {
    setDraft(draftFromPolicy(policy));
    setFieldErrors({});
    setConflict(null);
    setNotice("");
    setError("");
    setEditing(true);
  }

  function updateField(name: RetentionCategoryName, change: Partial<RetentionDraft[RetentionCategoryName]>) {
    setDraft((current) => ({ ...current, [name]: { ...current[name], ...change } }));
    setFieldErrors((current) => ({ ...current, [name]: undefined }));
  }

  /** Confirm first if any effective value would drop, otherwise write now. */
  function proceed(kind: "save" | "reset", write: Write, next: RetentionValues) {
    const shortened = shortenedCategories(policy, next);
    if (shortened.length) {
      setConfirmation({
        kind,
        write,
        next,
        shortened: policy.categories.filter((entry) => shortened.includes(entry.name)),
      });
      return;
    }
    void submit(write);
  }

  function save() {
    setError("");
    setNotice("");
    const result = validateDraft(policy, draft);
    if (!result.ok) {
      setFieldErrors(result.errors);
      return;
    }
    proceed("save", { method: "PUT", body: { expected_version: policy.version, ...result.values } }, result.values);
  }

  function reset() {
    setError("");
    setNotice("");
    proceed("reset", { method: "DELETE", body: { expected_version: policy.version } }, allInherited());
  }

  async function reloadAfterConflict() {
    const response = await fetch(endpoint, { method: "GET" });
    const body = await response.json().catch(() => null) as { policy?: RetentionPolicy } | null;
    if (!response.ok || !body?.policy || !Array.isArray(body.policy.categories)) {
      setError("Another administrator changed this policy, and it could not be reloaded. Refresh the page.");
      return;
    }
    setConflict({ changes: conflictChanges(policy, body.policy), setBy: body.policy.setBy });
    setPolicy(body.policy);
    setDraft(draftFromPolicy(body.policy));
  }

  async function submit(write: Write) {
    setConfirmation(null);
    setStepUpWrite(null);
    setConflict(null);
    setBusy(true);
    try {
      const response = await fetch(endpoint, {
        method: write.method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(write.body),
      });
      const body = await response.json().catch(() => null) as
        | { policy?: RetentionPolicy; error?: string; code?: string | null; category?: RetentionCategoryName | null }
        | null;
      if (response.ok && body?.policy) {
        setPolicy(body.policy);
        setDraft(draftFromPolicy(body.policy));
        setEditing(false);
        setNotice(write.method === "DELETE" ? "Retention reset to platform defaults." : "Retention policy saved.");
        return;
      }
      if (response.status === 403 && body?.code === "step_up_required") {
        setStepUpWrite(write);
        return;
      }
      if (response.status === 409 && body?.code === "retention_policy_conflict") {
        await reloadAfterConflict();
        return;
      }
      const message = retentionErrorMessage(body?.code) ?? body?.error ?? "The retention policy could not be saved.";
      if (response.status === 422 && body?.category) {
        setFieldErrors({ [body.category]: message });
        return;
      }
      setError(message);
    } catch {
      setError("The retention policy change could not be confirmed. Refresh before trying again.");
    } finally {
      setBusy(false);
    }
  }

  async function confirmStepUp() {
    const write = stepUpWrite;
    if (!write) return;
    setBusy(true);
    setError("");
    const result = await performStepUp();
    setBusy(false);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    await submit(write);
  }

  return (
    <section aria-labelledby={headingId} className={cx(cardClass, "grid gap-4 p-5")}>
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1">
          <h2 id={headingId} className="m-0 text-lg font-semibold text-(--ink)">Retention</h2>
          <p className="m-0 text-sm text-(--slate)">
            How long this client&apos;s data is kept before the retention sweep prunes it.
            {policy.setBy ? ` Last changed by ${policy.setBy}.` : " This client uses the platform defaults."}
          </p>
        </div>
        {policy.canEdit && !editing ? (
          <Button onClick={startEditing}>Edit retention</Button>
        ) : null}
      </header>

      {policy.pruningSuspended ? (
        <div role="status" aria-label="Pruning suspended" className="flex gap-3 rounded-lg bg-(--amber-soft) p-3 text-sm text-(--ink)">
          <Archive size={18} aria-hidden="true" className="mt-0.5 shrink-0" />
          <p className="m-0">
            <strong>Pruning suspended.</strong> A client-wide legal hold is active, so nothing of this
            client&apos;s is pruned until it is released.{" "}
            <Link href={auditLink("evidence_legal_hold.placed", clientId)}>Review evidence vault holds</Link>
          </p>
        </div>
      ) : null}

      {notice ? <p role="status" className="m-0 text-sm text-(--green-strong,#1d6b3a)">{notice}</p> : null}
      {error ? <p role="alert" className="m-0 text-sm text-(--red,#b42318)">{error}</p> : null}

      {conflict ? (
        <div role="alert" aria-label="Policy changed by another administrator" className="grid gap-1 rounded-lg border border-(--line) p-3 text-sm">
          <p className="m-0 font-semibold text-(--ink)">
            {conflict.setBy ?? "Another administrator"} changed this policy while you were editing. Nothing of yours was saved.
          </p>
          {conflict.changes.length ? (
            <ul className="m-0 pl-5">
              {conflict.changes.map((change) => (
                <li key={change.name}>
                  {RETENTION_CATEGORY_LABELS[change.name].label}: {savedValue(change.before, change.unit)} → {savedValue(change.after, change.unit)}
                </li>
              ))}
            </ul>
          ) : <p className="m-0">No saved values differ; only the version moved on.</p>}
          <p className="m-0 text-(--slate)">The editor now shows their policy. Review it, then save again.</p>
        </div>
      ) : null}

      {stepUpWrite ? (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded-lg border border-(--line) p-3 text-sm">
          <KeyRound size={18} aria-hidden="true" />
          <span>{retentionErrorMessage("step_up_required")}</span>
          <Button variant="primary" disabled={busy} onClick={() => void confirmStepUp()}>Confirm with security key</Button>
        </div>
      ) : null}

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="text-xs text-(--muted)">
              <th scope="col" className="py-2 pr-3 font-semibold">Category</th>
              <th scope="col" className="py-2 pr-3 font-semibold">Effective</th>
              <th scope="col" className="py-2 pr-3 font-semibold">Source</th>
              <th scope="col" className="py-2 pr-3 font-semibold">Saved override</th>
              <th scope="col" className="py-2 pr-3 font-semibold">Platform default</th>
              <th scope="col" className="py-2 font-semibold">Allowed</th>
            </tr>
          </thead>
          <tbody>
            {policy.categories.map((entry) => (
              <tr key={entry.name} className="border-t border-(--line) align-top">
                <th scope="row" className="py-2 pr-3 font-normal">
                  <span className="block font-semibold text-(--ink)">{RETENTION_CATEGORY_LABELS[entry.name].label}</span>
                  <span className="block text-xs text-(--muted)">{RETENTION_CATEGORY_LABELS[entry.name].description}</span>
                </th>
                <td className="py-2 pr-3 font-semibold">{formatRetention(entry.effective, entry.unit)}</td>
                <td className="py-2 pr-3">{RETENTION_SOURCE_LABELS[entry.source]}</td>
                <td className="py-2 pr-3">{savedValue(entry.override, entry.unit)}</td>
                <td className="py-2 pr-3">{formatRetention(entry.platformDefault, entry.unit)}</td>
                <td className="py-2">{bounds(entry)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && policy.canEdit ? (
        <form
          className="grid gap-4 border-t border-(--line) pt-4"
          onSubmit={(event) => { event.preventDefault(); save(); }}
          noValidate
        >
          <div className="grid gap-4 sm:grid-cols-2">
            {policy.categories.map((entry) => {
              const field = draft[entry.name];
              const label = RETENTION_CATEGORY_LABELS[entry.name].label;
              const fieldError = fieldErrors[entry.name];
              return (
                <fieldset key={entry.name} className="m-0 grid gap-2 border-0 p-0">
                  <Select
                    label={`${label} retention`}
                    value={field.mode}
                    error={field.mode === "custom" ? undefined : fieldError}
                    onChange={(event) => updateField(entry.name, { mode: event.target.value as DraftMode })}
                  >
                    <option value="inherit">Inherit platform default ({formatRetention(entry.platformDefault, entry.unit)})</option>
                    {entry.foreverAllowed ? <option value="forever">Keep forever</option> : null}
                    <option value="custom">Custom value</option>
                  </Select>
                  {field.mode === "custom" ? (
                    <Input
                      label={`${label} value`}
                      inputMode="numeric"
                      value={field.value}
                      hint={`${bounds(entry)} (${entry.unit === "count" ? "snapshots" : "days"})`}
                      error={fieldError}
                      onChange={(event) => updateField(entry.name, { value: event.target.value })}
                    />
                  ) : null}
                </fieldset>
              );
            })}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" disabled={busy}>Save retention</Button>
            <Button disabled={busy} onClick={() => { setEditing(false); setFieldErrors({}); }}>Cancel</Button>
            {hasOverrides ? (
              <Button variant="danger" disabled={busy} onClick={reset}>Reset to platform defaults</Button>
            ) : null}
          </div>
        </form>
      ) : null}

      {confirmation ? (
        <ShortenConfirmation
          confirmation={confirmation}
          busy={busy}
          suspended={policy.pruningSuspended}
          onCancel={() => setConfirmation(null)}
          onConfirm={() => void submit(confirmation.write)}
        />
      ) : null}

      <p className="m-0 flex flex-wrap gap-x-4 gap-y-1 text-xs text-(--slate)">
        <ShieldAlert size={14} aria-hidden="true" />
        <span>Recent purges in the audit log:</span>
        <Link href={auditLink("retention.purged", clientId)}>Purged</Link>
        <Link href={auditLink("retention.purge_suspended", clientId)}>Suspended</Link>
        <Link href={auditLink("retention.purge_failed", clientId)}>Failed</Link>
      </p>
    </section>
  );
}

function ShortenConfirmation({ confirmation, busy, suspended, onCancel, onConfirm }: {
  confirmation: PendingConfirmation;
  busy: boolean;
  suspended: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const titleId = useId();
  const bodyId = useId();
  return (
    <div role="alertdialog" aria-labelledby={titleId} aria-describedby={bodyId} className="grid gap-3 rounded-lg border border-(--line) bg-(--amber-soft) p-4 text-sm">
      <h3 id={titleId} className="m-0 flex items-center gap-2 text-base font-semibold text-(--ink)">
        <TriangleAlert size={18} aria-hidden="true" />
        Shorten retention?
      </h3>
      <div id={bodyId} className="grid gap-2">
        <p className="m-0">
          This {confirmation.kind === "reset" ? "reset" : "change"} keeps less data in:
        </p>
        <ul className="m-0 pl-5">
          {confirmation.shortened.map((entry) => (
            <li key={entry.name}>
              {RETENTION_CATEGORY_LABELS[entry.name].label}: {formatRetention(entry.effective, entry.unit)} →{" "}
              {formatRetention(confirmation.next[entry.name] ?? entry.platformDefault, entry.unit)}
            </li>
          ))}
        </ul>
        <p className="m-0 font-semibold">
          {suspended
            ? "Pruning is suspended by a legal hold now, but once it is released, data outside the new retention is deleted and cannot be recovered."
            : "The next retention sweep deletes data outside the new retention. Pruned data cannot be recovered."}
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="danger" disabled={busy} onClick={onConfirm} autoFocus>
          {confirmation.kind === "reset" ? "Reset and save" : "Shorten and save"}
        </Button>
        <Button disabled={busy} onClick={onCancel}>Back to editing</Button>
      </div>
    </div>
  );
}
