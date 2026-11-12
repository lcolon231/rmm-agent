// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CircleCheck, History, Play, ShieldAlert, Siren, Timer, TriangleAlert } from "lucide-react";
import type { FormEvent } from "react";
import { useCallback, useId, useState } from "react";

import { formatAuditTimestamp } from "@/lib/audit-core";
import {
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  OVERRIDE_COMMAND_KINDS,
  canReview,
  canRevoke,
  canRun,
  formatTimeRemaining,
  isLive,
  isValidJustification,
  isValidNote,
  notificationLabel,
  parsePayloadText,
  sortForReview,
  statusLabel,
  type EmergencyOverride,
  type EmergencyOverrideDetail,
} from "@/lib/emergency-overrides-core";
import type { EndpointListItem } from "@/lib/endpoint-list";

import { PageHeader, PageStack } from "./shell/page-header";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { DataTable, PrimaryCell, TableFooter, type Column } from "./ui/data-table";
import { CodeBlock, DefinitionList, Drawer } from "./ui/drawer";
import { Input, Select, Textarea } from "./ui/field";
import { FilterBar, FilterChip } from "./ui/filter-bar";
import { StatRow, StatTile } from "./ui/stat-tile";
import { EmptyState, ErrorState } from "./ui/states";
import { StatusBadge } from "./ui/status-badge";
import { useModal } from "./ui/use-modal";

type EmergencyOverrideViewProps = {
  initialError: string;
  initialOverrides: EmergencyOverride[] | null;
  initialEndpoints: EndpointListItem[];
  viewerOperatorId: string | null;
  viewerIsAdmin: boolean;
};

type Filter = "all" | "unreviewed" | "reviewed";

const BREADCRUMB = [{ label: "Compliance" }, { label: "Emergency overrides" }];
const DESCRIPTION =
  "For urgent situations when a second approver cannot be reached. Each one runs one exact command, expires within an hour, is emailed to the alert recipients, and stays open here until a different administrator reviews it.";
const NOTE_ERROR = "Enter a printable note of 10 to 512 characters.";
const mono = "font-(family-name:--font-data)";

function sentence(text: string) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

type TimelineEntry = { at: string; text: string; pending?: boolean };

/** Only timestamps the service recorded; expiry is shown as future until it passes. */
function timeline(override: EmergencyOverride, now: Date): TimelineEntry[] {
  const entries: TimelineEntry[] = [{ at: override.created_at, text: `Activated by ${override.activated_by_email}` }];
  if (override.notified_at) entries.push({ at: override.notified_at, text: sentence(notificationLabel(override)) });
  else entries.push({ at: override.created_at, text: sentence(notificationLabel(override)), pending: override.notification_error === null });
  if (override.consumed_at) entries.push({ at: override.consumed_at, text: "Command dispatched; the override is spent" });
  if (override.revoked_at) entries.push({ at: override.revoked_at, text: `Revoked${override.revoked_by_email ? ` by ${override.revoked_by_email}` : ""}` });
  if (override.status === "expired" || (!override.consumed_at && !override.revoked_at && Date.parse(override.expires_at) <= now.getTime())) {
    entries.push({ at: override.expires_at, text: "Expired" });
  } else if (isLive(override, now)) {
    entries.push({ at: override.expires_at, text: `Expires (${formatTimeRemaining(override.expires_at, now)})`, pending: true });
  }
  if (override.reviewed_at) entries.push({ at: override.reviewed_at, text: `Reviewed${override.reviewed_by_email ? ` by ${override.reviewed_by_email}` : ""}` });
  else entries.push({ at: "", text: "Not reviewed yet", pending: true });
  // Recorded events in time order; anything still to come goes last.
  const done = entries.filter((entry) => !entry.pending).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  return [...done, ...entries.filter((entry) => entry.pending)];
}

/**
 * Justified emergency overrides (issue #65).
 *
 * The screen is deliberately uncomfortable, like the break-glass page. An
 * override is the one place a single person's word stands in for a second
 * reviewer, so the page leads with the debts it creates — unreviewed
 * overrides — and keeps activation behind a warning.
 *
 * Nothing here is a security decision. The management service refuses an
 * override unless the policy opted in and the activator is a tenant admin who
 * could run the command anyway; it binds the override to the exact payload,
 * spends it once, expires it on its own clock, and refuses self-review.
 */
export function EmergencyOverrideView({
  initialError,
  initialOverrides,
  initialEndpoints,
  viewerOperatorId,
  viewerIsAdmin,
}: EmergencyOverrideViewProps) {
  const [overrides, setOverrides] = useState<EmergencyOverride[]>(initialOverrides ?? []);
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [justification, setJustification] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [note, setNote] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activating, setActivating] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState("");

  const replace = useCallback((updated: EmergencyOverrideDetail) => {
    setOverrides((current) => {
      const exists = current.some((entry) => entry.id === updated.id);
      return exists ? current.map((entry) => (entry.id === updated.id ? updated : entry)) : [updated, ...current];
    });
  }, []);

  /** Sends one action. Returns an error message, or null when it succeeded. */
  const act = useCallback(
    async (overrideId: string, action: "revoke" | "review" | "run", text?: string): Promise<string | null> => {
      setError("");
      setNotice("");
      setBusyId(overrideId);
      try {
        const body = action === "run" ? undefined : JSON.stringify(action === "revoke" ? { reason: text } : { note: text });
        const response = await fetch(`/api/emergency-overrides/${overrideId}/${action}`, {
          ...(body ? { body, headers: { "Content-Type": "application/json" } } : {}),
          method: "POST",
        });
        const payload = (await response.json().catch(() => null)) as { override?: EmergencyOverrideDetail; error?: string } | null;
        if (!response.ok || !payload?.override) return payload?.error ?? "That request could not be completed. Try again.";
        replace(payload.override);
        setNotice(
          action === "run"
            ? `Command dispatched as ${payload.override.consumed_command_id?.slice(0, 8) ?? "a run"}. The override is spent.`
            : action === "revoke"
              ? "Override revoked."
              : "Override reviewed.",
        );
        return null;
      } finally {
        setBusyId(null);
      }
    },
    [replace],
  );

  async function review(override: EmergencyOverride) {
    if (!isValidNote(note)) {
      setError(NOTE_ERROR);
      return;
    }
    const failure = await act(override.id, "review", note.trim());
    if (failure) setError(failure);
    else setNote("");
  }

  async function confirmRevoke(reason: string) {
    if (!revokingId) return;
    if (!isValidNote(reason)) {
      setDialogError("Enter a printable reason of 10 to 512 characters.");
      return;
    }
    setDialogError("");
    const failure = await act(revokingId, "revoke", reason);
    if (failure) setDialogError(failure);
    else setRevokingId(null);
  }

  async function confirmRun() {
    if (!runningId) return;
    setDialogError("");
    const failure = await act(runningId, "run");
    if (failure) setDialogError(failure);
    else setRunningId(null);
  }

  async function activate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const agentId = String(data.get("agent_id") ?? "").trim();
    const kind = String(data.get("kind") ?? "");
    const minutes = Number(data.get("ttl_minutes") ?? DEFAULT_TTL_SECONDS / 60);
    const payload = parsePayloadText(payloadText);
    if (payload === null) {
      setError("The payload must be a JSON object (or empty).");
      return;
    }
    if (!isValidJustification(justification)) {
      setError("Enter a printable justification of 20 to 512 characters.");
      return;
    }
    setError("");
    setNotice("");
    setBusyId("activate");
    try {
      const response = await fetch("/api/emergency-overrides", {
        body: JSON.stringify({
          agent_id: agentId,
          kind,
          payload,
          justification,
          ttl_seconds: Math.min(MAX_TTL_SECONDS, Math.max(MIN_TTL_SECONDS, Math.round(minutes * 60))),
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        setError(body?.error ?? "That request could not be completed. Try again.");
        return;
      }
      const body = (await response.json()) as { override: EmergencyOverrideDetail };
      replace(body.override);
      form.reset();
      setJustification("");
      setPayloadText("");
      setActivating(false);
      setNotice(
        body.override.notified_at
          ? "Override activated and recipients notified. Use it before it expires; it must still be reviewed."
          : "Override activated, but nobody was notified. Tell someone yourself; it must still be reviewed.",
      );
    } finally {
      setBusyId(null);
    }
  }

  if (initialOverrides === null) {
    return (
      <PageStack>
        <PageHeader breadcrumb={BREADCRUMB} title="Emergency overrides" description={DESCRIPTION} />
        <ErrorState title="Emergency overrides could not be loaded" body={initialError || "The management service did not answer. Try again"} />
      </PageStack>
    );
  }

  const now = new Date();
  const ordered = sortForReview(overrides);
  const unreviewed = ordered.filter((entry) => entry.reviewed_at === null);
  const live = ordered.filter((entry) => isLive(entry, now));
  const visible = ordered.filter((entry) => (filter === "all" ? true : filter === "unreviewed" ? entry.reviewed_at === null : entry.reviewed_at !== null));
  const selected = ordered.find((entry) => entry.id === selectedId) ?? null;
  const revoking = ordered.find((entry) => entry.id === revokingId) ?? null;
  const running = ordered.find((entry) => entry.id === runningId) ?? null;
  const drawerOpen = selected !== null || activating;

  const columns: Column<EmergencyOverride>[] = [
    { key: "override", header: "Override", cell: (row) => <PrimaryCell mono title={row.kind} sub={`Stood in for ${row.required_approvals} ${row.required_approvals === 1 ? "approval" : "approvals"}`} /> },
    {
      key: "review",
      header: "Review",
      cell: (row) => (row.reviewed_at ? <StatusBadge tone="ok">Reviewed</StatusBadge> : <StatusBadge tone="warn">Needs review</StatusBadge>),
    },
    {
      key: "by",
      header: "Used by",
      cell: (row) => (
        <span>
          <span className={`${mono} text-[13px]`}>{row.activated_by_email}</span>
          {row.activated_by_operator_id === viewerOperatorId ? <span className="text-(--muted)"> (you)</span> : null}
        </span>
      ),
    },
    { key: "reason", header: "Reason given", cell: (row) => <span className="block max-w-[320px] truncate">{row.justification}</span> },
    {
      key: "state",
      header: "State",
      cell: (row) => (
        <span className="grid gap-0.5">
          <span className="font-semibold text-(--ink)">{statusLabel(row.status)}</span>
          {isLive(row, now) ? <span className="text-xs text-[#89500b]">{formatTimeRemaining(row.expires_at, now)}</span> : null}
        </span>
      ),
    },
    { key: "when", header: "When", cell: (row) => formatAuditTimestamp(row.created_at) },
  ];

  const state =
    ordered.length === 0 ? (
      <EmptyState icon={Siren} title="No overrides yet" body="No emergency override has ever been activated." />
    ) : visible.length === 0 ? (
      <EmptyState title="No overrides match" body="No override is in this state." actionLabel="Clear filters" onAction={() => setFilter("all")} />
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={BREADCRUMB}
        title="Emergency overrides"
        description={DESCRIPTION}
        actions={
          viewerIsAdmin ? (
            <Button
              variant="primary"
              icon={Siren}
              onClick={() => {
                setError("");
                setSelectedId(null);
                setActivating(true);
              }}
            >
              Request an override
            </Button>
          ) : null
        }
      />
      <StatRow>
        <StatTile icon={Siren} label="Active now" tone={live.length > 0 ? "warn" : "ok"} value={live.length} sub={live.length > 0 ? "Can run without a second approver" : "None in use"} />
        <StatTile icon={TriangleAlert} label="Needs review" tone={unreviewed.length > 0 ? "warn" : "ok"} value={unreviewed.length} sub="Waiting for another administrator" />
        <StatTile icon={History} label="On record" tone="info" value={ordered.length} sub="The 100 most recent are loaded" />
        <StatTile icon={Timer} label="Time limit" tone="info" value={`${DEFAULT_TTL_SECONDS / 60} min`} sub={`Default; ${MIN_TTL_SECONDS / 60} to ${MAX_TTL_SECONDS / 60} minutes allowed`} />
      </StatRow>

      {unreviewed.length > 0 ? (
        <p role="alert" className="m-0 flex items-center gap-2 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-[#89500b]">
          <Siren aria-hidden="true" size={16} /> {unreviewed.length} {unreviewed.length === 1 ? "override" : "overrides"} awaiting review.
        </p>
      ) : null}
      {live.length > 0 ? (
        <p role="status" className="m-0 flex items-center gap-2 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-[#89500b]">
          <ShieldAlert aria-hidden="true" size={16} /> {live.length} live {live.length === 1 ? "override" : "overrides"} can run without a second approver right now.
        </p>
      ) : null}
      {error && !drawerOpen ? (
        <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm text-(--red)">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="m-0 rounded-lg bg-(--success-soft) px-4 py-3 text-sm text-(--success)">
          {notice}
        </p>
      ) : null}

      <DataTable
        caption="Emergency overrides"
        columns={columns}
        rows={visible}
        rowKey={(row) => row.id}
        rowLabel={(row) => `Open ${row.kind} override by ${row.activated_by_email}`}
        onRowSelect={(row) => {
          setError("");
          setNote("");
          setSelectedId(row.id);
        }}
        state={state}
        minWidth={1000}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter by review" className="flex flex-wrap gap-2">
              <FilterChip selected={filter === "all"} count={ordered.length} onClick={() => setFilter("all")}>
                All
              </FilterChip>
              <FilterChip selected={filter === "unreviewed"} count={unreviewed.length} onClick={() => setFilter("unreviewed")}>
                Needs review
              </FilterChip>
              <FilterChip selected={filter === "reviewed"} count={ordered.length - unreviewed.length} onClick={() => setFilter("reviewed")}>
                Reviewed
              </FilterChip>
            </div>
          </FilterBar>
        }
        footer={visible.length > 0 ? <TableFooter shown={visible.length} total={ordered.length} sortNote="unreviewed first, then live, then newest" /> : null}
      />

      {selected ? (
        <OverrideDrawer
          override={selected}
          now={now}
          viewerOperatorId={viewerOperatorId}
          viewerIsAdmin={viewerIsAdmin}
          busy={busyId === selected.id}
          error={error}
          note={note}
          onNote={setNote}
          onClose={() => {
            setError("");
            setSelectedId(null);
          }}
          onReview={() => review(selected)}
          onRun={() => {
            setError("");
            setDialogError("");
            setSelectedId(null);
            setRunningId(selected.id);
          }}
          onRevoke={() => {
            setError("");
            setDialogError("");
            setSelectedId(null);
            setRevokingId(selected.id);
          }}
        />
      ) : null}

      {activating && viewerIsAdmin ? (
        <Drawer
          open
          onClose={() => {
            setError("");
            setActivating(false);
          }}
          title="Request an override"
          sub="Skips the second approver for one exact command"
        >
          <p role="note" className="m-0 flex items-start gap-3 rounded-lg bg-(--amber-soft) px-4 py-3 text-[#89500b]">
            <ShieldAlert aria-hidden="true" size={18} className="mt-0.5 shrink-0" />
            <span>
              This skips the second reviewer the approval policy requires. Use it only when the delay itself is the harm. The alert recipients are emailed the moment you
              submit, the override expires in minutes, it runs exactly one command, and another administrator must review it afterwards.
            </span>
          </p>
          <form onSubmit={activate} className="grid gap-4" aria-label="Request an override">
            {initialEndpoints.length > 0 ? (
              <Select label="Endpoint" name="agent_id" required defaultValue="">
                <option value="" disabled>
                  Choose an endpoint
                </option>
                {initialEndpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>
                    {endpoint.hostname} · {endpoint.client_name} / {endpoint.site_name}
                  </option>
                ))}
              </Select>
            ) : (
              <Input label="Endpoint" hint="The device list could not be loaded, so enter the endpoint ID." autoComplete="off" maxLength={36} name="agent_id" required type="text" />
            )}
            <Select label="Command kind" name="kind" required defaultValue="powershell">
              {OVERRIDE_COMMAND_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </Select>
            <Textarea
              label="Payload (JSON object, exactly as it will run)"
              name="payload"
              className={`${mono} text-[13px]`}
              onChange={(event) => setPayloadText(event.target.value)}
              placeholder='{"script": "Restart-Service -Name Spooler"}'
              rows={4}
              value={payloadText}
            />
            <Textarea
              label="Justification (recorded, sent to recipients)"
              hint="20 to 512 characters."
              maxLength={512}
              name="justification"
              onChange={(event) => setJustification(event.target.value)}
              placeholder="What is broken, the ticket, and why approvers cannot be reached"
              required
              rows={3}
              value={justification}
            />
            <Input
              label="Expires after (minutes, 1 to 60)"
              defaultValue={DEFAULT_TTL_SECONDS / 60}
              max={MAX_TTL_SECONDS / 60}
              min={MIN_TTL_SECONDS / 60}
              name="ttl_minutes"
              required
              type="number"
            />
            {error ? (
              <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-(--red)">
                {error}
              </p>
            ) : null}
            <div>
              <Button type="submit" variant="primary" icon={Siren} disabled={busyId === "activate"}>
                Activate emergency override
              </Button>
            </div>
          </form>
        </Drawer>
      ) : null}

      <ConfirmDialog
        open={revoking !== null}
        title="Revoke this override?"
        consequence="It can no longer be used to run its command. Revoking does not undo a command that already ran."
        confirmLabel="Revoke override"
        busy={revoking !== null && busyId === revoking.id}
        error={dialogError || undefined}
        onCancel={() => {
          setRevokingId(null);
          setDialogError("");
        }}
        onConfirm={confirmRevoke}
      />
      {running ? (
        <RunDialog
          override={running}
          busy={busyId === running.id}
          error={dialogError}
          onCancel={() => {
            setRunningId(null);
            setDialogError("");
          }}
          onConfirm={confirmRun}
        />
      ) : null}
    </PageStack>
  );
}

type OverrideDrawerProps = {
  override: EmergencyOverride;
  now: Date;
  viewerOperatorId: string | null;
  viewerIsAdmin: boolean;
  busy: boolean;
  error: string;
  note: string;
  onNote: (value: string) => void;
  onClose: () => void;
  onReview: () => void;
  onRun: () => void;
  onRevoke: () => void;
};

function OverrideDrawer({ override, now, viewerOperatorId, viewerIsAdmin, busy, error, note, onNote, onClose, onReview, onRun, onRevoke }: OverrideDrawerProps) {
  const isActivator = override.activated_by_operator_id === viewerOperatorId;
  const runnable = canRun(override, viewerOperatorId, now);
  const revocable = canRevoke(override, viewerOperatorId, viewerIsAdmin, now);
  const reviewable = canReview(override, viewerOperatorId, viewerIsAdmin);
  const detail = override as Partial<EmergencyOverrideDetail>;

  return (
    <Drawer
      open
      onClose={onClose}
      context={`Endpoint ${override.agent_id.slice(0, 8)}`}
      title={<span className={mono}>{override.kind}</span>}
      sub={`${statusLabel(override.status)}${isLive(override, now) ? ` · ${formatTimeRemaining(override.expires_at, now)}` : ""} · ${override.reviewed_at ? "reviewed" : "not reviewed"}`}
      record={`Activated by ${override.activated_by_email} on ${formatAuditTimestamp(override.created_at)}`}
      footer={
        runnable || revocable || reviewable ? (
          <>
            {runnable ? (
              <Button variant="primary" icon={Play} disabled={busy} onClick={onRun}>
                Run now
              </Button>
            ) : null}
            {reviewable ? (
              <Button variant="primary" icon={CircleCheck} disabled={busy} onClick={onReview}>
                Mark as reviewed
              </Button>
            ) : null}
            {revocable ? (
              <Button variant="danger" disabled={busy} onClick={onRevoke}>
                Revoke
              </Button>
            ) : null}
          </>
        ) : undefined
      }
    >
      {override.reviewed_at ? null : (
        <p role="note" className="m-0 rounded-lg bg-(--amber-soft) px-4 py-3 text-[#89500b]">
          {isActivator
            ? "You activated this override, so someone else must review it."
            : "Must be reviewed by an administrator other than the person who used it."}
        </p>
      )}
      <DefinitionList
        items={[
          { term: "Reason given", value: override.justification },
          { term: "Used by", value: <span className={mono}>{override.activated_by_email}</span> },
          { term: "Endpoint", value: <span className={mono}>{override.agent_id}</span> },
          { term: "Stood in for", value: `${override.required_approvals} ${override.required_approvals === 1 ? "approval" : "approvals"}` },
          { term: "Notified", value: sentence(notificationLabel(override)) },
          ...(detail.consumed_command_id ? [{ term: "Ran as command", value: <span className={mono}>{detail.consumed_command_id.slice(0, 8)}</span> }] : []),
          ...(detail.revoke_reason ? [{ term: "Revoke reason", value: detail.revoke_reason }] : []),
          ...(detail.review_note ? [{ term: "Review note", value: detail.review_note }] : []),
        ]}
      />
      <section aria-label="Fingerprint" className="grid gap-2">
        <h3 className="m-0 text-sm font-semibold text-(--ink)">Fingerprint</h3>
        <p className="m-0 text-xs text-(--muted)">The override only works for the command with this fingerprint: the same endpoint, kind and contents.</p>
        <CodeBlock label="Fingerprint">{`sha256  ${override.payload_sha256}`}</CodeBlock>
      </section>
      <section aria-label="Timeline" className="grid gap-2">
        <h3 className="m-0 text-sm font-semibold text-(--ink)">Timeline</h3>
        <ol className="m-0 grid list-none gap-2.5 p-0">
          {timeline(override, now).map((entry, index) => (
            <li key={`${entry.text}-${index}`} className="grid grid-cols-[1fr_auto] gap-3">
              <span className={entry.pending ? "text-(--muted)" : "text-(--ink)"}>{entry.text}</span>
              <span className="text-xs text-(--muted)">{entry.at ? formatAuditTimestamp(entry.at) : ""}</span>
            </li>
          ))}
        </ol>
      </section>
      {reviewable ? (
        <Textarea
          label="Review note (kept in the audit record)"
          hint="10 to 512 characters."
          maxLength={512}
          value={note}
          onChange={(event) => onNote(event.target.value)}
          disabled={busy}
        />
      ) : null}
      {error ? (
        <p role="alert" className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-(--red)">
          {error}
        </p>
      ) : null}
    </Drawer>
  );
}

/**
 * Confirmation for spending an override. The run API takes no reason (the
 * justification given at activation is what is cited), so this dialog does not
 * ask for one rather than collecting text that would not be recorded.
 */
function RunDialog({ override, busy, error, onCancel, onConfirm }: { override: EmergencyOverride; busy: boolean; error: string; onCancel: () => void; onConfirm: () => void }) {
  const panelRef = useModal(true, busy ? () => {} : onCancel);
  const titleId = useId();
  const bodyId = useId();
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div aria-hidden="true" className="absolute inset-0 bg-[rgb(23_19_42/45%)]" onClick={busy ? undefined : onCancel} />
      <div
        ref={panelRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        className="relative w-[min(480px,100%)] rounded-[10px] bg-(--paper) shadow-[0_14px_34px_rgb(24_16_46/12%)]"
      >
        <div className="grid gap-4 p-6">
          <span className="flex size-10 items-center justify-center rounded-full bg-(--amber-soft) text-[#89500b]">
            <TriangleAlert size={20} aria-hidden="true" />
          </span>
          <div className="grid gap-2">
            <h2 id={titleId} className="m-0 text-lg leading-[1.3] font-semibold text-(--ink)">
              Run this command now?
            </h2>
            <p id={bodyId} className="m-0 text-sm leading-normal text-(--slate)">
              The {override.kind} command runs on endpoint {override.agent_id.slice(0, 8)} without a second approver, citing this override. It can be used once.
            </p>
          </div>
          {error ? (
            <p role="alert" className="m-0 text-sm text-(--red)">
              {error}
            </p>
          ) : null}
        </div>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-(--line) px-6 py-4">
          <Button onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" icon={Play} onClick={onConfirm} disabled={busy} aria-busy={busy || undefined}>
            Run now
          </Button>
        </footer>
      </div>
    </div>
  );
}
