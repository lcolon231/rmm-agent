// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CircleCheck, Clock, Fingerprint, ShieldCheck, UserCheck } from "lucide-react";
import { useCallback, useState } from "react";

import {
  canDecide,
  decideBlockedReason,
  formatApprovalScope,
  formatTimeRemaining,
  isValidDecisionReason,
  sortForReview,
  statusLabel,
  type ApprovalPolicy,
  type ApprovalRequest,
  type ApprovalRequestDetail,
  type ApprovalStatus,
} from "@/lib/approvals-core";
import { formatAuditTimestamp } from "@/lib/audit-core";

import { PageHeader, PageStack } from "./shell/page-header";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { DataTable, PrimaryCell, TableFooter, type Column } from "./ui/data-table";
import { CodeBlock, DefinitionList, Drawer } from "./ui/drawer";
import { Textarea } from "./ui/field";
import { FilterBar, FilterChip } from "./ui/filter-bar";
import { StatRow, StatTile } from "./ui/stat-tile";
import { EmptyState, ErrorState } from "./ui/states";
import { StatusBadge, type StatusTone } from "./ui/status-badge";

type ApprovalQueueViewProps = {
  initialError: string;
  initialRequests: ApprovalRequest[] | null;
  initialPolicies: ApprovalPolicy[] | null;
  /** Detail (payload keys and recorded verdicts) for each listed request. */
  initialDetails: ApprovalRequestDetail[];
  viewerOperatorId: string | null;
  viewerCanDecide: boolean;
};

type Action = "approve" | "reject" | "cancel";
type Filter = "all" | "waiting" | "approved" | "closed";

const REASON_ERROR = "Enter a printable reason of 10 to 512 characters.";

const TONES: Record<ApprovalStatus, StatusTone> = {
  pending: "info",
  approved: "ok",
  rejected: "crit",
  cancelled: "off",
  expired: "off",
  consumed: "off",
};

const BREADCRUMB = [{ label: "Compliance" }, { label: "Approvals" }];
const DESCRIPTION = "Sensitive commands need someone other than the requester to agree. Check what will run before you approve.";

function matches(filter: Filter, status: ApprovalStatus) {
  if (filter === "all") return true;
  if (filter === "waiting") return status === "pending";
  if (filter === "approved") return status === "approved";
  return status !== "pending" && status !== "approved";
}

function withdrawable(request: ApprovalRequestDetail, viewerOperatorId: string | null) {
  return request.requested_by_operator_id === viewerOperatorId && (request.status === "pending" || request.status === "approved");
}

const mono = "font-(family-name:--font-data)";

/**
 * The reviewer queue for two-person authorization (issue #64).
 *
 * The screen is built around one question: is it safe for me to agree to this?
 * So it leads with what is waiting, shows who has already agreed, and states
 * plainly when the viewer is not eligible — including the common and correct
 * case of being the person who raised the request.
 *
 * Nothing here is a security decision. The management service refuses
 * self-approval, counts distinct identities, re-checks every approver's
 * authority at dispatch, and binds the approval to the reviewed payload. This
 * view hides controls the server would refuse anyway; the server refusing them
 * is what makes the control real.
 */
export function ApprovalQueueView({
  initialError,
  initialRequests,
  initialPolicies,
  initialDetails,
  viewerOperatorId,
  viewerCanDecide,
}: ApprovalQueueViewProps) {
  const [details, setDetails] = useState(initialDetails);
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [rejectError, setRejectError] = useState("");
  const [filter, setFilter] = useState<Filter>("all");

  /** Sends one decision. Returns an error message, or null when it was recorded. */
  const send = useCallback(async (requestId: string, action: Action, reason: string): Promise<string | null> => {
    setBusyId(requestId);
    try {
      const response = await fetch(`/api/approval-requests/${requestId}/${action}`, {
        body: JSON.stringify({ reason }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = (await response.json().catch(() => null)) as { request?: ApprovalRequestDetail; error?: string } | null;
      if (!response.ok || !body?.request) return body?.error ?? "The decision could not be confirmed. Try again.";
      const updated = body.request;
      setDetails((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)));
      setReasons((current) => ({ ...current, [requestId]: "" }));
      setNotice(
        action === "cancel"
          ? "Request withdrawn."
          : action === "reject"
            ? "Request rejected."
            : updated.status === "approved"
              ? "Approved. It now has every approval it needs."
              : "Approval recorded. It still needs another identity.",
      );
      return null;
    } finally {
      setBusyId(null);
    }
  }, []);

  const decideFromDrawer = useCallback(
    async (requestId: string, action: "approve" | "cancel") => {
      const reason = (reasons[requestId] ?? "").trim();
      if (!isValidDecisionReason(reason)) {
        setError(REASON_ERROR);
        return;
      }
      setError("");
      setNotice("");
      const failure = await send(requestId, action, reason);
      if (failure) setError(failure);
    },
    [reasons, send],
  );

  async function confirmReject(reason: string) {
    if (!rejectingId) return;
    // The dialog only checks that a reason exists; the decision rules still apply.
    if (!isValidDecisionReason(reason)) {
      setRejectError(REASON_ERROR);
      return;
    }
    setRejectError("");
    setError("");
    setNotice("");
    const failure = await send(rejectingId, "reject", reason);
    if (failure) {
      setRejectError(failure);
      return;
    }
    setRejectingId(null);
  }

  if (initialRequests === null) {
    return (
      <PageStack>
        <PageHeader breadcrumb={BREADCRUMB} title="Approvals" description={DESCRIPTION} />
        <ErrorState title="Approval requests could not be loaded" body={initialError || "The management service did not answer. Try again"} />
      </PageStack>
    );
  }

  const now = new Date();
  const ordered = sortForReview(details);
  const pending = ordered.filter((entry) => entry.status === "pending");
  const waitingForViewer = pending.filter((entry) => viewerCanDecide && canDecide(entry, viewerOperatorId));
  const waitingForOthers = pending.filter((entry) => entry.requested_by_operator_id === viewerOperatorId);
  const approved = ordered.filter((entry) => entry.status === "approved");
  const enabledPolicies = initialPolicies?.filter((policy) => policy.enabled) ?? null;
  const visible = ordered.filter((entry) => matches(filter, entry.status));
  const unreadable = initialRequests.length - details.length;
  const selected = ordered.find((entry) => entry.id === selectedId) ?? null;
  const rejecting = ordered.find((entry) => entry.id === rejectingId) ?? null;

  const columns: Column<ApprovalRequestDetail>[] = [
    { key: "request", header: "Request", cell: (request) => <PrimaryCell mono title={request.kind} sub={request.reason} /> },
    {
      key: "state",
      header: "State",
      cell: (request) => (
        <span className="grid justify-items-start gap-1">
          <StatusBadge tone={TONES[request.status]}>{statusLabel(request.status)}</StatusBadge>
          <span className="text-xs text-(--muted)">
            {request.approvals_recorded} of {request.required_approvals} approvals
          </span>
        </span>
      ),
    },
    {
      key: "by",
      header: "Requested by",
      cell: (request) => (
        <span>
          <span className={`${mono} text-[13px]`}>{request.requested_by_email}</span>
          {request.requested_by_operator_id === viewerOperatorId ? <span className="text-(--muted)"> (you)</span> : null}
        </span>
      ),
    },
    { key: "endpoint", header: "Endpoint", cell: (request) => <span className={`${mono} text-[13px]`}>{request.agent_id.slice(0, 8)}</span> },
    {
      key: "expires",
      header: "Expires",
      cell: (request) =>
        request.status === "pending" || request.status === "approved" ? formatTimeRemaining(request.expires_at, now) : <span className="text-(--muted)">—</span>,
    },
  ];

  const chips: Array<{ label: string; value: Filter; count: number }> = [
    { label: "All", value: "all", count: ordered.length },
    { label: "Waiting", value: "waiting", count: pending.length },
    { label: "Approved", value: "approved", count: approved.length },
    { label: "Closed", value: "closed", count: ordered.length - pending.length - approved.length },
  ];

  const state =
    ordered.length === 0 ? (
      <EmptyState icon={UserCheck} title="Nothing is waiting" body="Nothing has been raised for approval." />
    ) : visible.length === 0 ? (
      <EmptyState title="No requests match" body="No request is in this state." actionLabel="Clear filters" onAction={() => setFilter("all")} />
    ) : undefined;

  return (
    <PageStack>
      <PageHeader breadcrumb={BREADCRUMB} title="Approvals" description={DESCRIPTION} />
      <StatRow>
        <StatTile
          icon={UserCheck}
          label="Waiting for you"
          tone={waitingForViewer.length > 0 ? "warn" : "ok"}
          value={waitingForViewer.length}
          sub={viewerCanDecide ? "You can approve or reject these" : "Your role cannot decide requests"}
        />
        <StatTile icon={Clock} label="Waiting for others" tone="info" value={waitingForOthers.length} sub="Requests you raised" />
        <StatTile icon={CircleCheck} label="Approved, not yet run" tone="ok" value={approved.length} sub="Each approval runs once" />
        <StatTile
          icon={ShieldCheck}
          label="Policies in force"
          tone="info"
          value={enabledPolicies === null ? "—" : enabledPolicies.length}
          sub={enabledPolicies === null ? "Could not be loaded" : "Commands that need approval"}
        />
      </StatRow>

      {initialPolicies && initialPolicies.length === 0 ? (
        <p role="status" className="m-0 rounded-lg bg-(--fog) px-4 py-3 text-sm text-(--slate)">
          No approval policy is configured, so no command currently requires approval. Dispatch follows the ordinary role and script-permission rules.
        </p>
      ) : null}
      {error && !selected ? (
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
        caption="Approval requests"
        columns={columns}
        rows={visible}
        rowKey={(request) => request.id}
        rowLabel={(request) => `Review ${request.kind} request from ${request.requested_by_email}`}
        onRowSelect={(request) => {
          setError("");
          setSelectedId(request.id);
        }}
        state={state}
        minWidth={900}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {chips.map((chip) => (
                <FilterChip key={chip.value} selected={filter === chip.value} count={chip.count} onClick={() => setFilter(chip.value)}>
                  {chip.label}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        }
        footer={
          visible.length > 0 ? (
            <TableFooter shown={visible.length} total={initialRequests.length} sortNote="waiting first, then soonest to expire · the 100 most recent requests are loaded" />
          ) : null
        }
      />
      {unreadable > 0 ? (
        <p role="status" className="m-0 text-xs text-(--muted)">
          {unreadable} {unreadable === 1 ? "request" : "requests"} could not be opened and {unreadable === 1 ? "is" : "are"} not listed. Nothing was changed.
        </p>
      ) : null}

      <PoliciesTable policies={initialPolicies} />

      {selected ? (
        <RequestDrawer
          request={selected}
          now={now}
          viewerOperatorId={viewerOperatorId}
          viewerCanDecide={viewerCanDecide}
          busy={busyId === selected.id}
          error={error}
          reason={reasons[selected.id] ?? ""}
          onReason={(value) => setReasons((current) => ({ ...current, [selected.id]: value }))}
          onClose={() => {
            setError("");
            setSelectedId(null);
          }}
          onApprove={() => decideFromDrawer(selected.id, "approve")}
          onWithdraw={() => decideFromDrawer(selected.id, "cancel")}
          onReject={() => {
            // Close the drawer first so only one modal owns focus and Escape.
            setError("");
            setRejectError("");
            setSelectedId(null);
            setRejectingId(selected.id);
          }}
        />
      ) : null}

      <ConfirmDialog
        open={rejecting !== null}
        title="Reject this request?"
        consequence="The command will not run and the request is closed. Your reason is kept with the decision."
        confirmLabel="Reject request"
        busy={rejecting !== null && busyId === rejecting.id}
        error={rejectError || undefined}
        onCancel={() => {
          setRejectingId(null);
          setRejectError("");
        }}
        onConfirm={confirmReject}
      />
    </PageStack>
  );
}

type RequestDrawerProps = {
  request: ApprovalRequestDetail;
  now: Date;
  viewerOperatorId: string | null;
  viewerCanDecide: boolean;
  busy: boolean;
  error: string;
  reason: string;
  onReason: (value: string) => void;
  onClose: () => void;
  onApprove: () => void;
  onWithdraw: () => void;
  onReject: () => void;
};

function RequestDrawer({ request, now, viewerOperatorId, viewerCanDecide, busy, error, reason, onReason, onClose, onApprove, onWithdraw, onReject }: RequestDrawerProps) {
  const blocked = decideBlockedReason(request, viewerOperatorId);
  const actionable = viewerCanDecide && canDecide(request, viewerOperatorId);
  const canWithdraw = withdrawable(request, viewerOperatorId);
  const open = request.status === "pending" || request.status === "approved";

  return (
    <Drawer
      open
      onClose={onClose}
      context={`Endpoint ${request.agent_id.slice(0, 8)}`}
      title={<span className={mono}>{request.kind}</span>}
      sub={`${statusLabel(request.status)} · ${request.approvals_recorded} of ${request.required_approvals} approvals${open ? ` · ${formatTimeRemaining(request.expires_at, now)}` : ""}`}
      record={`Requested by ${request.requested_by_email} on ${formatAuditTimestamp(request.created_at)}`}
      footer={
        actionable || canWithdraw ? (
          <>
            {actionable ? (
              <>
                <Button variant="primary" icon={CircleCheck} disabled={busy} onClick={onApprove}>
                  Approve
                </Button>
                <Button variant="danger" disabled={busy} onClick={onReject}>
                  Reject request
                </Button>
              </>
            ) : null}
            {canWithdraw ? (
              <Button disabled={busy} onClick={onWithdraw}>
                Withdraw
              </Button>
            ) : null}
          </>
        ) : undefined
      }
    >
      {blocked && request.status === "pending" ? (
        <p role="status" className="m-0 rounded-lg bg-(--fog) px-4 py-3 text-(--slate)">
          {blocked}
        </p>
      ) : null}
      <p role="note" className="m-0 flex items-start gap-3 rounded-lg bg-(--primary-tint) px-4 py-3 text-(--slate)">
        <Fingerprint size={18} aria-hidden="true" className="mt-0.5 shrink-0 text-(--primary-press)" />
        <span>
          Your approval is tied to this exact command: this endpoint, this kind of command and these contents. If any of them changes, the approval no longer applies and the
          command is refused. An approval is used for one run, and every approver&rsquo;s authority is checked again when it runs.
        </span>
      </p>

      <section aria-label="Exactly what will run" className="grid gap-2.5">
        <h3 className="m-0 text-sm font-semibold text-(--ink)">Exactly what will run</h3>
        <DefinitionList
          items={[
            { term: "Command kind", value: <span className={mono}>{request.kind}</span> },
            { term: "Endpoint", value: <span className={mono}>{request.agent_id}</span> },
            { term: "Fields", value: request.payload_keys.length > 0 ? <span className={mono}>{request.payload_keys.join(", ")}</span> : "None" },
          ]}
        />
        <p className="m-0 text-xs text-(--muted)">Field values are not shown on this screen. The fingerprint below covers the endpoint, the command kind and every value.</p>
        <h4 className="m-0 text-[13px] font-semibold text-(--slate)">Fingerprint</h4>
        <CodeBlock label="Fingerprint">{`sha256  ${request.payload_sha256}`}</CodeBlock>
      </section>

      <DefinitionList
        items={[
          { term: "Reason given", value: request.reason },
          { term: "Requested by", value: <span className={mono}>{request.requested_by_email}</span> },
          ...(request.consumed_command_id ? [{ term: "Ran as command", value: <span className={mono}>{request.consumed_command_id.slice(0, 8)}</span> }] : []),
          ...(request.closed_by_email ? [{ term: "Closed by", value: <span className={mono}>{request.closed_by_email}</span> }] : []),
        ]}
      />

      <section aria-label="Decisions so far" className="grid gap-2">
        <h3 className="m-0 text-sm font-semibold text-(--ink)">Decisions so far</h3>
        {request.decisions.length === 0 ? (
          <p className="m-0 text-(--muted)">Nobody has decided yet.</p>
        ) : (
          <ul className="m-0 grid list-none gap-2 p-0">
            {request.decisions.map((entry) => (
              <li key={entry.id} className="grid gap-0.5">
                <span>
                  {entry.decision === "approve" ? "Approved" : "Rejected"} by <span className={mono}>{entry.operator_email}</span>
                </span>
                <span className="text-xs text-(--muted)">
                  {formatAuditTimestamp(entry.created_at)}
                  {entry.reason ? ` · ${entry.reason}` : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {actionable || canWithdraw ? (
        <Textarea
          label="Reason (kept in the audit record)"
          hint="10 to 512 characters. Needed to approve or withdraw."
          maxLength={512}
          value={reason}
          onChange={(event) => onReason(event.target.value)}
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

function PoliciesTable({ policies }: { policies: ApprovalPolicy[] | null }) {
  const columns: Column<ApprovalPolicy>[] = [
    { key: "name", header: "Policy", cell: (policy) => <PrimaryCell title={policy.name} /> },
    { key: "scope", header: "Applies to", cell: (policy) => formatApprovalScope(policy.scope, policy.scope_id) },
    { key: "approvers", header: "Approvers needed", cell: (policy) => (policy.required_approvals === 2 ? "Two different people" : "One other person") },
    { key: "kinds", header: "Commands", cell: (policy) => <span className={`${mono} text-[13px] whitespace-normal`}>{policy.command_kinds.join(", ")}</span> },
    { key: "state", header: "State", cell: (policy) => (policy.enabled ? <StatusBadge tone="ok">Active</StatusBadge> : <StatusBadge tone="off">Disabled</StatusBadge>) },
  ];
  return (
    <DataTable
      caption="Policies in force"
      columns={columns}
      rows={policies ?? []}
      rowKey={(policy) => policy.id}
      minWidth={760}
      filters={
        <div className="border-b border-(--line) px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-(--ink)">Policies in force</h2>
        </div>
      }
      state={
        policies === null ? (
          <ErrorState body="Approval policies could not be loaded" />
        ) : policies.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No policies" body="No command currently requires approval." />
        ) : undefined
      }
    />
  );
}
