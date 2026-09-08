// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CheckCircle2, ShieldCheck, UserCheck, XCircle } from "lucide-react";
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
} from "@/lib/approvals-core";

type ApprovalQueueViewProps = {
  initialError: string;
  initialRequests: ApprovalRequest[] | null;
  initialPolicies: ApprovalPolicy[] | null;
  /** Detail (payload keys and recorded verdicts) for each listed request. */
  initialDetails: ApprovalRequestDetail[];
  viewerOperatorId: string | null;
  viewerCanDecide: boolean;
};

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

  const decide = useCallback(
    async (requestId: string, action: "approve" | "reject" | "cancel") => {
      const reason = (reasons[requestId] ?? "").trim();
      if (!isValidDecisionReason(reason)) {
        setError("Enter a printable reason of 10 to 512 characters.");
        return;
      }
      setError("");
      setNotice("");
      setBusyId(requestId);
      try {
        const response = await fetch(`/api/approval-requests/${requestId}/${action}`, {
          body: JSON.stringify({ reason }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        });
        const body = (await response.json().catch(() => null)) as
          | { request?: ApprovalRequestDetail; error?: string }
          | null;
        if (!response.ok || !body?.request) {
          setError(body?.error ?? "The decision could not be confirmed. Try again.");
          return;
        }
        const updated = body.request;
        setDetails((current) =>
          current.map((entry) => (entry.id === updated.id ? updated : entry)),
        );
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
      } finally {
        setBusyId(null);
      }
    },
    [reasons],
  );

  if (initialRequests === null) {
    return (
      <div className="enrollment-empty" role="alert">
        <ShieldCheck size={24} />
        <h3>Approval requests could not be loaded</h3>
        <p>{initialError || "The management service did not answer. Try again."}</p>
      </div>
    );
  }

  const now = new Date();
  const ordered = sortForReview(details);
  const waiting = ordered.filter((entry) => entry.status === "pending");

  return (
    <section className="mfa-settings approval-queue">
      <header>
        <h1>Approvals</h1>
        <p>
          Sensitive commands that policy requires other people to authorize. An
          approval is bound to the exact endpoint, kind, and payload that was
          reviewed, is spent on one dispatch, and is re-checked against every
          approver&rsquo;s current authority at the moment it runs.
        </p>
      </header>

      {initialPolicies && initialPolicies.length === 0 ? (
        <p className="mfa-banner" role="status">
          No approval policy is configured, so no command currently requires
          approval. Dispatch follows the ordinary role and script-permission
          rules.
        </p>
      ) : null}

      {waiting.length > 0 ? (
        <p className="mfa-banner mfa-banner-warning" role="status">
          <UserCheck aria-hidden="true" size={16} /> {waiting.length}{" "}
          {waiting.length === 1 ? "request is" : "requests are"} awaiting approval.
        </p>
      ) : null}

      {error ? <p className="login-error" role="alert">{error}</p> : null}
      {notice ? <p className="mfa-banner" role="status">{notice}</p> : null}

      <h2>Requests</h2>
      {ordered.length === 0 ? (
        <p>Nothing has been raised for approval.</p>
      ) : (
        <ul className="session-list">
          {ordered.map((request) => {
            const blocked = decideBlockedReason(request, viewerOperatorId);
            const actionable = viewerCanDecide && canDecide(request, viewerOperatorId);
            const isRequester = request.requested_by_operator_id === viewerOperatorId;
            return (
              <li key={request.id}>
                <div>
                  <strong>
                    {request.kind}
                    <span
                      className={
                        request.status === "pending"
                          ? "session-badge session-badge-alarm"
                          : request.status === "approved"
                            ? "session-badge"
                            : "session-badge session-badge-warn"
                      }
                    >
                      {statusLabel(request.status)}
                    </span>
                  </strong>
                  <small>
                    {request.requested_by_email}
                    {" · endpoint "}
                    {request.agent_id.slice(0, 8)}
                    {" · "}
                    {request.approvals_recorded} of {request.required_approvals} approvals
                    {request.status === "pending" || request.status === "approved"
                      ? ` · ${formatTimeRemaining(request.expires_at, now)}`
                      : ""}
                  </small>
                  <small>
                    {request.reason}
                    {request.payload_keys.length > 0
                      ? ` · payload: ${request.payload_keys.join(", ")}`
                      : ""}
                  </small>
                  <small>
                    Binding <code>{request.payload_sha256.slice(0, 16)}</code>
                    {request.consumed_command_id
                      ? ` · ran as command ${request.consumed_command_id.slice(0, 8)}`
                      : ""}
                  </small>
                  {request.decisions.length > 0 ? (
                    <small>
                      {request.decisions
                        .map(
                          (entry) =>
                            `${entry.decision === "approve" ? "approved" : "rejected"} by ${entry.operator_email}`,
                        )
                        .join(" · ")}
                    </small>
                  ) : null}
                  {blocked && request.status === "pending" ? (
                    <small className="approval-blocked">{blocked}</small>
                  ) : null}
                </div>

                {actionable || (isRequester && request.status !== "consumed" && request.status !== "expired" && request.status !== "rejected" && request.status !== "cancelled") ? (
                  <div className="approval-actions">
                    <label className="sr-only" htmlFor={`reason-${request.id}`}>
                      Reason
                    </label>
                    <input
                      id={`reason-${request.id}`}
                      maxLength={512}
                      onChange={(event) =>
                        setReasons((current) => ({
                          ...current,
                          [request.id]: event.target.value,
                        }))
                      }
                      placeholder="Why? (recorded, 10-512 characters)"
                      type="text"
                      value={reasons[request.id] ?? ""}
                    />
                    {actionable ? (
                      <>
                        <button
                          disabled={busyId === request.id}
                          onClick={() => decide(request.id, "approve")}
                          type="button"
                        >
                          <CheckCircle2 aria-hidden="true" size={15} /> Approve
                        </button>
                        <button
                          disabled={busyId === request.id}
                          onClick={() => decide(request.id, "reject")}
                          type="button"
                        >
                          <XCircle aria-hidden="true" size={15} /> Reject
                        </button>
                      </>
                    ) : null}
                    {isRequester ? (
                      <button
                        disabled={busyId === request.id}
                        onClick={() => decide(request.id, "cancel")}
                        type="button"
                      >
                        Withdraw
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      <h2>Policies in force</h2>
      {initialPolicies === null ? (
        <p>Approval policies could not be loaded.</p>
      ) : initialPolicies.length === 0 ? (
        <p>None.</p>
      ) : (
        <ul className="session-list">
          {initialPolicies.map((policy) => (
            <li key={policy.id}>
              <div>
                <strong>
                  {policy.name}
                  {policy.enabled ? null : (
                    <span className="session-badge session-badge-warn">Disabled</span>
                  )}
                </strong>
                <small>
                  {formatApprovalScope(policy.scope, policy.scope_id)}
                  {" · "}
                  {policy.required_approvals === 2
                    ? "two distinct approvers"
                    : "one approver"}
                  {" · "}
                  {policy.command_kinds.join(", ")}
                </small>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
