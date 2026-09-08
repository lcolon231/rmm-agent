// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { ApprovalQueueView } from "@/components/approval-queue-view";
import type { ApprovalPolicy, ApprovalRequest, ApprovalRequestDetail } from "@/lib/approvals-core";
import { getApprovalPolicies, getApprovalRequest, getApprovalRequests } from "@/lib/approvals";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

/** Detail per listed request: payload key names and the verdicts so far.
 *
 * The list read deliberately omits both — the queue can be shown widely, and
 * the contents of a proposed command should not be distributed with it. The
 * page fetches detail only for what it is about to render, and a request that
 * fails to load individually is dropped rather than shown half-populated.
 */
async function loadDetails(
  sessionToken: string,
  requests: ApprovalRequest[],
): Promise<ApprovalRequestDetail[]> {
  const settled = await Promise.allSettled(
    requests.map((request) => getApprovalRequest(sessionToken, request.id)),
  );
  return settled.flatMap((result) =>
    result.status === "fulfilled" ? [result.value] : [],
  );
}

export default async function ApprovalsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let requests: ApprovalRequest[] | null = null;
  let policies: ApprovalPolicy[] | null = null;
  let details: ApprovalRequestDetail[] = [];
  let error = "";

  const [requestResult, policyResult] = await Promise.allSettled([
    getApprovalRequests(session.sessionToken),
    getApprovalPolicies(session.sessionToken),
  ]);
  if (requestResult.status === "fulfilled") {
    requests = requestResult.value;
    details = await loadDetails(session.sessionToken, requests);
  } else {
    error = "Approval requests are unavailable. Try again.";
  }
  if (policyResult.status === "fulfilled") policies = policyResult.value;

  return (
    <ApprovalQueueView
      initialDetails={details}
      initialError={error}
      initialPolicies={policies}
      initialRequests={requests}
      viewerCanDecide={session.operator.role !== "readonly"}
      viewerOperatorId={session.operator.id}
    />
  );
}
