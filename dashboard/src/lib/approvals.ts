// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  approvalPolicyListFromUnknown,
  approvalRequestDetailFromUnknown,
  approvalRequestListFromUnknown,
  type ApprovalPolicy,
  type ApprovalRequest,
  type ApprovalRequestDetail,
} from "@/lib/approvals-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getApprovalRequests(
  sessionToken: string,
): Promise<ApprovalRequest[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/approval-requests?limit=100", {
    method: "GET",
    sessionToken,
  });
  const requests = approvalRequestListFromUnknown(value);
  if (!requests) throw new Error("The management service returned invalid approval requests.");
  return requests;
}

export async function getApprovalRequest(
  sessionToken: string,
  requestId: string,
): Promise<ApprovalRequestDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/approval-requests/${encodeURIComponent(requestId)}`,
    { method: "GET", sessionToken },
  );
  const request = approvalRequestDetailFromUnknown(value);
  if (!request) throw new Error("The management service returned an invalid approval request.");
  return request;
}

export async function getApprovalPolicies(
  sessionToken: string,
): Promise<ApprovalPolicy[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/approval-policies", {
    method: "GET",
    sessionToken,
  });
  const policies = approvalPolicyListFromUnknown(value);
  if (!policies) throw new Error("The management service returned invalid approval policies.");
  return policies;
}

/** Record a verdict, or withdraw a request. The service re-checks everything. */
export async function performApprovalAction(
  sessionToken: string,
  requestId: string,
  action: "approve" | "reject" | "cancel",
  reason: string,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/approval-requests/${encodeURIComponent(requestId)}/${action}`,
    {
      body: JSON.stringify({ reason }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
}
