// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  effectivePatchPolicyFromUnknown,
  patchPolicyDetailFromUnknown,
  patchPolicyListFromUnknown,
  type EffectivePatchPolicy,
  type PatchApprovalPolicy,
  type PatchApprovalPolicyDetail,
} from "@/lib/patch-policies-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getPatchPolicies(sessionToken: string): Promise<PatchApprovalPolicy[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/patch-approval/policies", {
    method: "GET",
    sessionToken,
  });
  const policies = patchPolicyListFromUnknown(value);
  if (!policies) throw new Error("The management service returned invalid patch approval policies.");
  return policies;
}

export async function getPatchPolicy(
  sessionToken: string,
  policyId: string,
): Promise<PatchApprovalPolicyDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/patch-approval/policies/${encodeURIComponent(policyId)}`,
    { method: "GET", sessionToken },
  );
  const policy = patchPolicyDetailFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid patch approval policy.");
  return policy;
}

export async function getAgentEffectivePatchPolicy(
  sessionToken: string,
  agentId: string,
): Promise<EffectivePatchPolicy> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(agentId)}/patch-approval/effective`,
    { method: "GET", sessionToken },
  );
  const effective = effectivePatchPolicyFromUnknown(value);
  if (!effective) throw new Error("The management service returned an invalid effective patch policy.");
  return effective;
}
