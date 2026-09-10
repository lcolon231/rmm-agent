// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  effectivePatchPolicyFromUnknown,
  patchPolicyDetailFromUnknown,
  patchPolicyFromUnknown,
  patchPolicyListFromUnknown,
  type EffectivePatchPolicy,
  type PatchApprovalPolicy,
  type PatchApprovalPolicyDetail,
  type PatchPolicyCreateBody,
  type PatchPolicyToggleBody,
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

export async function createPatchPolicy(
  sessionToken: string,
  input: PatchPolicyCreateBody,
): Promise<PatchApprovalPolicy> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/patch-approval/policies", {
    body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
    method: "POST", sessionToken,
  });
  const policy = patchPolicyFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid patch approval policy.");
  return policy;
}

export async function revisePatchPolicy(
  sessionToken: string,
  policyId: string,
  input: PatchPolicyToggleBody,
): Promise<PatchApprovalPolicy> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/patch-approval/policies/${encodeURIComponent(policyId)}`,
    {
      body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
      method: "PUT", sessionToken,
    },
  );
  const policy = patchPolicyFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid patch approval policy.");
  return policy;
}

export async function deletePatchPolicy(
  sessionToken: string,
  policyId: string,
): Promise<void> {
  await nodelinkApiRequest<unknown>(
    `/api/v1/patch-approval/policies/${encodeURIComponent(policyId)}`,
    { method: "DELETE", sessionToken },
  );
}
