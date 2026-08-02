// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
  type MonitoringPolicy,
  type MonitoringPolicyDetail,
} from "@/lib/monitoring-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getMonitoringPolicies(sessionToken: string): Promise<MonitoringPolicy[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/policies", {
    method: "GET",
    sessionToken,
  });
  const policies = monitoringPolicyListFromUnknown(value);
  if (!policies) throw new Error("The management service returned invalid monitoring policies.");
  return policies;
}

export async function getMonitoringPolicy(
  sessionToken: string,
  policyId: string,
): Promise<MonitoringPolicyDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/policies/${encodeURIComponent(policyId)}`,
    { method: "GET", sessionToken },
  );
  const policy = monitoringPolicyDetailFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid monitoring policy.");
  return policy;
}
