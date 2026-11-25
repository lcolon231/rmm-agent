// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest, nodelinkApiRequestRaw } from "@/lib/nodelink-api";
import { retentionPolicyFromUnknown, type RetentionPolicy } from "@/lib/retention-policy-core";
import type { RetentionMethod } from "@/lib/retention-policy-route-core";

function policyPath(clientId: string): string {
  return `/api/v1/clients/${encodeURIComponent(clientId)}/retention-policy`;
}

/** The client's effective policy; throws `NodelinkApiError` on a non-2xx. */
export async function getRetentionPolicy(
  sessionToken: string,
  clientId: string,
): Promise<RetentionPolicy | null> {
  return retentionPolicyFromUnknown(
    await nodelinkApiRequest<unknown>(policyPath(clientId), { method: "GET", sessionToken }),
  );
}

/** Raw upstream response, so the route can relay `detail.code` and `category`. */
export function sendRetentionPolicy(
  sessionToken: string,
  method: RetentionMethod,
  clientId: string,
  body?: unknown,
): Promise<Response> {
  return nodelinkApiRequestRaw(policyPath(clientId), {
    method,
    sessionToken,
    headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
