// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  emergencyOverrideDetailFromUnknown,
  emergencyOverrideListFromUnknown,
  type EmergencyOverride,
  type EmergencyOverrideDetail,
} from "@/lib/emergency-overrides-core";
import type { ActivateInput } from "@/lib/emergency-override-route-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getEmergencyOverrides(sessionToken: string): Promise<EmergencyOverride[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/emergency-overrides?limit=100", {
    method: "GET",
    sessionToken,
  });
  const rows = emergencyOverrideListFromUnknown(value);
  if (!rows) throw new Error("The management service returned invalid emergency overrides.");
  return rows;
}

export async function getEmergencyOverride(
  sessionToken: string,
  overrideId: string,
): Promise<EmergencyOverrideDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/emergency-overrides/${encodeURIComponent(overrideId)}`,
    { method: "GET", sessionToken },
  );
  const detail = emergencyOverrideDetailFromUnknown(value);
  if (!detail) throw new Error("The management service returned an invalid emergency override.");
  return detail;
}

export async function activateEmergencyOverride(
  sessionToken: string,
  input: ActivateInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>("/api/v1/emergency-overrides", {
    body: JSON.stringify(input),
    headers: { "Content-Type": "application/json" },
    method: "POST",
    sessionToken,
  });
}

export async function revokeEmergencyOverride(
  sessionToken: string,
  overrideId: string,
  reason: string,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/emergency-overrides/${encodeURIComponent(overrideId)}/revoke`,
    {
      body: JSON.stringify({ reason }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
}

export async function reviewEmergencyOverride(
  sessionToken: string,
  overrideId: string,
  note: string,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/emergency-overrides/${encodeURIComponent(overrideId)}/review`,
    {
      body: JSON.stringify({ note }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
}

/** Dispatch exactly the command the override is bound to, citing it.
 *
 * The payload is read back from the service rather than re-sent by the
 * browser, so what runs is what was reviewed at activation; the service
 * recomputes the binding digest and refuses any drift regardless.
 */
export async function runEmergencyOverride(
  sessionToken: string,
  overrideId: string,
): Promise<unknown> {
  const detail = await getEmergencyOverride(sessionToken, overrideId);
  await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(detail.agent_id)}/commands`,
    {
      body: JSON.stringify({
        kind: detail.kind,
        payload: detail.payload,
        emergency_override_id: detail.id,
      }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  return nodelinkApiRequest<unknown>(
    `/api/v1/emergency-overrides/${encodeURIComponent(overrideId)}`,
    { method: "GET", sessionToken },
  );
}
