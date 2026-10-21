// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { EmergencyOverrideView } from "@/components/emergency-override-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList, type EndpointListItem } from "@/lib/endpoint-list";
import { getEmergencyOverrides } from "@/lib/emergency-overrides";
import type { EmergencyOverride } from "@/lib/emergency-overrides-core";

export const dynamic = "force-dynamic";

/**
 * Justified emergency overrides (issue #65).
 *
 * The service enforces every rule independently; this page renders whatever
 * the viewer is allowed to see and hides controls the service would refuse.
 * Endpoints are loaded only so the activation form can offer a picker; a
 * failure there degrades to a text field rather than an unusable page.
 */
export default async function EmergencyOverridesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let overrides: EmergencyOverride[] | null = null;
  let endpoints: EndpointListItem[] = [];
  let error = "";

  const [overrideResult, endpointResult] = await Promise.allSettled([
    getEmergencyOverrides(session.sessionToken),
    getEndpointList(session.sessionToken, { sort: "hostname", direction: "asc" }),
  ]);
  if (overrideResult.status === "fulfilled") {
    overrides = overrideResult.value;
  } else {
    error = "Emergency overrides are unavailable. Try again.";
  }
  if (endpointResult.status === "fulfilled") endpoints = endpointResult.value.items;

  return (
    <EmergencyOverrideView
      initialEndpoints={endpoints}
      initialError={error}
      initialOverrides={overrides}
      viewerIsAdmin={session.operator.role === "admin"}
      viewerOperatorId={session.operator.id}
    />
  );
}
