// SPDX-License-Identifier: AGPL-3.0-only

import { getAuditAnchors, verifyAuditChain } from "@/lib/audit";
import { handleAuditIntegrity } from "@/lib/audit-integrity-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

async function getIntegrityInputs(sessionToken: string) {
  // Either half may fail on its own; a failed verify reads "unknown", never intact.
  const [verification, anchors] = await Promise.allSettled([verifyAuditChain(sessionToken), getAuditAnchors(sessionToken)]);
  return {
    verification: verification.status === "fulfilled" ? verification.value : null,
    anchors: anchors.status === "fulfilled" ? anchors.value : null,
  };
}

export function GET(request: Request) {
  return handleAuditIntegrity(request, { getSession: getDashboardSession, getIntegrityInputs });
}
