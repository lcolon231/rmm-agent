// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { requestPatchComplianceExport } from "@/lib/patch-compliance";
import { handlePatchComplianceExport } from "@/lib/patch-compliance-export-route-core";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return handlePatchComplianceExport(request, {
    getSession: getDashboardSession,
    requestExport: requestPatchComplianceExport,
  });
}
