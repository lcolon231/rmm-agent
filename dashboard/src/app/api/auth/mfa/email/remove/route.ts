// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleEmailFactorMutation } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { readMfaCookie, removeEmailFactor } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

/**
 * Remove the operator's email factor. Step-up gated upstream, so a session that
 * signed in *with* an email code is refused here — which is the point.
 */
export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleEmailFactorMutation(request, {
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
      mutate: removeEmailFactor,
      payload: "reason",
    }),
  );
}
