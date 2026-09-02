// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleEmailFactorMutation } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { readMfaCookie, verifyEmailEnrollment } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleEmailFactorMutation(request, {
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
      mutate: verifyEmailEnrollment,
      payload: "code",
    }),
  );
}
