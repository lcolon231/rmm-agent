// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleSendEmailCode } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { readMfaCookie, startEmailEnrollment } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleSendEmailCode(request, {
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
      credential: "session",
      send: startEmailEnrollment,
    }),
  );
}
