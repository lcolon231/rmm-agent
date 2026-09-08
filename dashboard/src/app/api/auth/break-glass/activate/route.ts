// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { handleActivateBreakGlass } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { activateBreakGlass } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

/**
 * Reachable without a session by design: this is the escape hatch for the case
 * where no session can be obtained. The handler still enforces same-origin, and
 * the upstream applies the per-IP rate limit and the audit trail.
 */
export async function POST(request: NextRequest) {
  return applyAdminSessionResult(
    await handleActivateBreakGlass(request, { activate: activateBreakGlass }),
  );
}
