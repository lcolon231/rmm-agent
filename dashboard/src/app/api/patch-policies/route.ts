// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { createPatchPolicy } from "@/lib/patch-policies";
import { handlePatchPolicyCreate } from "@/lib/patch-policies-route-core";

export function POST(request: NextRequest) {
  return handlePatchPolicyCreate(request, {
    getSession: getDashboardSession,
    createPolicy: createPatchPolicy,
  });
}
