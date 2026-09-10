// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { deletePatchPolicy, getPatchPolicy, revisePatchPolicy } from "@/lib/patch-policies";
import {
  handlePatchPolicyDelete,
  handlePatchPolicyToggle,
} from "@/lib/patch-policies-route-core";

type Context = { params: Promise<{ policyId: string }> };

export async function PATCH(request: NextRequest, context: Context) {
  const { policyId } = await context.params;
  return handlePatchPolicyToggle(request, policyId, {
    getSession: getDashboardSession,
    getPolicy: getPatchPolicy,
    revisePolicy: revisePatchPolicy,
  });
}

export async function DELETE(request: NextRequest, context: Context) {
  const { policyId } = await context.params;
  return handlePatchPolicyDelete(request, policyId, {
    getSession: getDashboardSession,
    deletePolicy: deletePatchPolicy,
  });
}
