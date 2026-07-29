// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import {
  handleCreateOperator,
  handleListOperators,
} from "@/lib/operator-management-route-core";
import {
  createOperator,
  listOperators,
} from "@/lib/operator-management";

export const dynamic = "force-dynamic";

export function GET(request: NextRequest) {
  return handleListOperators(request, {
    getSession: getDashboardSession,
    listOperators,
  });
}

export function POST(request: NextRequest) {
  return handleCreateOperator(request, {
    createOperator,
    getSession: getDashboardSession,
  });
}
