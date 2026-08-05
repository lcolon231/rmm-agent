// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { createScript } from "@/lib/script-library";
import { handleScriptCreate } from "@/lib/script-library-route-core";
export function POST(request: NextRequest) { return handleScriptCreate(request, { getSession: getDashboardSession, createScript }); }
