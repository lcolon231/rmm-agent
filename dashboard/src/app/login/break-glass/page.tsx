// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { BreakGlassActivateForm } from "@/components/break-glass-activate-form";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

/**
 * Emergency sign-in (issue #69). Deliberately not linked from the sign-in page:
 * it is a documented URL for an incident runbook, not a visible alternative to
 * signing in normally.
 */
export default async function BreakGlassLoginPage() {
  const session = await getDashboardSession();
  if (session.kind === "authenticated") {
    // Already signed in: there is no emergency to break glass for.
    redirect("/security");
  }
  return <BreakGlassActivateForm />;
}
