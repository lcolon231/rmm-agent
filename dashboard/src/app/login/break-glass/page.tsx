// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { BreakGlassActivateForm } from "@/components/break-glass-activate-form";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

/** Emergency sign-in with the existing sealed credential flow. */
export default async function BreakGlassLoginPage() {
  const session = await getDashboardSession();
  if (session.kind === "authenticated") {
    // Already signed in: there is no emergency to break glass for.
    redirect("/security");
  }
  return <BreakGlassActivateForm />;
}
