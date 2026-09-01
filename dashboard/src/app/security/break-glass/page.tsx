// SPDX-License-Identifier: AGPL-3.0-only

import { BreakGlassView } from "@/components/break-glass-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  fetchBreakGlassAccounts,
  fetchBreakGlassActivations,
  fetchBreakGlassStatus,
} from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

/**
 * Break-glass provisioning and review (issue #69).
 *
 * The API is platform-admin only and enforces that independently; this page
 * simply renders whatever it is allowed to see, so a non-admin who reaches the
 * URL gets an empty, unusable screen rather than a partial one.
 */
export default async function BreakGlassPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return null;

  const [accounts, activations, status] = await Promise.all([
    fetchBreakGlassAccounts(session.sessionToken),
    fetchBreakGlassActivations(session.sessionToken),
    fetchBreakGlassStatus(session.sessionToken),
  ]);

  return (
    <BreakGlassView
      initialAccounts={accounts}
      initialActivations={activations}
      initialError={accounts ? "" : "Break-glass records are unavailable, or your role cannot see them."}
      initialStatus={status}
    />
  );
}
