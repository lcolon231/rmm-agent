// SPDX-License-Identifier: AGPL-3.0-only

import { MfaSettingsView } from "@/components/mfa-settings-view";
import { SessionInventoryView } from "@/components/session-inventory-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { fetchOwnSessions } from "@/lib/nodelink-admin-sessions";
import { fetchMfaStatus } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

/**
 * Self-service second-factor management for the signed-in operator (issue #67).
 *
 * The initial state is fetched server-side so the page renders correctly with
 * no client round trip; the view refreshes it after every change.
 */
export default async function SecurityPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return null;
  }

  const [status, sessions] = await Promise.all([
    fetchMfaStatus(session.sessionToken),
    fetchOwnSessions(session.sessionToken),
  ]);
  return (
    <>
      <MfaSettingsView
        initialError={status ? "" : "Your multi-factor state is unavailable. Try again."}
        initialStatus={status}
      />
      <SessionInventoryView
        initialError={sessions ? "" : "Your sessions are unavailable. Try again."}
        initialSessions={sessions}
      />
    </>
  );
}
