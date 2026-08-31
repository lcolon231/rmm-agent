// SPDX-License-Identifier: AGPL-3.0-only

import { MfaSettingsView } from "@/components/mfa-settings-view";
import { getDashboardSession } from "@/lib/dashboard-session";
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

  const status = await fetchMfaStatus(session.sessionToken);
  return (
    <MfaSettingsView
      initialError={status ? "" : "Your multi-factor state is unavailable. Try again."}
      initialStatus={status}
    />
  );
}
