// SPDX-License-Identifier: AGPL-3.0-only

import type { DashboardOperator, DashboardSessionState } from "./dashboard-auth-core.ts";
import { NodelinkApiError } from "./nodelink-api-core.ts";

/**
 * Revalidate a session cookie against the API (issue #281 split).
 *
 * The cookie read and the `/auth/me` call are injected so the decision can be
 * tested without a Next runtime. It fails closed: only a 2xx yields an
 * operator. A 401/403 means the token is dead, so the visitor is anonymous and
 * can sign in again; anything else (5xx, timeout, transport error) is reported
 * as unavailable so a healthy session is not logged out by an API blip.
 */
export async function resolveDashboardSession(
  sessionToken: string | undefined,
  loadOperator: (sessionToken: string) => Promise<DashboardOperator>,
): Promise<DashboardSessionState> {
  if (!sessionToken) {
    return { kind: "anonymous" };
  }

  try {
    return {
      kind: "authenticated",
      operator: await loadOperator(sessionToken),
      sessionToken,
    };
  } catch (error) {
    if (error instanceof NodelinkApiError && (error.status === 401 || error.status === 403)) {
      return { kind: "anonymous" };
    }
    return { kind: "unavailable" };
  }
}
