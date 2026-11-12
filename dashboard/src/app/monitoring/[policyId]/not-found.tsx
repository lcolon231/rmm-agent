// SPDX-License-Identifier: AGPL-3.0-only

import { NotFoundPanel } from "@/components/monitoring/not-found-panel";

export default function MonitoringPolicyNotFound() {
  return <NotFoundPanel role="alert" title="Monitoring policy not found" body="The policy may have been deleted, or the link is no longer valid." href="/monitoring" linkLabel="Back to monitoring policies" />;
}
