// SPDX-License-Identifier: AGPL-3.0-only

import { NotFoundPanel } from "@/components/monitoring/not-found-panel";

export default function AlertNotFound() {
  return <NotFoundPanel title="Alert not found" body="It may have been removed with its device, or the link is no longer valid." href="/alerts" linkLabel="Back to Alerts" />;
}
