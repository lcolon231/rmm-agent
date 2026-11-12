// SPDX-License-Identifier: AGPL-3.0-only

import { TabNav } from "../ui/tab-nav";

/**
 * Monitoring sub-tabs. There is no fleet-wide delivery history in the API
 * (deliveries are listed per alert), so the second tab is the webhook
 * destinations page, which carries the delivery totals.
 */
export function MonitoringTabs({ current }: { current: "policies" | "webhooks" }) {
  return (
    <TabNav
      label="Monitoring sections"
      tabs={[
        { label: "Policies", href: "/monitoring", current: current === "policies" },
        { label: "Webhook destinations", href: "/monitoring/webhooks", current: current === "webhooks" },
      ]}
    />
  );
}
