// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { render, screen } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { WebhookEndpointManager } from "@/components/webhook-endpoint-manager";
test("readonly webhook review exposes no create or secret mutation actions", () => {
  render(<AppRouterContext.Provider value={{ refresh() {} } as never}><WebhookEndpointManager initialEndpoints={[]} status={{ encryption_key_configured: true, endpoint_count: 0, enabled_endpoint_count: 0, endpoint_limit: 10, counts: {} }} canAdmin={false} canOperate={false} /></AppRouterContext.Provider>);
  assert.equal(screen.queryByRole("button", { name: /Add a webhook|Rotate secret|Remove destination/ }), null);
});
