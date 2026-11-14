// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import { assistantPageHref, assistantPrefill, loadAssistantContext } from "../src/lib/assistant-context-core.ts";

const CLIENT = "55555555-5555-4555-8555-555555555555";
const ENDPOINT = "77777777-7777-4777-8777-777777777777";

test("navigation and status load together and fail independently", async () => {
  const navigation = { items: [] };
  assert.deepEqual(
    await loadAssistantContext({ navigation: async () => navigation, status: async () => ({ state: "available" }) }),
    { clients: navigation, state: "available" },
  );
  assert.deepEqual(
    await loadAssistantContext({ navigation: async () => { throw new Error("nav down"); }, status: async () => ({ state: "disabled" }) }),
    { clients: null, state: "disabled" },
  );
  for (const status of [async () => { throw new Error("status down"); }, async () => null, async () => "available", async () => ({})]) {
    assert.deepEqual(await loadAssistantContext({ navigation: async () => navigation, status }), { clients: navigation, state: "unavailable" });
  }
});

test("prefill accepts only a visible client and a well-formed endpoint", () => {
  assert.deepEqual(assistantPrefill("/alerts", { client_id: CLIENT, endpoint_id: ENDPOINT }, [CLIENT]), { clientId: CLIENT, endpointId: ENDPOINT });
  assert.deepEqual(assistantPrefill("/alerts", { client_id: "someone-else", endpoint_id: "../etc" }, [CLIENT]), { clientId: undefined, endpointId: undefined });
  assert.deepEqual(assistantPrefill("/alerts", {}, [CLIENT]), { clientId: undefined, endpointId: undefined });
});

test("on an endpoint page the endpoint comes from the route segment", () => {
  assert.equal(assistantPrefill(`/endpoints/${ENDPOINT}`, {}, []).endpointId, ENDPOINT);
  assert.equal(assistantPrefill(`/endpoints/${ENDPOINT}/inventory`, { endpoint_id: null }, []).endpointId, ENDPOINT);
  assert.equal(assistantPrefill("/endpoints", {}, []).endpointId, undefined);
  assert.equal(assistantPrefill("/endpoints/not-an-id", {}, []).endpointId, undefined);
  assert.equal(assistantPrefill(`/support/${ENDPOINT}`, {}, []).endpointId, undefined);
});

test("the full-page link keeps the current client and endpoint", () => {
  assert.equal(assistantPageHref({}), "/assistant");
  assert.equal(assistantPageHref({ clientId: CLIENT }), `/assistant?client_id=${CLIENT}`);
  assert.equal(assistantPageHref({ clientId: CLIENT, endpointId: ENDPOINT }), `/assistant?client_id=${CLIENT}&endpoint_id=${ENDPOINT}`);
});
