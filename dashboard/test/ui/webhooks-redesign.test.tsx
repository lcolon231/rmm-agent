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

import { fireEvent, waitFor, within } from "@testing-library/react";
import type { WebhookEndpoint } from "@/lib/monitoring-core";
const endpoint: WebhookEndpoint = { id:"w1",name:"Relay",url:"https://relay.example.test/***",event_types:["opened"],enabled:true,current_secret_version:1,current_secret_key_id:"key1",version:3,deleted_at:null,created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z" };
function manage() { render(<AppRouterContext.Provider value={{refresh(){}} as never}><WebhookEndpointManager initialEndpoints={[endpoint]} status={{encryption_key_configured:true,endpoint_count:1,enabled_endpoint_count:1,endpoint_limit:10,counts:{delivered:2,failed:1}}} canAdmin canOperate /></AppRouterContext.Provider>); }
test("editing a webhook keeps the masked address out of updates and preserves concurrency",async(t)=>{
 let body: Record<string,unknown>={};
 t.mock.method(globalThis,"fetch",async(_url:RequestInfo|URL,init?:RequestInit)=>{body=JSON.parse(init?.body as string);return Response.json({endpoint:{...endpoint,name:"Renamed",version:4}});});
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Edit"}));
 fireEvent.change(screen.getByLabelText("Name"),{target:{value:"Renamed"}});fireEvent.click(screen.getByLabelText("Opened again"));fireEvent.click(screen.getByLabelText("Opened again"));
 fireEvent.submit(screen.getByRole("form",{name:"Edit destination"}));
 await waitFor(()=>assert.equal(body.name,"Renamed"));assert.equal(body.expected_version,3);assert.equal(body.url,undefined);assert.equal(typeof body.request_id,"string");
 assert.ok(await screen.findByRole("row",{name:"Open Renamed"}));
});
test("webhook address validation reports the server result without claiming delivery",async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({validation:{state:"invalid",code:"private_address",resolved_address_count:0}}));
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Check address"}));
 assert.ok(await screen.findByText(/Address check failed/));
});
test("webhook rotation requires a reason and shows the replacement secret only until dismissed",async(t)=>{
 let body:Record<string,unknown>={};
 t.mock.method(globalThis,"fetch",async(_url:RequestInfo|URL,init?:RequestInit)=>{body=JSON.parse(init?.body as string);return Response.json({endpoint:{...endpoint,version:4,current_secret_version:2,secret:"one-time-secret"}});});
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Rotate secret"}));
 const dialog=within(screen.getByRole("alertdialog"));assert.equal((dialog.getByRole("button",{name:"Rotate secret"}) as HTMLButtonElement).disabled,true);
 fireEvent.change(dialog.getByRole("textbox"),{target:{value:"Scheduled rotation"}});fireEvent.click(dialog.getByRole("button",{name:"Rotate secret"}));
 assert.ok(await screen.findByText("one-time-secret"));assert.equal(body.expected_version,3);assert.equal(body.reason,undefined);
 fireEvent.click(screen.getByRole("button",{name:"Dismiss"}));assert.equal(screen.queryByText("one-time-secret"),null);
});
test("webhook creation sends selected events and clears the one-time reveal on dismissal",async(t)=>{
 let body:Record<string,unknown>={};
 t.mock.method(globalThis,"fetch",async(_url:RequestInfo|URL,init?:RequestInit)=>{body=JSON.parse(init?.body as string);return Response.json({endpoint:{...endpoint,id:"w2",name:"Second",secret:"new-secret"}});});
 manage();fireEvent.click(screen.getByRole("button",{name:"Add a webhook"}));
 fireEvent.change(screen.getByLabelText("Name"),{target:{value:"Second"}});fireEvent.change(screen.getByLabelText("Public HTTPS address"),{target:{value:"https://second.example.test/hook"}});
 fireEvent.click(screen.getByLabelText("Opened"));fireEvent.submit(screen.getByRole("form",{name:"Add a webhook"}));
 assert.ok(await screen.findByText("new-secret"));assert.equal(body.url,"https://second.example.test/hook");assert.equal((body.event_types as string[]).includes("opened"),false);
 fireEvent.click(screen.getByRole("button",{name:"Dismiss"}));assert.equal(screen.queryByText("new-secret"),null);
});
test("webhook removal preserves a refused server response inside the reason dialog",async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({error:"Version conflict"},{status:409}));
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Remove"}));
 const dialog=within(screen.getByRole("alertdialog"));fireEvent.change(dialog.getByRole("textbox"),{target:{value:"Relay retired"}});fireEvent.click(dialog.getByRole("button",{name:"Remove destination"}));
 assert.ok(await dialog.findByText("Version conflict"));assert.ok(screen.getByRole("row",{name:"Open Relay"}));
});

test("webhook validation does not turn an unavailable address check into a pass",async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({validation:{state:"unavailable",code:null,resolved_address_count:0}}));
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Check address"}));
 assert.ok(await screen.findByText(/could not be checked right now/));
});
test("webhook rotation preserves refused version checks without exposing a secret",async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({error:"Version conflict"},{status:409}));
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Rotate secret"}));
 const dialog=within(screen.getByRole("alertdialog"));fireEvent.change(dialog.getByRole("textbox"),{target:{value:"Rotation requested"}});fireEvent.click(dialog.getByRole("button",{name:"Rotate secret"}));
 assert.ok(await dialog.findByText("Version conflict"));assert.equal(screen.queryByRole("status",{name:"New signing secret"}),null);
});

for (const result of [
 {state:"valid",code:null,resolved_address_count:1,expected:"Address check passed · 1 public address"},
 {state:"valid",code:null,resolved_address_count:2,expected:"Address check passed · 2 public addresses"},
 {state:"unsupported",code:"scheme",resolved_address_count:0,expected:"This address cannot be used · scheme"},
]) test(`webhook address check distinguishes ${result.state} with ${result.resolved_address_count} addresses`,async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({validation:result}));
 manage();fireEvent.click(screen.getByRole("row",{name:"Open Relay"}));fireEvent.click(screen.getByRole("button",{name:"Check address"}));
 assert.ok(await screen.findByText(result.expected));
});
