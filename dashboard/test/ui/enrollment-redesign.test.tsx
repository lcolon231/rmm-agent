// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, within, waitFor } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { EnrollmentAgentsTable } from "@/components/enrollment/agents-view";
import { EnrollmentTokensView } from "@/components/enrollment/tokens-view";
import type { EnrollmentAgent, EnrollmentTokenMetadata } from "@/lib/enrollment";
const agent={site_id:"s1",owner_user_id:null,enrolled_by_token_id:null,credential_issued_at:null,command_envelope_versions:[],trust_state_changed_at:null,trust_state_changed_by:null,id:"a1",name:"Workstation",hostname:"host1",os:"Windows",os_version:"11",agent_version:"1.0",architecture:"x64",environment:null,labels:[],status:"offline",trust_state:"quarantined",trust_state_reason:null,last_seen_at:null,enrolled_at:"2026-01-01T00:00:00Z",revoked_at:null,credential_fingerprint:null,credential_expires_at:null} as EnrollmentAgent;
const token={site_id:"s1",organization_id:"c1",description:null,assigned_user_id:null,assigned_user_email:null,environment:null,hostname_restriction:null,agent_name_restriction:null,created_by_id:null,revoked_at:null,revoked_by_id:null,revoked_by_email:null,notes:null,id:"t1",name:"Rollout",masked_token:"nl_***",organization_name:"Client",site_name:"Office",labels:[],status:"active",use_count:0,max_uses:1,created_at:"2026-01-01T00:00:00Z",expires_at:null,last_used_at:null,created_by_email:null} as EnrollmentTokenMetadata;
test("agent preview exposes missing credential evidence and hides read-only revocation",()=>{
 render(<AppRouterContext.Provider value={{refresh(){}} as never}><EnrollmentAgentsTable agents={[agent]} canRevoke={false} now="2026-01-02T00:00:00Z" sortNote="needs review first" /></AppRouterContext.Provider>);
 fireEvent.click(screen.getByRole("row",{name:"Preview Workstation"}));
 const drawer=within(screen.getByRole("dialog"));assert.ok(drawer.getByText(/None recorded/));assert.ok(drawer.getByText("Needs review"));assert.equal(drawer.queryByRole("button",{name:"Revoke agent"}),null);
 fireEvent.click(drawer.getByRole("button",{name:/Close/}));assert.equal(screen.queryByRole("dialog"),null);
});
test("token pagination retains filters and previews only the masked credential",()=>{
 render(<AppRouterContext.Provider value={{refresh(){}} as never}><EnrollmentTokensView tokens={[token]} total={80} pageSize={25} query={{page:2,search:"roll",status:"active"}} canManage={false} /></AppRouterContext.Provider>);
 assert.equal(screen.getByRole("link",{name:"Next page"}).getAttribute("href"),"/enrollment/tokens?page=3&search=roll&status=active");
 assert.equal(screen.getByRole("link",{name:"Previous page"}).getAttribute("href"),"/enrollment/tokens?search=roll&status=active");
 fireEvent.click(screen.getByRole("row",{name:"Preview Rollout"}));assert.ok(within(screen.getByRole("dialog")).getByText("nl_***"));assert.equal(screen.queryByRole("button",{name:"Revoke token"}),null);
 fireEvent.keyDown(document,{key:"Escape"});assert.equal(screen.queryByRole("dialog"),null);
});
test("token revocation closes layered dialogs only after success",async(t)=>{
 t.mock.method(globalThis,"fetch",async()=>Response.json({ok:true}));
 render(<AppRouterContext.Provider value={{refresh(){}} as never}><EnrollmentTokensView tokens={[token]} total={1} pageSize={25} query={{page:1}} canManage /></AppRouterContext.Provider>);
 fireEvent.click(screen.getByRole("row",{name:"Preview Rollout"}));fireEvent.click(screen.getByRole("button",{name:"Revoke token"}));
 const dialog=within(screen.getByRole("alertdialog"));fireEvent.change(dialog.getByRole("textbox"),{target:{value:"Rollout completed"}});fireEvent.click(dialog.getByRole("button",{name:"Revoke token"}));
 await waitFor(()=>assert.ok(screen.queryByRole("alertdialog")===null));assert.equal(screen.queryByRole("dialog"),null);
});
test("empty filtered tokens can clear filters without inventing token data",()=>{
 let pushed="";render(<AppRouterContext.Provider value={{refresh(){},push(value:string){pushed=value;}} as never}><EnrollmentTokensView tokens={[]} total={0} pageSize={25} query={{page:1,search:"missing"}} canManage={false} /></AppRouterContext.Provider>);
 fireEvent.click(screen.getByRole("button",{name:"Clear filters"}));assert.equal(pushed,"/enrollment/tokens");
});

