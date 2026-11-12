// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import * as view from "../src/lib/monitoring-view-core.ts";
import * as admin from "../src/lib/admin-screens-core.ts";
import type { OperatorRecord } from "../src/lib/operator-management-core.ts";
test("monitoring filters preserve route defaults and never include resolved alerts in active severity filters",()=>{
 for(const state of ["open","acknowledged","resolved"] as const) {
  const row={state,last_result_status:"critical" as const};
  assert.equal(view.alertMatchesFilter(row,"critical"),state!=="resolved");
  assert.equal(view.alertMatchesFilter(row,"active"),state!=="resolved");
  assert.equal(view.alertMatchesFilter(row,state),true);
  assert.ok(view.alertStateWord(state).label);
 }
 assert.equal(view.parseAlertFilter(["warning"]),"warning");assert.equal(view.parseAlertFilter("nonsense"),"active");
 assert.equal(view.alertsHref("active"),"/alerts");assert.equal(view.alertsHref("open"),"/alerts?filter=open");
 assert.equal(view.parseAlertTab(["timeline"]),"timeline");assert.equal(view.parseAlertTab("notifications"),"notifications");assert.equal(view.parseAlertTab(undefined),"summary");
 assert.equal(view.parsePolicyFilter(["disabled"]),"disabled");assert.equal(view.parsePolicyFilter("active"),"active");assert.equal(view.parsePolicyFilter(undefined),"all");
 assert.equal(view.policiesHref("all"),"/monitoring");assert.equal(view.policiesHref("disabled"),"/monitoring?state=disabled");
 assert.equal(view.parsePolicyTab(["history"]),"history");assert.equal(view.parsePolicyTab("bad"),"rule");
});
test("policy risk uses only loaded unresolved alerts and keeps unknown data neutral",()=>{
 const counts=view.countAlertsByPolicy([{policy_id:"p",state:"open",last_result_status:"critical"},{policy_id:"p",state:"acknowledged",last_result_status:"warning"},{policy_id:"p",state:"resolved",last_result_status:"critical"}]);
 assert.deepEqual(counts.get("p"),{open:2,critical:1});
 assert.equal(view.policyRiskTone({enabled:true},undefined,false),"info");assert.equal(view.policyRiskTone({enabled:false},undefined,false),"off");
 assert.equal(view.policyRiskTone({enabled:true},{open:1,critical:0},true),"warn");assert.equal(view.policyRiskTone({enabled:false},undefined,true),"off");assert.equal(view.policyRiskTone({enabled:true},undefined,true),"ok");
 assert.deepEqual(view.sortPoliciesByRisk([{id:"q",enabled:true},{id:"p",enabled:true},{id:"r",enabled:true}],counts,true).map(p=>p.id),["p","q","r"]);
 assert.equal(view.policyStateWord(false).label,"Disabled");assert.equal(view.policyStateWord(true).label,"Active");
});
test("monitoring descriptions distinguish delivery, state changes and threshold comparisons",()=>{
 assert.equal(view.alertTitle(""),"Monitoring check");assert.equal(view.alertTitle("cpu_usage"),"Cpu usage");
 for(const event of ["opened","reopened","acknowledged","manual_resolution","automatic_recovery","assigned"] as const){assert.ok(view.alertEventWord(event));assert.ok(view.alertEventTone(event));}
 for(const state of ["pending","sending","retrying","failed","suppressed"] as const){assert.ok(view.emailDeliveryWord(state).label);assert.ok(view.webhookDeliveryWord(state).label);}
 assert.equal(view.emailDeliveryWord("sent").label,"Sent");assert.equal(view.webhookDeliveryWord("delivered").label,"Delivered");
 assert.equal(view.thresholdWords(null),"Raised when the state changes");assert.equal(view.thresholdWords({op:"gte",warning:null,critical:null}),"No limit set");assert.equal(view.thresholdWords({op:"gt",warning:70,critical:90}),"Warning above 70 · Critical above 90");
 assert.equal(view.intervalWords(3600),"Every hour");assert.equal(view.intervalWords(120),"Every 2 minutes");assert.equal(view.intervalWords(15),"Every 15 seconds");
 assert.equal(view.paramsWords({}),"None");assert.equal(view.paramsWords({z:2,a_name:"svc"}),"a name: svc · z: 2");assert.equal(view.checkTypeWord("service"),"Windows service running");
});
test("enrollment risk and counts separate revoked credentials from live devices",()=>{
 const rows=[{status:"online",trust_state:"active"},{status:"offline",trust_state:"active"},{status:"pending",trust_state:"active"},{status:"online",trust_state:"quarantined"},{status:"offline",trust_state:"revoked"}] as const;
 assert.deepEqual(admin.sortAgentsByAttention(rows),[rows[3],rows[1],rows[2],rows[0],rows[4]]);
 assert.deepEqual(admin.countAgents(rows),{online:2,offline:1,waiting:1,revoked:1});
 for(const state of ["online","offline","pending"] as const)assert.ok(admin.agentCheckInBadge(state).label);
 for(const state of ["active","quarantined","revoked"] as const)assert.ok(admin.agentTrustBadge(state).detail);
 for(const state of ["active","revoked","expired","used"] as const)assert.ok(admin.tokenStatusBadge(state).label);
 assert.equal(admin.tokensHref({page:1}),"/enrollment/tokens");assert.equal(admin.tokensHref({page:1,search:"a b",status:"expired"},{page:2}),"/enrollment/tokens?page=2&search=a+b&status=expired");
 assert.ok(admin.reasonProblem(" "));assert.ok(admin.reasonProblem("x".repeat(501)));assert.equal(admin.reasonProblem("Retired"),null);
});
test("operator counts and search never confuse disabled administrators with active ones",()=>{
 const rows=[{email:"Admin@example.test",role:"admin",disabled:false,script_execution_scope:"global"},{email:"old@example.test",role:"admin",disabled:true,script_execution_scope:null},{email:"tech@example.test",role:"operator",disabled:false,script_execution_scope:null},{email:"view@example.test",role:"readonly",disabled:false,script_execution_scope:null}] as OperatorRecord[];
 assert.deepEqual(admin.operatorCounts(rows),{total:4,disabled:1,admins:1,technicians:1,readonly:1,scripts:1});
 assert.equal(admin.filterOperators(rows,"all"," ADMIN ").length,1);assert.deepEqual(admin.filterOperators(rows,"disabled",""),[rows[1]]);assert.deepEqual(admin.filterOperators(rows,"operator",""),[rows[2]]);
});

