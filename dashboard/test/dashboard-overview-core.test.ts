// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import type { AuditAnchorRecord, AuditChainVerification, AuditEventRecord } from "../src/lib/audit-core.ts";
import {
  calculateFleetSummary,
  deriveAttentionItems,
  formatSignedActions,
  formatTrustStatus,
  type SigningKeyInfo,
} from "../src/lib/dashboard-overview-core.ts";
import type { EndpointListItem } from "../src/lib/endpoint-list.ts";
import type { MonitoringAlert } from "../src/lib/monitoring-core.ts";

test("calculateFleetSummary handles empty endpoint array cleanly without division by zero", () => {
  const summary = calculateFleetSummary([], 0);
  assert.equal(summary.total, 0);
  assert.equal(summary.onlineCount, 0);
  assert.equal(summary.onlinePercent, 0);
  assert.equal(summary.warningCount, 0);
  assert.equal(summary.warningPercent, 0);
  assert.equal(summary.criticalCount, 0);
  assert.equal(summary.criticalPercent, 0);
  assert.equal(summary.offlineCount, 0);
  assert.equal(summary.offlinePercent, 0);
});

test("calculateFleetSummary accurately calculates status counts and percentages for mixed endpoints", () => {
  const items: EndpointListItem[] = [
    {
      id: "ep-1",
      hostname: "HOST-1",
      os: "Windows 11",
      os_version: "22H2",
      agent_version: "0.1.0",
      status: "online",
      last_seen_at: "2026-08-11T12:00:00Z",
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: 10,
      mem_percent: 40,
      disk_percent: 30,
      logged_in_user: "user1",
    },
    {
      id: "ep-2",
      hostname: "HOST-2",
      os: "Windows 11",
      os_version: "22H2",
      agent_version: "0.1.0",
      status: "online",
      last_seen_at: "2026-08-11T12:00:00Z",
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: 20,
      mem_percent: 50,
      disk_percent: 95, // High disk -> warning
      logged_in_user: "user2",
    },
    {
      id: "ep-3",
      hostname: "HOST-3",
      os: "Windows Server 2022",
      os_version: "21H2",
      agent_version: "0.1.0",
      status: "pending", // Pending -> warning
      last_seen_at: "2026-08-11T11:00:00Z",
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: 5,
      mem_percent: 20,
      disk_percent: 15,
      logged_in_user: "SYSTEM",
    },
    {
      id: "ep-4",
      hostname: "HOST-4",
      os: "Windows 11",
      os_version: "22H2",
      agent_version: "0.1.0",
      status: "offline",
      last_seen_at: "2026-08-10T08:00:00Z",
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: null,
      mem_percent: null,
      disk_percent: null,
      logged_in_user: null,
    },
  ];

  const summary = calculateFleetSummary(items, 4);
  assert.equal(summary.total, 4);
  assert.equal(summary.onlineCount, 1);
  assert.equal(summary.warningCount, 2);
  assert.equal(summary.offlineCount, 1);

  assert.equal(summary.onlinePercent, 25.0);
  assert.equal(summary.warningPercent, 50.0);
  assert.equal(summary.offlinePercent, 25.0);
  assert.equal(summary.onlineCount + summary.warningCount + summary.criticalCount + summary.offlineCount, summary.total);
});

test("deriveAttentionItems extracts offline, critical alert, high disk, and stale check-in items", () => {
  const now = new Date("2026-08-11T20:00:00Z");

  const endpoints: EndpointListItem[] = [
    {
      id: "ep-1",
      hostname: "OFFLINE-PC",
      os: "Windows 11",
      os_version: "22H2",
      agent_version: "0.1.0",
      status: "offline",
      last_seen_at: "2026-08-10T10:00:00Z", // 34h ago (> 24h)
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: null,
      mem_percent: null,
      disk_percent: null,
      logged_in_user: null,
    },
    {
      id: "ep-2",
      hostname: "DISK-FULL-PC",
      os: "Windows Server",
      os_version: "2019",
      agent_version: "0.1.0",
      status: "online",
      last_seen_at: "2026-08-11T19:55:00Z",
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: 15,
      mem_percent: 45,
      disk_percent: 94, // High disk (> 90%)
      logged_in_user: "admin",
    },
    {
      id: "ep-3",
      hostname: "STALE-PC",
      os: "Windows 10",
      os_version: "21H2",
      agent_version: "0.1.0",
      status: "online",
      last_seen_at: "2026-08-11T05:00:00Z", // 15h ago (12h..24h)
      client_id: "c-1",
      client_name: "Acme",
      site_id: "s-1",
      site_name: "HQ",
      cpu_percent: 5,
      mem_percent: 30,
      disk_percent: 40,
      logged_in_user: "user3",
    },
  ];

  const alerts: MonitoringAlert[] = [
    {
      id: "alt-1",
      agent_id: "ep-2",
      policy_id: "pol-1",
      policy_revision_id: "rev-1",
      check_key: "check-cpu",
      state: "open",
      last_result_status: "critical",
      occurrence_count: 3,
      total_occurrence_count: 5,
      generation: 1,
      first_opened_at: "2026-08-11T18:00:00Z",
      opened_at: "2026-08-11T18:00:00Z",
      last_observed_at: "2026-08-11T19:50:00Z",
      resolved_at: null,
      last_evaluated_at: "2026-08-11T19:50:00Z",
      last_result_id: "res-1",
      last_value: 98,
      resolution_reason: null,
      suppression_window_id: null,
      suppressed_until: null,
      assigned_to_operator_id: null,
      assigned_to_email: null,
      acknowledged_at: null,
      acknowledged_by: null,
      version: 1,
      created_at: "2026-08-11T18:00:00Z",
      updated_at: "2026-08-11T19:50:00Z",
    },
  ];

  const attention = deriveAttentionItems(alerts, endpoints, now);
  assert.equal(attention.length, 4);

  const offlineItem = attention.find((i) => i.id === "offline");
  assert.ok(offlineItem);
  assert.equal(offlineItem.count, 1);
  assert.equal(offlineItem.endpoint, "OFFLINE-PC");

  const failedItem = attention.find((i) => i.id === "failed");
  assert.ok(failedItem);
  assert.equal(failedItem.count, 1);
  assert.equal(failedItem.endpoint, "DISK-FULL-PC");

  const diskItem = attention.find((i) => i.id === "disk");
  assert.ok(diskItem);
  assert.equal(diskItem.count, 1);
  assert.equal(diskItem.endpoint, "DISK-FULL-PC");

  const staleItem = attention.find((i) => i.id === "stale");
  assert.ok(staleItem);
  assert.equal(staleItem.count, 1);
  assert.equal(staleItem.endpoint, "STALE-PC");
});

test("formatSignedActions maps real audit events into SignedAction list", () => {
  const events: AuditEventRecord[] = [
    {
      id: "evt-101",
      seq: 42,
      ts: "2026-08-11T14:30:00Z",
      actor: "operator@nodelink.dev",
      actor_user_id: "op-1",
      action: "command.dispatched",
      agent_id: "agent-abc12345",
      enrollment_token_id: null,
      organization_id: "org-1",
      source_ip: "127.0.0.1",
      detail: {},
    },
    {
      id: "evt-102",
      seq: 43,
      ts: "2026-08-11T15:00:00Z",
      actor: "NodeLink System",
      actor_user_id: null,
      action: "audit.anchored",
      agent_id: null,
      enrollment_token_id: null,
      organization_id: null,
      source_ip: null,
      detail: {},
    },
  ];

  const actions = formatSignedActions(events);
  assert.equal(actions.length, 2);

  assert.equal(actions[0].id, "evt-101");
  assert.equal(actions[0].title, "Command Dispatched");
  assert.equal(actions[0].target, "Agent agent-ab");
  assert.equal(actions[0].actor, "operator@nodelink.dev");
  assert.equal(actions[0].signature, "Seq #42");
  assert.equal(actions[0].kind, "action");

  assert.equal(actions[1].id, "evt-102");
  assert.equal(actions[1].title, "Audit Anchored");
  assert.equal(actions[1].target, "System");
  assert.equal(actions[1].kind, "anchor");
});

test("formatTrustStatus accurately surfaces intact vs broken chain and anchor details", () => {
  const chain: AuditChainVerification = {
    intact: true,
    first_broken_event_id: null,
  };
  const anchors: AuditAnchorRecord[] = [
    {
      id: "anc-1",
      created_at: "2026-08-11T10:00:00Z",
      event_count: 50,
      last_event_id: "evt-50",
      merkle_root: "a1b2c3d4e5f67890123456789abcdef0",
    },
  ];
  const signingKeys: SigningKeyInfo = {
    active_key_id: "key-prod-2026",
    keys: [{ key_id: "key-prod-2026", status: "Active", active: true }],
  };

  const status = formatTrustStatus(chain, anchors, signingKeys, false);
  assert.equal(status.chainIntact, true);
  assert.equal(status.firstBrokenEventId, null);
  assert.equal(status.anchorCount, 1);
  assert.equal(status.lastAnchorTime, "2026-08-11T10:00:00Z");
  assert.equal(status.lastAnchorMerkle, "a1b2c3d4e5f67890123456789abcdef0");
  assert.equal(status.activeSigningKeyId, "key-prod-2026");
  assert.equal(status.signingKeyStatus, "Active");
  assert.equal(status.isStale, false);
});
