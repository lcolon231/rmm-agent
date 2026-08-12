// SPDX-License-Identifier: AGPL-3.0-only

export type EndpointStatus = "online" | "warning" | "critical" | "offline";

export type Endpoint = {
  id: string;
  name: string;
  os: string;
  client: string;
  site: string;
  group: string;
  status: EndpointStatus;
  lastSeen: string;
  user: string;
  cpu: number | null;
  memory: number | null;
  disk: number | null;
  work: "none" | "command" | "queued" | "policy";
  issue: "offline" | "failed" | "disk" | "stale" | null;
};

export type AttentionItem = {
  id: "offline" | "failed" | "disk" | "stale";
  title: string;
  detail: string;
  count: number;
  endpoint: string;
  site: string;
  observed: string;
  tone: "critical" | "warning";
  action: string;
};

export type SignedAction = {
  id?: string;
  time: string;
  title: string;
  target: string;
  actor: string;
  signature: string;
  kind: "action" | "anchor";
};
