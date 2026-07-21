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
  id: NonNullable<Endpoint["issue"]>;
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
  time: string;
  title: string;
  target: string;
  actor: string;
  signature: string;
  kind: "action" | "anchor";
};

export const clients = [
  {
    name: "Acme Health",
    short: "AH",
    sites: ["HQ", "West Clinic"],
  },
  {
    name: "Northstar Dental",
    short: "ND",
    sites: ["Main", "South"],
  },
];

export const attentionItems: AttentionItem[] = [
  {
    id: "offline",
    title: "Offline",
    detail: "Not seen in 24h+",
    count: 2,
    endpoint: "AH-HQ-LAP-27",
    site: "Acme Health · HQ",
    observed: "May 16, 8:47 AM",
    tone: "critical",
    action: "Investigate",
  },
  {
    id: "failed",
    title: "Failed commands",
    detail: "Last attempt failed",
    count: 2,
    endpoint: "NSD-DC-01",
    site: "Northstar Dental · Main",
    observed: "May 16, 9:51 AM",
    tone: "critical",
    action: "Review",
  },
  {
    id: "disk",
    title: "High disk usage",
    detail: "> 90% disk used",
    count: 2,
    endpoint: "AH-SRV-FS01",
    site: "Acme Health · HQ",
    observed: "May 16, 10:12 AM",
    tone: "warning",
    action: "Remediate",
  },
  {
    id: "stale",
    title: "Stale check-ins",
    detail: "No check-in in 12h+",
    count: 1,
    endpoint: "NSD-LAP-12",
    site: "Northstar Dental · South",
    observed: "May 16, 6:02 AM",
    tone: "warning",
    action: "Investigate",
  },
];

export const endpoints: Endpoint[] = [
  {
    id: "ep-01",
    name: "AH-HQ-LAP-14",
    os: "Windows 11 Pro",
    client: "Acme Health",
    site: "HQ",
    group: "Workstations",
    status: "online",
    lastSeen: "1 min ago",
    user: "jdoe",
    cpu: 18,
    memory: 42,
    disk: 61,
    work: "queued",
    issue: null,
  },
  {
    id: "ep-02",
    name: "AH-SRV-FS01",
    os: "Windows Server 2019",
    client: "Acme Health",
    site: "HQ",
    group: "Servers",
    status: "warning",
    lastSeen: "2 min ago",
    user: "SYSTEM",
    cpu: 26,
    memory: 68,
    disk: 93,
    work: "command",
    issue: "disk",
  },
  {
    id: "ep-03",
    name: "AH-HQ-LAP-27",
    os: "Windows 11 Pro",
    client: "Acme Health",
    site: "HQ",
    group: "Workstations",
    status: "offline",
    lastSeen: "1 day ago",
    user: "asmith",
    cpu: null,
    memory: null,
    disk: null,
    work: "queued",
    issue: "offline",
  },
  {
    id: "ep-04",
    name: "NSD-DC-01",
    os: "Windows Server 2019",
    client: "Northstar Dental",
    site: "Main",
    group: "Servers",
    status: "critical",
    lastSeen: "4 min ago",
    user: "SYSTEM",
    cpu: 74,
    memory: 81,
    disk: 45,
    work: "command",
    issue: "failed",
  },
  {
    id: "ep-05",
    name: "NSD-LAP-12",
    os: "Windows 11 Pro",
    client: "Northstar Dental",
    site: "South",
    group: "Workstations",
    status: "warning",
    lastSeen: "12 hr ago",
    user: "bwilson",
    cpu: 22,
    memory: 49,
    disk: 88,
    work: "policy",
    issue: "stale",
  },
  {
    id: "ep-06",
    name: "NSD-TS-03",
    os: "Windows 10 IoT",
    client: "Northstar Dental",
    site: "Main",
    group: "Treatment Rooms",
    status: "online",
    lastSeen: "3 min ago",
    user: "nsd\\ts03",
    cpu: 12,
    memory: 34,
    disk: 28,
    work: "none",
    issue: null,
  },
];

export const signedActions: SignedAction[] = [
  {
    time: "10:21 AM",
    title: "Run script: Clear temp files",
    target: "AH-SRV-FS01",
    actor: "Taylor Morgan",
    signature: "9F2B…7C1E",
    kind: "action",
  },
  {
    time: "10:12 AM",
    title: "Deploy update: KB5052660",
    target: "24 endpoints",
    actor: "Taylor Morgan",
    signature: "5C8D…2A90",
    kind: "action",
  },
  {
    time: "9:58 AM",
    title: "Reboot endpoint",
    target: "NSD-DC-01",
    actor: "Taylor Morgan",
    signature: "A1D4…8F60",
    kind: "action",
  },
  {
    time: "8:12 AM",
    title: "Anchor committed to ledger",
    target: "Block 7,482,193",
    actor: "NodeLink",
    signature: "C9CF…B11A",
    kind: "anchor",
  },
];
