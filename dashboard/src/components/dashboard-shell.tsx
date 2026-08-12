// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  BriefcaseBusiness,
  Building2,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Circle,
  CircleAlert,
  Clock3,
  Command,
  Download,
  FileClock,
  HeartPulse,
  KeyRound,
  Laptop,
  ListChecks,
  Menu,
  Monitor,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  TerminalSquare,
  Users,
  X,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import type { AuditAnchorRecord, AuditChainVerification, AuditEventRecord } from "@/lib/audit-core";
import type { NavigationData } from "@/lib/client-navigation";
import {
  calculateFleetSummary,
  deriveAttentionItems,
  formatSignedActions,
  formatTrustStatus,
  type AttentionItem,
  type SignedAction,
  type SigningKeyInfo,
  type TrustStatus,
} from "@/lib/dashboard-overview-core";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import { formatAgentVersion } from "@/lib/endpoint-detail-core";
import type { EndpointListData } from "@/lib/endpoint-list";
import type { MonitoringAlert } from "@/lib/monitoring-core";
import { operatorRoleLabel } from "@/lib/operator-management-core";
import type { Endpoint, EndpointStatus } from "@/data/dashboard";

const navItems = [
  { label: "Overview", icon: Activity, href: "/" },
  { label: "Endpoints", icon: Monitor, count: null, href: "/endpoints" },
  { label: "Alerts", icon: AlertTriangle, count: 7, href: "/alerts" },
  { label: "Automation", icon: Bot, count: null, href: "/scripts" },
  { label: "Tasks", icon: ListChecks, count: null, href: "/tasks" },
  { label: "Schedules", icon: Clock3, count: null, href: "/schedules" },
  { label: "Monitoring", icon: HeartPulse, count: null, href: "/monitoring" },
  { label: "Patch compliance", icon: Shield, count: null, href: "/patch-compliance" },
  { label: "Audit", icon: ShieldCheck, count: null, href: "/audit" },
  { label: "Administration", icon: Settings, count: null, href: "/enrollment" },
  { label: "Operators", icon: Users, count: null, href: "/operators", adminOnly: true },
];

const statusLabels: Record<EndpointStatus, string> = {
  online: "Online",
  warning: "Warning",
  critical: "Critical",
  offline: "Offline",
};

function StatusMark({ status }: { status: EndpointStatus }) {
  if (status === "online") {
    return <CheckCircle2 size={15} strokeWidth={2.4} />;
  }
  if (status === "warning") {
    return <AlertTriangle size={15} strokeWidth={2.4} />;
  }
  if (status === "critical") {
    return <CircleAlert size={15} strokeWidth={2.4} />;
  }
  return <Circle size={15} strokeWidth={2.2} />;
}

function Meter({ value }: { value: number | null }) {
  if (value === null) {
    return <span className="empty-value">—</span>;
  }

  const tone = value >= 90 ? "critical" : value >= 68 ? "warning" : "healthy";
  return (
    <div className="meter" aria-label={`${value}%`}>
      <span>{value}%</span>
      <i>
        <b className={tone} style={{ width: `${value}%` }} />
      </i>
    </div>
  );
}

function WorkIcon({ work }: { work: Endpoint["work"] }) {
  if (work === "command") return <TerminalSquare size={17} />;
  if (work === "queued") return <BriefcaseBusiness size={17} />;
  if (work === "policy") return <Shield size={17} />;
  return <FileClock size={17} />;
}

type SidebarProps = {
  activePath: string;
  navigation: NavigationData | null;
  navigationError: boolean;
  onClose: () => void;
  open: boolean;
  operator: DashboardOperator;
  selectedClientId?: string;
  selectedSiteId?: string;
  selectionError: boolean;
};

function Sidebar({
  activePath,
  navigation,
  navigationError,
  onClose,
  open,
  operator,
  selectedClientId,
  selectedSiteId,
  selectionError,
}: SidebarProps) {
  return (
    <>
      <button
        className={`sidebar-scrim ${open ? "is-open" : ""}`}
        onClick={onClose}
        aria-label="Close navigation"
      />
      <aside className={`sidebar ${open ? "is-open" : ""}`}>
        <div className="brand-row">
          <Link className="dashboard-brand" href="/" onClick={onClose}>
            <Image
              alt="NodeLink"
              className="brand-logo dark-logo"
              height={36}
              priority
              src="/brand/nodelink-dark.svg"
              width={140}
            />
            <Image
              alt="NodeLink"
              className="brand-logo light-logo"
              height={36}
              priority
              src="/brand/nodelink-light.svg"
              width={140}
            />
          </Link>
          <button className="mobile-close" onClick={onClose} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(({ label, icon: Icon, count, href, adminOnly }) => {
            if (adminOnly && operator.role !== "admin") {
              return null;
            }
            const isActive = activePath === href;
            return (
              <Link
                key={label}
                className={`nav-item ${isActive ? "active" : ""}`}
                href={href}
                onClick={onClose}
              >
                <Icon size={19} />
                <span>{label}</span>
                {count ? <span className="nav-count">{count}</span> : null}
              </Link>
            );
          })}
        </nav>

        <button className="collapse-button">
          <ChevronLeft size={18} />
          <span>Collapse</span>
        </button>
      </aside>
    </>
  );
}

function TrustRail({
  signedActions,
  trustStatus,
  error,
}: {
  signedActions: SignedAction[];
  trustStatus: TrustStatus;
  error?: boolean;
}) {
  return (
    <aside className="trust-rail">
      <header className="trust-title">
        <ShieldCheck size={27} />
        <div>
          <span>Trust status</span>
          <small>
            {error
              ? "Trust telemetry unavailable"
              : trustStatus.isStale
              ? "Stale trust data"
              : trustStatus.chainIntact
              ? "Live chain verified"
              : "Audit chain alert"}
          </small>
        </div>
      </header>

      <div className="trust-facts">
        <div className="trust-fact">
          <span className="fact-icon">
            <Shield size={17} />
          </span>
          <div>
            <small>Audit chain</small>
            <strong className={trustStatus.chainIntact ? "healthy" : "critical"}>
              {trustStatus.chainIntact ? "Intact" : "Compromised"}
            </strong>
          </div>
        </div>
        <div className="trust-fact">
          <span className="fact-icon">
            <Clock3 size={17} />
          </span>
          <div>
            <small>Last anchor</small>
            <strong className="neutral">
              {trustStatus.lastAnchorTime
                ? new Intl.DateTimeFormat("en-US", { dateStyle: "short", timeStyle: "short" }).format(new Date(trustStatus.lastAnchorTime))
                : "No anchors"}
            </strong>
            <em>
              {trustStatus.lastAnchorMerkle
                ? `${trustStatus.lastAnchorMerkle.slice(0, 16)}…`
                : "Unanchored"}
            </em>
          </div>
        </div>
        <div className="trust-fact">
          <span className="fact-icon">
            <KeyRound size={17} />
          </span>
          <div>
            <small>Signing key</small>
            <strong className="neutral">{trustStatus.signingKeyStatus ?? "Active"}</strong>
            <em>
              {trustStatus.activeSigningKeyId
                ? `${trustStatus.activeSigningKeyId.slice(0, 16)}…`
                : "Default key"}
            </em>
          </div>
        </div>
      </div>

      <div className="rail-divider" />
      <h2>
        Recent actions <span>(signed)</span>
      </h2>
      <div className="custody-timeline">
        {signedActions.length === 0 ? (
          <div className="empty-state">
            <span>No recent audit events</span>
          </div>
        ) : (
          signedActions.map((action) => (
            <article key={action.id || `${action.time}-${action.title}`}>
              <span className={`timeline-node ${action.kind}`}>
                {action.kind === "anchor" ? <Shield size={14} /> : <Check size={14} />}
              </span>
              <time>{action.time}</time>
              <strong>{action.title}</strong>
              <span>{action.target}</span>
              <small>by {action.actor}</small>
              <code>Sig: {action.signature}</code>
            </article>
          ))
        )}
      </div>
      <div className="chain-state">
        <ShieldCheck size={16} /> Authenticated audit trail
      </div>
    </aside>
  );
}

function EndpointDrawer({ endpoint, onClose }: { endpoint: Endpoint | null; onClose: () => void }) {
  return (
    <>
      <button
        className={`drawer-scrim ${endpoint ? "is-open" : ""}`}
        onClick={onClose}
        aria-label="Close endpoint details"
      />
      <aside className={`endpoint-drawer ${endpoint ? "is-open" : ""}`} aria-hidden={!endpoint}>
        {endpoint ? (
          <>
            <div className="drawer-header">
              <div className="device-icon">
                <Server size={24} />
              </div>
              <div>
                <small>
                  {endpoint.client} · {endpoint.site}
                </small>
                <h2>{endpoint.name}</h2>
                <span>{endpoint.os}</span>
              </div>
              <button onClick={onClose} aria-label="Close endpoint details">
                <X size={20} />
              </button>
            </div>
            <div className={`status-chip ${endpoint.status}`}>
              <StatusMark status={endpoint.status} /> {statusLabels[endpoint.status]}
            </div>
            <div className="drawer-grid">
              <div>
                <small>Last seen</small>
                <strong>{endpoint.lastSeen}</strong>
              </div>
              <div>
                <small>Logged-in user</small>
                <strong>{endpoint.user}</strong>
              </div>
              <div>
                <small>Group</small>
                <strong>{endpoint.group}</strong>
              </div>
              <div>
                <small>Trust</small>
                <strong className="verified-text">
                  <ShieldCheck size={15} /> Verified
                </strong>
              </div>
            </div>
            <h3>Current telemetry</h3>
            <div className="drawer-telemetry">
              <div>
                <span>CPU</span>
                <Meter value={endpoint.cpu} />
              </div>
              <div>
                <span>Memory</span>
                <Meter value={endpoint.memory} />
              </div>
              <div>
                <span>System disk</span>
                <Meter value={endpoint.disk} />
              </div>
            </div>
            {endpoint.issue ? (
              <div className={`drawer-notice ${endpoint.status}`}>
                <AlertTriangle size={18} />
                <div>
                  <strong>Operator review recommended</strong>
                  <span>This endpoint is included in the active attention queue.</span>
                </div>
              </div>
            ) : null}
            <div className="drawer-actions">
              <Link className="primary-action" href={`/endpoints/${encodeURIComponent(endpoint.id)}/commands`}>
                <Command size={17} /> Review action
              </Link>
              <Link className="secondary-action" href={`/endpoints/${encodeURIComponent(endpoint.id)}`}>
                Open endpoint
              </Link>
            </div>
          </>
        ) : null}
      </aside>
    </>
  );
}

export function DashboardSectionShell({
  activePath,
  children,
  navigation,
  navigationError,
  operator,
  sectionLabel,
  sectionTitle,
}: {
  activePath: string;
  children: React.ReactNode;
  navigation: NavigationData | null;
  navigationError: boolean;
  operator: DashboardOperator;
  sectionLabel: string;
  sectionTitle: string;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [signOutError, setSignOutError] = useState("");

  async function signOut() {
    setSignOutError("");
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.assign("/login");
    } catch {
      setSignOutError("Sign-out could not be confirmed. Try again.");
    }
  }

  const operatorInitials = operator.email
    .split("@")[0]
    .split(/[._-]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="app-shell">
      <Sidebar
        activePath={activePath}
        navigation={navigation}
        navigationError={navigationError}
        onClose={() => setSidebarOpen(false)}
        open={sidebarOpen}
        operator={operator}
        selectionError={false}
      />
      <header className="topbar section-topbar">
        <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
          <Menu size={21} />
        </button>
        <div className="section-context">
          <span>{sectionLabel}</span>
          <strong>{sectionTitle}</strong>
        </div>
        <div className="topbar-spacer" />
        <div className="profile-block">
          <div>
            <strong>{operator.email}</strong>
            <span>{operatorRoleLabel(operator.role)}</span>
          </div>
          <span className="avatar">{operatorInitials}</span>
          <button className="sign-out" onClick={signOut}>
            Sign out
          </button>
        </div>
      </header>
      <main className="workspace section-workspace">
        <div className="content-column">
          {signOutError ? (
            <p className="sign-out-error" role="alert">
              {signOutError}
            </p>
          ) : null}
          {children}
        </div>
      </main>
    </div>
  );
}

type DashboardShellProps = {
  alerts: MonitoringAlert[];
  alertsError: boolean;
  auditEvents: AuditEventRecord[];
  auditError: boolean;
  chainVerification: AuditChainVerification | null;
  anchors: AuditAnchorRecord[];
  signingKeys: SigningKeyInfo | null;
  trustError: boolean;
  endpointError: boolean;
  endpointList: EndpointListData | null;
  endpointSearch: string;
  endpointSort: "last_seen" | "hostname" | "status";
  endpointStatus?: "online" | "offline" | "pending";
  navigation: NavigationData | null;
  navigationError: boolean;
  operator: DashboardOperator;
  selectedClientId?: string;
  selectedSiteId?: string;
  selectionError: boolean;
};

export function DashboardShell({
  alerts,
  alertsError,
  auditEvents,
  auditError,
  chainVerification,
  anchors,
  signingKeys,
  trustError,
  endpointError,
  endpointList,
  endpointSearch,
  endpointSort,
  endpointStatus,
  navigation,
  navigationError,
  operator,
  selectedClientId,
  selectedSiteId,
  selectionError,
}: DashboardShellProps) {
  const router = useRouter();
  const [query, setQuery] = useState(endpointSearch);
  const [issueFilter, setIssueFilter] = useState<Endpoint["issue"] | "all">("all");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);
  const [refreshTime, setRefreshTime] = useState(() =>
    new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(new Date()),
  );
  const [signOutError, setSignOutError] = useState("");

  const fleetSummary = useMemo(
    () => calculateFleetSummary(endpointList?.items ?? [], endpointList?.total),
    [endpointList],
  );

  const attentionItemsList = useMemo(
    () => deriveAttentionItems(alerts, endpointList?.items ?? []),
    [alerts, endpointList],
  );

  const signedActionsList = useMemo(
    () => formatSignedActions(auditEvents),
    [auditEvents],
  );

  const trustStatusData = useMemo(
    () => formatTrustStatus(chainVerification, anchors, signingKeys, trustError),
    [chainVerification, anchors, signingKeys, trustError],
  );

  const serverEndpoints: Endpoint[] = useMemo(
    () =>
      endpointList?.items.map((endpoint) => {
        const isOffline = endpoint.status === "offline";
        const isWarning = endpoint.status === "pending" || (endpoint.disk_percent !== null && endpoint.disk_percent >= 90);
        const issue: Endpoint["issue"] = isOffline
          ? "offline"
          : endpoint.disk_percent !== null && endpoint.disk_percent >= 90
          ? "disk"
          : null;

        return {
          id: endpoint.id,
          name: endpoint.hostname,
          os: [endpoint.os, endpoint.os_version].filter(Boolean).join(" "),
          client: endpoint.client_name,
          site: endpoint.site_name,
          group: formatAgentVersion(endpoint.agent_version, "Agent"),
          status: isOffline ? "offline" : isWarning ? "warning" : "online",
          lastSeen: endpoint.last_seen_at
            ? new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(new Date(endpoint.last_seen_at))
            : "Never",
          user: endpoint.logged_in_user ?? "—",
          cpu: endpoint.cpu_percent,
          memory: endpoint.mem_percent,
          disk: endpoint.disk_percent,
          work: "none",
          issue,
        };
      }) ?? [],
    [endpointList],
  );

  const visibleEndpoints = useMemo(() => {
    return serverEndpoints.filter((endpoint) => {
      const matchesIssue = issueFilter === "all" || endpoint.issue === issueFilter;
      return matchesIssue;
    });
  }, [issueFilter, serverEndpoints]);

  const exportCsv = () => {
    const rows = [
      ["Endpoint", "Client", "Site", "Status", "Last seen", "User", "CPU", "Memory", "Disk"],
      ...visibleEndpoints.map((endpoint) => [
        endpoint.name,
        endpoint.client,
        endpoint.site,
        endpoint.status,
        endpoint.lastSeen,
        endpoint.user,
        endpoint.cpu ?? "",
        endpoint.memory ?? "",
        endpoint.disk ?? "",
      ]),
    ];
    const csv = rows
      .map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(","))
      .join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "nodelink-fleet.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const refresh = () => {
    setRefreshTime(new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(new Date()));
    router.refresh();
  };

  const signOut = async () => {
    setSignOutError("");
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.assign("/login");
    } catch {
      setSignOutError("Sign-out could not be confirmed. Try again.");
    }
  };

  const updateEndpointQuery = (changes: Record<string, string | undefined>) => {
    if ("search" in changes) setQuery(changes.search ?? "");
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(changes)) {
      if (value) params.set(key, value);
      else params.delete(key);
    }
    if (!("page" in changes)) params.delete("page");
    const nextQuery = params.toString();
    router.push(nextQuery ? `/?${nextQuery}` : "/");
  };

  const operatorInitials = operator.email
    .split("@")[0]
    .split(/[._-]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const activeAlertCount = alerts.filter((a) => a.state !== "resolved").length;

  return (
    <div className="app-shell">
      <Sidebar
        activePath="/"
        navigation={navigation}
        navigationError={navigationError}
        onClose={() => setSidebarOpen(false)}
        open={sidebarOpen}
        operator={operator}
        selectedClientId={selectedClientId}
        selectedSiteId={selectedSiteId}
        selectionError={selectionError}
      />

      <header className="topbar">
        <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
          <Menu size={21} />
        </button>
        <label className="scope-select">
          <Building2 size={17} />
          <select
            value={selectedClientId ?? ""}
            onChange={(event) =>
              updateEndpointQuery({ client: event.target.value || undefined, site: undefined })
            }
            aria-label="Client scope"
          >
            <option value="">All clients</option>
            {navigation?.items.map((client) => (
              <option key={client.id} value={client.id}>
                {client.name}
              </option>
            ))}
          </select>
          <ChevronDown size={15} />
        </label>
        <label className="global-search">
          <Search size={18} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search endpoints, users, or sites…"
            aria-label="Search endpoints, users, or sites"
            onKeyDown={(event) => {
              if (event.key === "Enter") updateEndpointQuery({ search: query });
            }}
          />
          <kbd>⌘ K</kbd>
        </label>
        <div className="topbar-spacer" />
        <div className={`audit-verified ${trustStatusData.chainIntact ? "" : "error-status"}`}>
          {trustStatusData.chainIntact ? <ShieldCheck size={19} /> : <CircleAlert size={19} />}
          <span>{trustStatusData.chainIntact ? "Live data · Verified" : "Audit chain alert"}</span>
          <i />
        </div>
        <button className="notification-button" aria-label="Notifications">
          <Bell size={19} />
          <span>{activeAlertCount}</span>
        </button>
        <div className="profile-block">
          <div>
            <strong>{operator.email}</strong>
            <span>{operatorRoleLabel(operator.role)}</span>
          </div>
          <span className="avatar">{operatorInitials}</span>
          <button className="sign-out" onClick={signOut}>
            Sign out
          </button>
        </div>
      </header>

      <main className="workspace">
        <div className="content-column">
          <section className="page-heading">
            <div>
              <span className="eyebrow">Fleet operations</span>
              <h1>Operations overview</h1>
              <p>Risk and operational posture across your managed endpoints.</p>
              {signOutError ? (
                <p className="sign-out-error" role="alert">
                  {signOutError}
                </p>
              ) : null}
            </div>
            <div className="freshness">
              <span>
                Data as of <strong>{refreshTime}</strong>
              </span>
              <button onClick={refresh}>
                <RefreshCw size={15} />
                <span>Refresh</span>
              </button>
            </div>
          </section>

          <section className="panel attention-panel">
            <header className="panel-header danger-heading">
              <div>
                <AlertTriangle size={20} />
                <h2>
                  {alertsError
                    ? "Attention telemetry unavailable"
                    : `${attentionItemsList.length} endpoint${
                        attentionItemsList.length === 1 ? "" : "s"
                      } need attention`}
                </h2>
              </div>
              {issueFilter !== "all" ? (
                <button onClick={() => setIssueFilter("all")}>Clear filter</button>
              ) : null}
            </header>

            {alertsError ? (
              <div className="empty-state" role="alert">
                <CircleAlert size={24} />
                <strong>Monitoring alerts could not be retrieved</strong>
                <span>Try refreshing the dashboard section.</span>
                <button onClick={refresh}>Retry</button>
              </div>
            ) : attentionItemsList.length === 0 ? (
              <div className="empty-state">
                <CheckCircle2 size={24} />
                <strong>All endpoints operating normally</strong>
                <span>No active monitoring alerts or health warnings detected.</span>
              </div>
            ) : (
              <div className="attention-table">
                <div className="attention-head">
                  <span>Issue</span>
                  <span>Endpoints</span>
                  <span>Latest example</span>
                  <span>First observed</span>
                  <span>Action</span>
                </div>
                {attentionItemsList.map((item) => (
                  <button
                    className={`attention-row ${issueFilter === item.id ? "selected" : ""}`}
                    key={item.id}
                    onClick={() => setIssueFilter(item.id)}
                  >
                    <span className="issue-cell">
                      <i className={item.tone} />
                      <span>
                        <strong>{item.title}</strong>
                        <small>{item.detail}</small>
                      </span>
                    </span>
                    <span className="attention-count">{item.count}</span>
                    <span className="endpoint-example">
                      <Monitor size={17} />
                      <span>
                        <strong>{item.endpoint}</strong>
                        <small>{item.site}</small>
                      </span>
                    </span>
                    <span>{item.observed}</span>
                    <span className="row-action">
                      {item.action}
                      <ChevronRight size={14} />
                    </span>
                  </button>
                ))}
              </div>
            )}
            <Link className="panel-link" href="/alerts">
              View all alerts <ChevronRight size={15} />
            </Link>
          </section>

          <section className="panel fleet-panel">
            <header className="fleet-header">
              <div>
                <span className="eyebrow">Managed estate</span>
                <h2>Fleet status</h2>
              </div>
              <button className="export-button" onClick={exportCsv}>
                <Download size={16} />
                <span>Export CSV</span>
              </button>
              <select
                aria-label="Endpoint status"
                value={endpointStatus ?? ""}
                onChange={(event) =>
                  updateEndpointQuery({ status: event.target.value || undefined })
                }
              >
                <option value="">All statuses</option>
                <option value="online">Online</option>
                <option value="offline">Offline</option>
                <option value="pending">Pending</option>
              </select>
              <select
                aria-label="Endpoint sort order"
                value={endpointSort}
                onChange={(event) => updateEndpointQuery({ sort: event.target.value })}
              >
                <option value="last_seen">Last seen</option>
                <option value="hostname">Hostname</option>
                <option value="status">Status</option>
              </select>
            </header>
            <div className="fleet-summary">
              <div className="total-stat">
                <small>Total endpoints</small>
                <strong>{endpointList?.total ?? 0}</strong>
              </div>
              <div className="summary-stat online">
                <CheckCircle2 size={19} />
                <span>
                  <small>Online</small>
                  <strong>
                    {fleetSummary.onlineCount} <em>{fleetSummary.onlinePercent}%</em>
                  </strong>
                </span>
              </div>
              <div className="summary-stat warning">
                <AlertTriangle size={19} />
                <span>
                  <small>Warnings</small>
                  <strong>
                    {fleetSummary.warningCount} <em>{fleetSummary.warningPercent}%</em>
                  </strong>
                </span>
              </div>
              <div className="summary-stat critical">
                <CircleAlert size={19} />
                <span>
                  <small>Critical</small>
                  <strong>
                    {fleetSummary.criticalCount} <em>{fleetSummary.criticalPercent}%</em>
                  </strong>
                </span>
              </div>
              <div className="summary-stat offline">
                <Circle size={19} />
                <span>
                  <small>Offline</small>
                  <strong>
                    {fleetSummary.offlineCount} <em>{fleetSummary.offlinePercent}%</em>
                  </strong>
                </span>
              </div>
            </div>
            <div className="table-scroll">
              <table className="endpoint-table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Client / Site</th>
                    <th>Status</th>
                    <th>Last seen ↓</th>
                    <th>User</th>
                    <th>CPU</th>
                    <th>Memory</th>
                    <th>Disk</th>
                    <th>
                      <span className="sr-only">Work</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {visibleEndpoints.map((endpoint) => (
                    <tr
                      key={endpoint.id}
                      onClick={() => setSelectedEndpoint(endpoint)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedEndpoint(endpoint);
                        }
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <td>
                        <span className="device-cell">
                          <Laptop size={19} />
                          <span>
                            <strong>{endpoint.name}</strong>
                            <small>{endpoint.os}</small>
                          </span>
                        </span>
                      </td>
                      <td>
                        <span className="stacked-cell">
                          <strong>
                            {endpoint.client} · {endpoint.site}
                          </strong>
                          <small>{endpoint.group}</small>
                        </span>
                      </td>
                      <td>
                        <span className={`status-cell ${endpoint.status}`}>
                          <StatusMark status={endpoint.status} />
                          {statusLabels[endpoint.status]}
                        </span>
                      </td>
                      <td>
                        <span className="stacked-cell">
                          <strong>{endpoint.lastSeen}</strong>
                        </span>
                      </td>
                      <td>
                        <code>{endpoint.user}</code>
                      </td>
                      <td>
                        <Meter value={endpoint.cpu} />
                      </td>
                      <td>
                        <Meter value={endpoint.memory} />
                      </td>
                      <td>
                        <Meter value={endpoint.disk} />
                      </td>
                      <td>
                        <Link
                          className="work-button"
                          href={`/endpoints/${encodeURIComponent(endpoint.id)}`}
                          onClick={(event) => event.stopPropagation()}
                          aria-label={`Open ${endpoint.name}`}
                        >
                          <WorkIcon work={endpoint.work} />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {endpointError ? (
                <div className="empty-state" role="alert">
                  <CircleAlert size={24} />
                  <strong>Endpoint inventory is unavailable</strong>
                  <span>Try refreshing the dashboard section.</span>
                  <button onClick={refresh}>Try again</button>
                </div>
              ) : visibleEndpoints.length === 0 ? (
                <div className="empty-state">
                  <Search size={24} />
                  <strong>No endpoints found</strong>
                  <span>Try another search or filter.</span>
                </div>
              ) : null}
            </div>
            <footer className="table-footer">
              <span>
                {endpointError
                  ? "Endpoint inventory unavailable"
                  : `Showing ${visibleEndpoints.length} of ${endpointList?.total ?? 0} endpoints`}
              </span>
              <div className="pagination">
                <button
                  disabled={(endpointList?.page ?? 1) <= 1}
                  onClick={() => updateEndpointQuery({ page: String((endpointList?.page ?? 1) - 1) })}
                >
                  <ChevronLeft size={15} />
                </button>
                <button className="active">{endpointList?.page ?? 1}</button>
                <button
                  disabled={!endpointList || endpointList.page * endpointList.page_size >= endpointList.total}
                  onClick={() => updateEndpointQuery({ page: String((endpointList?.page ?? 1) + 1) })}
                >
                  <ChevronRight size={15} />
                </button>
              </div>
              <button className="page-size">
                25 / page <ChevronDown size={14} />
              </button>
            </footer>
          </section>
        </div>
        <TrustRail
          error={trustError || auditError}
          signedActions={signedActionsList}
          trustStatus={trustStatusData}
        />
      </main>

      <EndpointDrawer endpoint={selectedEndpoint} onClose={() => setSelectedEndpoint(null)} />
    </div>
  );
}
