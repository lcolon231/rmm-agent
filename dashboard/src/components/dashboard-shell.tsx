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
  FlaskConical,
  KeyRound,
  Laptop,
  Menu,
  Monitor,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  TerminalSquare,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";

import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import {
  attentionItems,
  clients,
  endpoints,
  signedActions,
  type Endpoint,
  type EndpointStatus,
} from "@/data/dashboard";

const navItems = [
  { label: "Overview", icon: Activity, active: true },
  { label: "Endpoints", icon: Monitor, count: null },
  { label: "Alerts", icon: AlertTriangle, count: 7 },
  { label: "Automation", icon: Bot, count: null },
  { label: "Audit", icon: ShieldCheck, count: null },
  { label: "Administration", icon: Settings, count: null },
];

const statusLabels: Record<EndpointStatus, string> = {
  online: "Online",
  warning: "Warning",
  critical: "Critical",
  offline: "Offline",
};

function NodeLinkMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

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

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <>
      <button
        className={`sidebar-scrim ${open ? "is-open" : ""}`}
        onClick={onClose}
        aria-label="Close navigation"
      />
      <aside className={`sidebar ${open ? "is-open" : ""}`}>
        <div className="brand-row">
          <NodeLinkMark />
          <strong>NodeLink</strong>
          <button className="sidebar-close" onClick={onClose} aria-label="Close navigation">
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-section client-section">
          <div className="sidebar-label">
            <span>Clients</span>
            <button aria-label="Add client">+</button>
          </div>
          {clients.map((client, clientIndex) => (
            <div className="client-tree" key={client.name}>
              <button className="client-name">
                <span className="client-avatar">{client.short}</span>
                <span>{client.name}</span>
                <ChevronDown size={15} />
              </button>
              <div className="site-list">
                {client.sites.map((site, siteIndex) => (
                  <button
                    className={clientIndex === 0 && siteIndex === 0 ? "active" : ""}
                    key={site}
                  >
                    <span>{site}</span>
                    {clientIndex === 0 && siteIndex === 0 && <span className="site-count">84</span>}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        <nav className="sidebar-section main-nav" aria-label="Primary navigation">
          <div className="sidebar-label">Navigation</div>
          {navItems.map(({ label, icon: Icon, count, active }) => (
            <button className={active ? "active" : ""} key={label}>
              <Icon size={19} />
              <span>{label}</span>
              {count ? <span className="nav-count">{count}</span> : null}
              {label === "Administration" ? <ChevronRight className="nav-chevron" size={15} /> : null}
            </button>
          ))}
        </nav>

        <button className="collapse-button">
          <ChevronLeft size={18} />
          <span>Collapse</span>
        </button>
      </aside>
    </>
  );
}

function TrustRail() {
  return (
    <aside className="trust-rail">
      <header className="trust-title">
        <ShieldCheck size={27} />
        <div>
          <span>Trust status</span>
          <small>Fixture data · no live verification</small>
        </div>
      </header>

      <div className="trust-facts">
        <div className="trust-fact">
          <span className="fact-icon"><Shield size={17} /></span>
          <div><small>Audit chain</small><strong className="neutral">Preview only</strong></div>
        </div>
        <div className="trust-fact">
          <span className="fact-icon"><Clock3 size={17} /></span>
          <div><small>Last anchor</small><strong className="neutral">2h ago</strong><em>May 16, 2026 · 8:12 AM</em></div>
        </div>
        <div className="trust-fact">
          <span className="fact-icon"><KeyRound size={17} /></span>
          <div><small>Signing key</small><strong className="neutral">Active</strong><em>prod-2026-02 · 7F3A…C9D1</em></div>
        </div>
      </div>

      <div className="rail-divider" />
      <h2>Recent actions <span>(signed)</span></h2>
      <div className="custody-timeline">
        {signedActions.map((action) => (
          <article key={`${action.time}-${action.title}`}>
            <span className={`timeline-node ${action.kind}`}>
              {action.kind === "anchor" ? <Shield size={14} /> : <Check size={14} />}
            </span>
            <time>{action.time}</time>
            <strong>{action.title}</strong>
            <span>{action.target}</span>
            <small>by {action.actor}</small>
            <code>Sig: {action.signature}</code>
          </article>
        ))}
      </div>
      <div className="chain-state"><FlaskConical size={16} /> Illustrative chain timeline</div>
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
              <div className="device-icon"><Server size={24} /></div>
              <div>
                <small>{endpoint.client} · {endpoint.site}</small>
                <h2>{endpoint.name}</h2>
                <span>{endpoint.os}</span>
              </div>
              <button onClick={onClose} aria-label="Close endpoint details"><X size={20} /></button>
            </div>
            <div className={`status-chip ${endpoint.status}`}>
              <StatusMark status={endpoint.status} /> {statusLabels[endpoint.status]}
            </div>
            <div className="drawer-grid">
              <div><small>Last seen</small><strong>{endpoint.lastSeen}</strong></div>
              <div><small>Logged-in user</small><strong>{endpoint.user}</strong></div>
              <div><small>Group</small><strong>{endpoint.group}</strong></div>
              <div><small>Trust</small><strong className="verified-text"><ShieldCheck size={15} /> Verified</strong></div>
            </div>
            <h3>Current telemetry</h3>
            <div className="drawer-telemetry">
              <div><span>CPU</span><Meter value={endpoint.cpu} /></div>
              <div><span>Memory</span><Meter value={endpoint.memory} /></div>
              <div><span>System disk</span><Meter value={endpoint.disk} /></div>
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
              <button className="primary-action"><Command size={17} /> Review action</button>
              <button className="secondary-action">Open endpoint</button>
            </div>
          </>
        ) : null}
      </aside>
    </>
  );
}

type DashboardShellProps = {
  operator: DashboardOperator;
};

export function DashboardShell({ operator }: DashboardShellProps) {
  const [scope, setScope] = useState("All clients");
  const [query, setQuery] = useState("");
  const [issueFilter, setIssueFilter] = useState<Endpoint["issue"] | "all">("all");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);
  const [refreshTime, setRefreshTime] = useState("10:25 AM");
  const [signOutError, setSignOutError] = useState("");

  const visibleEndpoints = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return endpoints.filter((endpoint) => {
      const matchesScope = scope === "All clients" || endpoint.client === scope;
      const matchesIssue = issueFilter === "all" || endpoint.issue === issueFilter;
      const matchesQuery =
        normalizedQuery.length === 0 ||
        [endpoint.name, endpoint.client, endpoint.site, endpoint.user, endpoint.os]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      return matchesScope && matchesIssue && matchesQuery;
    });
  }, [issueFilter, query, scope]);

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
    const csv = rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "nodelink-fleet.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const refresh = () => {
    setRefreshTime(new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(new Date()));
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

  const operatorInitials = operator.email
    .split("@")[0]
    .split(/[._-]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="app-shell">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <header className="topbar">
        <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
          <Menu size={21} />
        </button>
        <label className="scope-select">
          <Building2 size={17} />
          <select value={scope} onChange={(event) => setScope(event.target.value)} aria-label="Client scope">
            <option>All clients</option>
            {clients.map((client) => <option key={client.name}>{client.name}</option>)}
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
          />
          <kbd>⌘ K</kbd>
        </label>
        <div className="topbar-spacer" />
        <div className="audit-verified preview-status"><FlaskConical size={19} /><span>Preview data</span><i /></div>
        <button className="notification-button" aria-label="Notifications"><Bell size={19} /><span>5</span></button>
        <div className="profile-block">
          <div><strong>{operator.email}</strong><span>{operator.role}</span></div>
          <span className="avatar">{operatorInitials}</span>
          <button className="sign-out" onClick={signOut}>Sign out</button>
        </div>
      </header>

      <main className="workspace">
        <div className="content-column">
          <section className="page-heading">
            <div>
              <span className="eyebrow">Fleet operations</span>
              <h1>Operations overview</h1>
              <p>Risk and operational posture across your managed endpoints.</p>
              <p className="preview-banner">Preview data only · Live endpoint and audit data require secure sign-in.</p>
              {signOutError ? <p className="sign-out-error" role="alert">{signOutError}</p> : null}
            </div>
            <div className="freshness">
              <span>Data as of <strong>{refreshTime}</strong></span>
              <button onClick={refresh}><RefreshCw size={15} /><span>Refresh</span></button>
            </div>
          </section>

          <section className="panel attention-panel">
            <header className="panel-header danger-heading">
              <div><AlertTriangle size={20} /><h2>7 endpoints need attention</h2></div>
              {issueFilter !== "all" ? <button onClick={() => setIssueFilter("all")}>Clear filter</button> : null}
            </header>
            <div className="attention-table">
              <div className="attention-head">
                <span>Issue</span><span>Endpoints</span><span>Latest example</span><span>First observed</span><span>Action</span>
              </div>
              {attentionItems.map((item) => (
                <button
                  className={`attention-row ${issueFilter === item.id ? "selected" : ""}`}
                  key={item.id}
                  onClick={() => setIssueFilter(item.id)}
                >
                  <span className="issue-cell"><i className={item.tone} /><span><strong>{item.title}</strong><small>{item.detail}</small></span></span>
                  <span className="attention-count">{item.count}</span>
                  <span className="endpoint-example"><Monitor size={17} /><span><strong>{item.endpoint}</strong><small>{item.site}</small></span></span>
                  <span>{item.observed}</span>
                  <span className="row-action">{item.action}<ChevronRight size={14} /></span>
                </button>
              ))}
            </div>
            <button className="panel-link">View all alerts <ChevronRight size={15} /></button>
          </section>

          <section className="panel fleet-panel">
            <header className="fleet-header">
              <div>
                <span className="eyebrow">Managed estate</span>
                <h2>Fleet status</h2>
              </div>
              <button className="export-button" onClick={exportCsv}><Download size={16} /><span>Export CSV</span></button>
            </header>
            <div className="fleet-summary">
              <div className="total-stat"><small>Total endpoints</small><strong>156</strong></div>
              <div className="summary-stat online"><CheckCircle2 size={19} /><span><small>Online</small><strong>132 <em>84.6%</em></strong></span></div>
              <div className="summary-stat warning"><AlertTriangle size={19} /><span><small>Warnings</small><strong>12 <em>7.7%</em></strong></span></div>
              <div className="summary-stat critical"><CircleAlert size={19} /><span><small>Critical</small><strong>7 <em>4.5%</em></strong></span></div>
              <div className="summary-stat offline"><Circle size={19} /><span><small>Offline</small><strong>5 <em>3.2%</em></strong></span></div>
            </div>
            <div className="table-scroll">
              <table className="endpoint-table">
                <thead>
                  <tr>
                    <th>Endpoint</th><th>Client / Site</th><th>Status</th><th>Last seen ↓</th><th>User</th><th>CPU</th><th>Memory</th><th>Disk</th><th><span className="sr-only">Work</span></th>
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
                      <td><span className="device-cell"><Laptop size={19} /><span><strong>{endpoint.name}</strong><small>{endpoint.os}</small></span></span></td>
                      <td><span className="stacked-cell"><strong>{endpoint.client} · {endpoint.site}</strong><small>{endpoint.group}</small></span></td>
                      <td><span className={`status-cell ${endpoint.status}`}><StatusMark status={endpoint.status} />{statusLabels[endpoint.status]}</span></td>
                      <td><span className="stacked-cell"><strong>{endpoint.lastSeen}</strong><small>{endpoint.status === "offline" ? "May 15, 8:47 AM" : "May 16, 10:24 AM"}</small></span></td>
                      <td><code>{endpoint.user}</code></td>
                      <td><Meter value={endpoint.cpu} /></td>
                      <td><Meter value={endpoint.memory} /></td>
                      <td><Meter value={endpoint.disk} /></td>
                      <td><button className="work-button" onClick={(event) => { event.stopPropagation(); setSelectedEndpoint(endpoint); }} aria-label={`Open ${endpoint.name}`}><WorkIcon work={endpoint.work} /></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visibleEndpoints.length === 0 ? (
                <div className="empty-state"><Search size={24} /><strong>No endpoints found</strong><span>Try another search or clear the active issue filter.</span></div>
              ) : null}
            </div>
            <footer className="table-footer">
              <span>Showing {visibleEndpoints.length} of 156 endpoints</span>
              <div className="pagination"><button disabled><ChevronLeft size={15} /></button><button className="active">1</button><button>2</button><button>3</button><span>…</span><button>7</button><button><ChevronRight size={15} /></button></div>
              <button className="page-size">25 / page <ChevronDown size={14} /></button>
            </footer>
          </section>
        </div>
        <TrustRail />
      </main>

      <EndpointDrawer endpoint={selectedEndpoint} onClose={() => setSelectedEndpoint(null)} />
    </div>
  );
}
