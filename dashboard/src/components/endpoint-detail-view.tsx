// SPDX-License-Identifier: AGPL-3.0-only

import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  Circle,
  Clock3,
  Cpu,
  Database,
  HardDrive,
  MemoryStick,
  ShieldCheck,
  TerminalSquare,
  TriangleAlert,
  UserRound,
} from "lucide-react";
import Link from "next/link";

import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData, EndpointTelemetrySample } from "@/lib/endpoint-detail";
import {
  buildMetricPath,
  formatEndpointDateTime,
  formatEndpointMetric,
  formatEndpointUptime,
  type MetricKey,
} from "@/lib/endpoint-detail-core";

const metricDefinitions: Array<{ key: MetricKey; label: string; shortLabel: string; tone: string }> = [
  { key: "cpu_percent", label: "Processor utilization", shortLabel: "CPU", tone: "cyan" },
  { key: "mem_percent", label: "Memory utilization", shortLabel: "Memory", tone: "violet" },
  { key: "disk_percent", label: "System disk utilization", shortLabel: "Disk", tone: "amber" },
];

function statusLabel(status: EndpointDetailData["status"]): string {
  if (status === "online") return "Online";
  if (status === "offline") return "Offline";
  return "Pending first heartbeat";
}

function NodeLinkMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

function MetricReading({ definition, sample }: { definition: (typeof metricDefinitions)[number]; sample: EndpointTelemetrySample | null }) {
  const value = sample?.[definition.key] ?? null;
  const Icon = definition.key === "cpu_percent" ? Cpu : definition.key === "mem_percent" ? MemoryStick : HardDrive;
  return (
    <article className={`detail-metric ${definition.tone}`}>
      <div className="detail-metric-icon"><Icon size={18} /></div>
      <span>{definition.shortLabel}</span>
      <strong>{formatEndpointMetric(value)}</strong>
      <small>{value === null ? "Unavailable or unsupported" : definition.label}</small>
    </article>
  );
}

function TelemetryTrack({ definition, samples }: { definition: (typeof metricDefinitions)[number]; samples: EndpointTelemetrySample[] }) {
  const values = samples.map((sample) => sample[definition.key]).filter((value): value is number => value !== null);
  const latest = values.at(-1) ?? null;
  const minimum = values.length ? Math.min(...values) : null;
  const maximum = values.length ? Math.max(...values) : null;
  const width = 760;
  const height = 146;
  const path = buildMetricPath(samples, definition.key, width, height);

  return (
    <figure className={`telemetry-track ${definition.tone}`}>
      <figcaption>
        <div><span>{definition.shortLabel}</span><strong>{formatEndpointMetric(latest)}</strong></div>
        <p>{definition.label}</p>
        <dl>
          <div><dt>Low</dt><dd>{formatEndpointMetric(minimum)}</dd></div>
          <div><dt>High</dt><dd>{formatEndpointMetric(maximum)}</dd></div>
        </dl>
      </figcaption>
      <div className="telemetry-plot">
        {path ? (
          <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${definition.label} over the selected history window`} preserveAspectRatio="none">
            <title>{definition.label}</title>
            <desc>{samples.length} samples. Latest {formatEndpointMetric(latest)}, low {formatEndpointMetric(minimum)}, high {formatEndpointMetric(maximum)}.</desc>
            {[25, 50, 75].map((lineValue) => (
              <line key={lineValue} x1="18" x2={width - 18} y1={14 + ((100 - lineValue) / 100) * (height - 28)} y2={14 + ((100 - lineValue) / 100) * (height - 28)} />
            ))}
            <path d={path} />
          </svg>
        ) : (
          <div className="telemetry-unavailable">No supported samples in this window</div>
        )}
      </div>
    </figure>
  );
}

function TelemetryValues({ samples }: { samples: EndpointTelemetrySample[] }) {
  return (
    <details className="telemetry-values">
      <summary>View exact telemetry values</summary>
      <div className="telemetry-values-scroll">
        <table>
          <thead><tr><th>Timestamp</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Uptime</th><th>Signed-in user</th></tr></thead>
          <tbody>
            {samples.map((sample) => (
              <tr key={sample.ts}>
                <td>{formatEndpointDateTime(sample.ts)}</td>
                <td>{formatEndpointMetric(sample.cpu_percent)}</td>
                <td>{formatEndpointMetric(sample.mem_percent)}</td>
                <td>{formatEndpointMetric(sample.disk_percent)}</td>
                <td>{formatEndpointUptime(sample.uptime_seconds)}</td>
                <td>{sample.logged_in_user ?? "Not reported"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export function EndpointDetailView({ endpoint, operator }: { endpoint: EndpointDetailData; operator: DashboardOperator }) {
  const sample = endpoint.current_telemetry;
  const rangeOptions = [6, 24, 72, 168];
  const freshnessLabel = endpoint.telemetry_freshness === "current" ? "Current" : endpoint.telemetry_freshness === "stale" ? "Stale" : "Unavailable";

  return (
    <main className="endpoint-detail-page">
      <header className="detail-topbar">
        <Link className="detail-brand" href="/"><NodeLinkMark /><strong>NodeLink</strong></Link>
        <span className="detail-context">Endpoint diagnostics</span>
        <div className="detail-operator"><span>{operator.email}</span><small>{operator.role}</small></div>
      </header>

      <div className="detail-workspace">
        <nav className="detail-breadcrumbs" aria-label="Breadcrumb">
          <Link href="/"><ArrowLeft size={15} /> Fleet</Link>
          <span>/</span><span>{endpoint.client_name}</span><span>/</span><span>{endpoint.site_name}</span>
        </nav>

        <section className="detail-identity" aria-labelledby="endpoint-title">
          <div className="detail-device-mark"><Database size={28} /></div>
          <div className="detail-title">
            <span className="eyebrow">Managed endpoint</span>
            <h1 id="endpoint-title">{endpoint.hostname}</h1>
            <p>{[endpoint.os, endpoint.os_version].filter(Boolean).join(" ")} · Agent {endpoint.agent_version || "version unavailable"}</p>
          </div>
          <div className="detail-state-stack">
            <span className={`detail-status ${endpoint.status}`}>
              {endpoint.status === "online" ? <CheckCircle2 size={16} /> : <Circle size={16} />}{statusLabel(endpoint.status)}
            </span>
            <span className={`detail-freshness ${endpoint.telemetry_freshness}`}><Activity size={15} /> Telemetry {freshnessLabel.toLowerCase()}</span>
            <Link className="detail-console-link" href={`/endpoints/${encodeURIComponent(endpoint.id)}/commands`}>
              <TerminalSquare size={15} /> Command console
            </Link>
          </div>
        </section>

        {endpoint.telemetry_freshness !== "current" ? (
          <section className={`detail-notice ${endpoint.telemetry_freshness}`} role="status">
            <TriangleAlert size={19} />
            <div>
              <strong>{endpoint.telemetry_freshness === "stale" ? "Telemetry is older than expected" : "No telemetry has been reported"}</strong>
              <span>{endpoint.telemetry_freshness === "stale" ? `The most recent sample exceeded the ${Math.round(endpoint.stale_after_seconds / 60)} minute freshness window.` : "Identity is available, but metric and uptime readings cannot be shown yet."}</span>
            </div>
          </section>
        ) : null}

        <section className="detail-overview" aria-label="Endpoint overview">
          <article><Clock3 size={17} /><span>Last seen</span><strong>{formatEndpointDateTime(endpoint.last_seen_at)}</strong></article>
          <article><UserRound size={17} /><span>Signed-in user</span><strong>{sample?.logged_in_user ?? "Not reported"}</strong></article>
          <article><Activity size={17} /><span>Uptime</span><strong>{formatEndpointUptime(sample?.uptime_seconds ?? null)}</strong></article>
          <article><ShieldCheck size={17} /><span>Trust state</span><strong>{endpoint.trust_state}</strong></article>
        </section>

        <section className="detail-current" aria-labelledby="current-telemetry-title">
          <header>
            <div><span className="eyebrow">Latest heartbeat</span><h2 id="current-telemetry-title">Current telemetry</h2></div>
            <time>{sample ? formatEndpointDateTime(sample.ts) : "Awaiting first sample"}</time>
          </header>
          <div className="detail-metric-grid">{metricDefinitions.map((definition) => <MetricReading definition={definition} key={definition.key} sample={sample} />)}</div>
        </section>

        <section className="telemetry-tape" aria-labelledby="telemetry-history-title">
          <header className="telemetry-tape-header">
            <div><span className="eyebrow">Heartbeat history</span><h2 id="telemetry-history-title">Telemetry tape</h2><p>CPU, memory, and disk share the same ordered sample window.</p></div>
            <nav aria-label="Telemetry history range">
              {rangeOptions.map((hours) => <Link className={endpoint.history_hours === hours ? "active" : ""} href={`/endpoints/${encodeURIComponent(endpoint.id)}?hours=${hours}`} key={hours}>{hours < 24 ? `${hours}h` : `${hours / 24}d`}</Link>)}
            </nav>
          </header>
          {endpoint.telemetry.length ? (
            <>
              <div className="telemetry-time-axis"><span>{formatEndpointDateTime(endpoint.telemetry[0].ts)}</span><span>{endpoint.telemetry.length} samples</span><span>{formatEndpointDateTime(endpoint.telemetry.at(-1)?.ts ?? null)}</span></div>
              <div className="telemetry-tracks">{metricDefinitions.map((definition) => <TelemetryTrack definition={definition} key={definition.key} samples={endpoint.telemetry} />)}</div>
              {endpoint.history_truncated ? <p className="telemetry-cap-note">This view reached the {endpoint.history_limit}-sample safety limit. Choose a shorter range for full resolution.</p> : null}
              <TelemetryValues samples={endpoint.telemetry} />
            </>
          ) : (
            <div className="detail-empty"><Activity size={24} /><strong>No telemetry in this window</strong><span>Choose a longer range or wait for the endpoint’s next heartbeat.</span></div>
          )}
        </section>

        <footer className="detail-footer"><span>Endpoint ID <code>{endpoint.id}</code></span><span>Enrolled {formatEndpointDateTime(endpoint.enrolled_at)}</span></footer>
      </div>
    </main>
  );
}
