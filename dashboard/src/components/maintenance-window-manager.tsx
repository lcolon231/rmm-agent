// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowRight,
  CalendarClock,
  CalendarPlus,
  LoaderCircle,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";

import {
  browserTimeZone,
  clockSnapshot,
  readClock,
  serverTimeZone,
  subscribeToClock,
  subscribeToTimeZone,
} from "@/lib/dashboard-clock";

import {
  MAX_WINDOW_NAME_LENGTH,
  describeRecurrence,
  describeWindowState,
  formatDurationSeconds,
  formatWallTimeInput,
  formatWindowScope,
  formatWindowTarget,
  validateMaintenanceWindowForm,
  windowStateAt,
  zonedWallTimeToUtc,
  type MaintenanceWindow,
} from "@/lib/maintenance-windows-core";
import { formatMonitoringTimestamp, type MonitoringScope } from "@/lib/monitoring-core";

export type ScopeTargetOption = { id: string; label: string; hint: string };

export type MaintenanceWindowPrefill = {
  scope: MonitoringScope | null;
  scopeId: string | null;
  name: string | null;
  coverSeconds: number | null;
  returnPath: string | null;
};

const DURATION_PRESETS = [
  { seconds: 1800, label: "30 minutes" },
  { seconds: 3600, label: "1 hour" },
  { seconds: 4 * 3600, label: "4 hours" },
  { seconds: 8 * 3600, label: "8 hours" },
];

const STATE_ORDER = { active: 0, between_occurrences: 1, upcoming: 2, expired: 3 } as const;

export function MaintenanceWindowManager({
  initialWindows,
  clients,
  sites,
  endpoints,
  canManage,
  serverNowMs,
  prefill,
}: {
  initialWindows: MaintenanceWindow[];
  clients: ScopeTargetOption[];
  sites: ScopeTargetOption[];
  endpoints: ScopeTargetOption[];
  canManage: boolean;
  serverNowMs: number;
  prefill: MaintenanceWindowPrefill;
}) {
  const router = useRouter();
  const [windows, setWindows] = useState(initialWindows);
  // The server's instant during hydration, the browser's coarse clock after it.
  const nowMs = useSyncExternalStore(subscribeToClock, clockSnapshot, () => serverNowMs);
  const operatorZone = useSyncExternalStore(subscribeToTimeZone, browserTimeZone, serverTimeZone);
  const zoneOptions = operatorZone === "UTC" ? ["UTC"] : ["UTC", operatorZone];
  const [timeZone, setTimeZone] = useState("UTC");
  const [name, setName] = useState(prefill.name ?? "");
  const [scope, setScope] = useState<MonitoringScope>(prefill.scope ?? "agent");
  const [scopeId, setScopeId] = useState(prefill.scopeId ?? "");
  // Seeded from the render instant in UTC, which both sides agree on. The
  // presets below re-seed from the operator's own clock on demand.
  const [startsAt, setStartsAt] = useState(() => formatWallTimeInput(serverNowMs, "UTC"));
  const [endsAt, setEndsAt] = useState(() => formatWallTimeInput(
    serverNowMs + Math.max((prefill.coverSeconds ?? 0) + 900, 3600) * 1000,
    "UTC",
  ));
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<MaintenanceWindow | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [confirmName, setConfirmName] = useState("");

  const targetOptions = scope === "client" ? clients : scope === "site" ? sites : endpoints;
  const targetNames = useMemo(() => {
    const names = new Map<string, string>();
    for (const option of [...clients, ...sites, ...endpoints]) names.set(option.id, option.label);
    return names;
  }, [clients, sites, endpoints]);

  const ordered = useMemo(() => {
    return [...windows]
      .map((window) => ({ window, state: windowStateAt(window, nowMs) }))
      .sort((a, b) => {
        if (a.state !== b.state) return STATE_ORDER[a.state] - STATE_ORDER[b.state];
        return Date.parse(a.window.starts_at) - Date.parse(b.window.starts_at);
      });
  }, [windows, nowMs]);

  const openCount = ordered.filter((item) => item.state === "active").length;
  const upcomingCount = ordered.filter((item) => item.state === "upcoming").length;

  function applyDuration(seconds: number) {
    const now = readClock();
    setStartsAt(formatWallTimeInput(now, timeZone));
    setEndsAt(formatWallTimeInput(now + seconds * 1000, timeZone));
  }

  function changeZone(nextZone: string) {
    // Re-render the same instants in the newly selected zone so switching the
    // zone never silently moves the span the operator already chose.
    const startsAtMs = zonedWallTimeToUtc(startsAt, timeZone);
    const endsAtMs = zonedWallTimeToUtc(endsAt, timeZone);
    setTimeZone(nextZone);
    if (startsAtMs !== null) setStartsAt(formatWallTimeInput(startsAtMs, nextZone));
    if (endsAtMs !== null) setEndsAt(formatWallTimeInput(endsAtMs, nextZone));
  }

  const preview = useMemo(() => {
    const result = validateMaintenanceWindowForm(
      { name, scope, scopeId, startsAt, endsAt, timeZone, requiredCoverageSeconds: prefill.coverSeconds },
      nowMs,
    );
    return result;
  }, [name, scope, scopeId, startsAt, endsAt, timeZone, prefill.coverSeconds, nowMs]);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setCreated(null);
    const validated = validateMaintenanceWindowForm(
      { name, scope, scopeId, startsAt, endsAt, timeZone, requiredCoverageSeconds: prefill.coverSeconds },
      readClock(),
    );
    if (!validated.ok) {
      setError(validated.error);
      return;
    }
    setBusy("create");
    try {
      const response = await fetch("/api/maintenance-windows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validated.request),
      });
      const body = await response.json().catch(() => null) as
        | { window?: MaintenanceWindow; error?: string }
        | null;
      if (!response.ok || !body?.window) {
        setError(body?.error ?? "The maintenance window could not be created.");
      } else {
        setWindows((current) => [...current, body.window as MaintenanceWindow]);
        setCreated(body.window);
        router.refresh();
      }
    } catch {
      setError("The maintenance window could not be created.");
    }
    setBusy(null);
  }

  async function endWindow(window: MaintenanceWindow) {
    setError("");
    setBusy(window.id);
    try {
      const response = await fetch(`/api/maintenance-windows/${encodeURIComponent(window.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm_name: confirmName }),
      });
      const body = await response.json().catch(() => null) as { error?: string } | null;
      if (!response.ok) {
        setError(body?.error ?? "The maintenance window could not be ended.");
      } else {
        setWindows((current) => current.filter((item) => item.id !== window.id));
        if (created?.id === window.id) setCreated(null);
        setConfirming(null);
        setConfirmName("");
        router.refresh();
      }
    } catch {
      setError("The maintenance window could not be ended.");
    }
    setBusy(null);
  }

  return (
    <>
      {prefill.coverSeconds ? (
        <section className="maintenance-power-callout" role="note">
          <TriangleAlert aria-hidden="true" size={19} />
          <div>
            <strong>A power action is waiting on this window</strong>
            <span>
              The management service refused the prepared restart or shutdown because no window
              covers this endpoint. Create one that is open now and stays open for at least{" "}
              {formatDurationSeconds(prefill.coverSeconds)} — the delay you chose — then return to
              the console and confirm the dispatch again.
            </span>
          </div>
        </section>
      ) : null}

      <section className="monitoring-summary-grid maintenance-summary-grid">
        <section><span>Open now</span><strong>{openCount}</strong></section>
        <section><span>Upcoming</span><strong>{upcomingCount}</strong></section>
        <section><span>Total</span><strong>{windows.length}</strong></section>
        <section><span>Evaluated</span><strong>{formatMonitoringTimestamp(new Date(nowMs).toISOString())}</strong></section>
      </section>

      {canManage ? (
        <section className="enrollment-panel maintenance-create-panel">
          <header>
            <div>
              <span>New window</span>
              <h2>Open a maintenance window</h2>
              <small>Absolute span. Restart and shutdown are authorized only while a covering window is open.</small>
            </div>
            <CalendarPlus aria-hidden="true" size={19} />
          </header>
          <form onSubmit={create}>
            <label>
              <span>Name</span>
              <input
                maxLength={MAX_WINDOW_NAME_LENGTH}
                onChange={(event) => setName(event.target.value)}
                placeholder="KB5120708 reboot — approved change 4821"
                required
                value={name}
              />
            </label>
            <label>
              <span>Scope</span>
              <select
                onChange={(event) => {
                  setScope(event.target.value as MonitoringScope);
                  setScopeId("");
                }}
                value={scope}
              >
                <option value="agent">Endpoint</option>
                <option value="site">Site</option>
                <option value="client">Client</option>
                <option value="global">Global</option>
              </select>
            </label>
            <label>
              <span>{scope === "global" ? "Coverage" : formatWindowScope(scope)}</span>
              {scope === "global" ? (
                <input disabled readOnly value="Every managed endpoint" />
              ) : (
                <select onChange={(event) => setScopeId(event.target.value)} required value={scopeId}>
                  <option value="">Choose a target…</option>
                  {targetOptions.some((option) => option.id === scopeId) || !scopeId ? null : (
                    <option value={scopeId}>{scopeId} (from the command console)</option>
                  )}
                  {targetOptions.map((option) => (
                    <option key={option.id} value={option.id}>{option.label} — {option.hint}</option>
                  ))}
                </select>
              )}
            </label>
            <label>
              <span>Time zone</span>
              <select onChange={(event) => changeZone(event.target.value)} value={timeZone}>
                {zoneOptions.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
              </select>
            </label>
            <label>
              <span>Starts</span>
              <input
                onChange={(event) => setStartsAt(event.target.value)}
                required
                step={60}
                type="datetime-local"
                value={startsAt}
              />
            </label>
            <label>
              <span>Ends</span>
              <input
                onChange={(event) => setEndsAt(event.target.value)}
                required
                step={60}
                type="datetime-local"
                value={endsAt}
              />
            </label>
            <fieldset className="maintenance-presets">
              <legend>Open now for</legend>
              {DURATION_PRESETS.map((preset) => (
                <button key={preset.seconds} onClick={() => applyDuration(preset.seconds)} type="button">
                  {preset.label}
                </button>
              ))}
            </fieldset>
            <p className="maintenance-preview" role="status">
              {preview.ok ? (
                <>
                  <ShieldCheck aria-hidden="true" size={14} />
                  Covers {formatMonitoringTimestamp(new Date(preview.startsAtMs).toISOString())} →{" "}
                  {formatMonitoringTimestamp(new Date(preview.endsAtMs).toISOString())} (
                  {formatDurationSeconds(Math.round((preview.endsAtMs - preview.startsAtMs) / 1000))}).
                </>
              ) : (
                <>
                  <TriangleAlert aria-hidden="true" size={14} />
                  {preview.error}
                </>
              )}
            </p>
            <button disabled={busy === "create" || !preview.ok} type="submit">
              {busy === "create" ? <LoaderCircle className="spin" size={15} /> : <CalendarClock size={15} />}
              Create window
            </button>
          </form>
        </section>
      ) : (
        <p className="alert-readonly-note" role="status">
          Your role can review maintenance windows. Creating or ending one requires the operator role.
        </p>
      )}

      {created ? (
        <section className="maintenance-created" role="status">
          <ShieldCheck aria-hidden="true" size={19} />
          <div>
            <strong>{created.name} is open</strong>
            <span>
              It closes at {formatMonitoringTimestamp(created.ends_at)}. The management service will
              re-check coverage when the command is signed.
            </span>
          </div>
          {prefill.returnPath ? (
            <Link className="maintenance-return" href={prefill.returnPath}>
              Return to the command console <ArrowRight aria-hidden="true" size={14} />
            </Link>
          ) : null}
        </section>
      ) : null}

      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Window register</span>
            <h2>{windows.length === 1 ? "1 maintenance window" : `${windows.length} maintenance windows`}</h2>
            <small>Creation and deletion are recorded in the tamper-evident audit log.</small>
          </div>
          <CalendarClock aria-hidden="true" size={19} />
        </header>
        {ordered.length === 0 ? (
          <div className="enrollment-empty">
            <CalendarClock size={24} />
            <h3>No maintenance windows</h3>
            <p>Alert suppression and power actions both stay closed until a window covers the endpoint.</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Window</th>
                  <th>State</th>
                  <th>Scope</th>
                  <th>Opens (UTC)</th>
                  <th>Closes (UTC)</th>
                  <th>Pattern</th>
                  <th>Created by</th>
                  {canManage ? <th>Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {ordered.map(({ window, state }) => (
                  <tr key={window.id}>
                    <td><strong>{window.name}</strong><code>{window.id}</code></td>
                    <td><span className={`maintenance-state-chip ${state}`}>{describeWindowState(state)}</span></td>
                    <td>
                      <strong>{formatWindowScope(window.scope)}</strong>
                      <code>{formatWindowTarget(window, targetNames)}</code>
                    </td>
                    <td>{formatMonitoringTimestamp(window.starts_at)}</td>
                    <td>
                      {formatMonitoringTimestamp(window.ends_at)}
                      {state === "active" ? (
                        <small>
                          {formatDurationSeconds(
                            Math.max(0, Math.floor((Date.parse(window.ends_at) - nowMs) / 1000)),
                          )} left
                        </small>
                      ) : null}
                    </td>
                    <td>{describeRecurrence(window.recurrence)}</td>
                    <td>{window.created_by ?? "—"}</td>
                    {canManage ? (
                      <td>
                        {confirming === window.id ? (
                          <div className="maintenance-confirm">
                            <label htmlFor={`confirm-${window.id}`}>Type <code>{window.name}</code></label>
                            <input
                              autoComplete="off"
                              id={`confirm-${window.id}`}
                              onChange={(event) => setConfirmName(event.target.value)}
                              value={confirmName}
                            />
                            <div>
                              <button
                                className="danger"
                                disabled={busy === window.id || confirmName !== window.name}
                                onClick={() => endWindow(window)}
                                type="button"
                              >
                                {busy === window.id ? "Ending…" : "End window"}
                              </button>
                              <button
                                onClick={() => { setConfirming(null); setConfirmName(""); }}
                                type="button"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        ) : (
                          <button
                            onClick={() => { setConfirming(window.id); setConfirmName(""); setError(""); }}
                            type="button"
                          >
                            <Trash2 aria-hidden="true" size={13} /> End
                          </button>
                        )}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
