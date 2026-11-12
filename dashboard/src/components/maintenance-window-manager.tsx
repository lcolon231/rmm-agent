// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowRight,
  CalendarClock,
  CalendarPlus,
  CalendarRange,
  CircleAlert,
  Plus,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";

import { MAINTENANCE_WINDOWS_DESCRIPTION } from "@/components/patching/copy";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { Button, buttonClass } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DataTable, PrimaryCell, TableFooter, type Column } from "@/components/ui/data-table";
import { DefinitionList, Drawer } from "@/components/ui/drawer";
import { Input, Select } from "@/components/ui/field";
import { FilterBar, FilterChip } from "@/components/ui/filter-bar";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { EmptyState } from "@/components/ui/states";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
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
  type MaintenanceWindowState,
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

/** Fixed status words: open is Active, not yet open is Waiting, past is Expired. */
const STATE_BADGE: Record<MaintenanceWindowState, { tone: StatusTone; label: string; reason: string }> = {
  active: { tone: "ok", label: "Active", reason: "Open now" },
  between_occurrences: { tone: "info", label: "Waiting", reason: "Between occurrences" },
  upcoming: { tone: "info", label: "Waiting", reason: "Not open yet" },
  expired: { tone: "off", label: "Expired", reason: "Closed" },
};

type StateFilter = "all" | "active" | "waiting" | "expired";

function matchesFilter(state: MaintenanceWindowState, filter: StateFilter) {
  if (filter === "all") return true;
  if (filter === "active") return state === "active";
  if (filter === "waiting") return state === "upcoming" || state === "between_occurrences";
  return state === "expired";
}

type Row = { window: MaintenanceWindow; state: MaintenanceWindowState };

function PowerActionCallout({ coverSeconds }: { coverSeconds: number }) {
  return (
    <section role="note" className="flex items-start gap-3 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-(--slate)">
      <TriangleAlert aria-hidden="true" size={18} className="mt-0.5 shrink-0 text-[#89500b]" />
      <p className="m-0 grid gap-0.5">
        <strong className="text-[#89500b]">A power action is waiting on this window</strong>
        <span>
          The management service refused the prepared restart or shutdown because no window
          covers this endpoint. Create one that is open now and stays open for at least{" "}
          {formatDurationSeconds(coverSeconds)} — the delay you chose — then return to
          the console and confirm the dispatch again.
        </span>
      </p>
    </section>
  );
}

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
  const [endError, setEndError] = useState("");
  const [created, setCreated] = useState<MaintenanceWindow | null>(null);
  // Arriving from the command console with a target or a power action waiting
  // opens the form straight away, as the always-visible form did before.
  const [creating, setCreating] = useState(
    canManage && Boolean(prefill.coverSeconds || prefill.scopeId || prefill.name),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [ending, setEnding] = useState<MaintenanceWindow | null>(null);
  // Ending a window still needs its exact name typed, which the route matches
  // against the live record before it deletes anything.
  const [confirmName, setConfirmName] = useState("");
  const [filter, setFilter] = useState<StateFilter>("all");

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
  const upcoming = ordered.filter((item) => item.state === "upcoming");
  const betweenCount = ordered.filter((item) => item.state === "between_occurrences").length;
  const waitingCount = upcoming.length + betweenCount;
  const expiredCount = ordered.filter((item) => item.state === "expired").length;
  const nextWindow = upcoming[0]?.window ?? null;
  const shown = ordered.filter((item) => matchesFilter(item.state, filter));
  const selected = ordered.find((item) => item.window.id === selectedId) ?? null;

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
        setCreating(false);
        router.refresh();
      }
    } catch {
      setError("The maintenance window could not be created.");
    }
    setBusy(null);
  }

  // The delete route takes only the typed window name, which it matches against
  // the live record; it has no field for a reason, so the reason is not sent.
  async function endWindow(window: MaintenanceWindow) {
    setEndError("");
    setBusy(window.id);
    try {
      const response = await fetch(`/api/maintenance-windows/${encodeURIComponent(window.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm_name: confirmName }),
      });
      const body = await response.json().catch(() => null) as { error?: string } | null;
      if (!response.ok) {
        setEndError(`${body?.error ?? "The maintenance window could not be ended."} Nothing was changed.`);
      } else {
        setWindows((current) => current.filter((item) => item.id !== window.id));
        if (created?.id === window.id) setCreated(null);
        setEnding(null);
        setConfirmName("");
        router.refresh();
      }
    } catch {
      setEndError("The maintenance window could not be ended. Nothing was changed.");
    }
    setBusy(null);
  }

  function openCreate() {
    setError("");
    setSelectedId(null);
    setCreating(true);
  }

  function openEnd(window: MaintenanceWindow) {
    setEndError("");
    setSelectedId(null);
    setEnding(window);
  }

  function selectWindow(id: string | null) {
    setConfirmName("");
    setSelectedId(id);
  }

  function cancelEnd() {
    setEnding(null);
    setConfirmName("");
  }

  const columns: Column<Row>[] = [
    { key: "window", header: "Window", cell: ({ window }) => <PrimaryCell title={window.name} sub={describeRecurrence(window.recurrence)} /> },
    {
      key: "state",
      header: "State",
      cell: ({ state }) => (
        <span className="grid justify-items-start gap-1">
          <StatusBadge tone={STATE_BADGE[state].tone}>{STATE_BADGE[state].label}</StatusBadge>
          <span className="text-xs text-(--muted)">{STATE_BADGE[state].reason}</span>
        </span>
      ),
    },
    {
      key: "when",
      header: "When",
      cell: ({ window, state }) => (
        <PrimaryCell
          title={`${formatMonitoringTimestamp(window.starts_at)} → ${formatMonitoringTimestamp(window.ends_at)}`}
          sub={
            state === "active"
              ? `${formatDurationSeconds(Math.max(0, Math.floor((Date.parse(window.ends_at) - nowMs) / 1000)))} left`
              : undefined
          }
        />
      ),
    },
    {
      key: "scope",
      header: "Applies to",
      cell: ({ window }) => (
        <PrimaryCell title={formatWindowScope(window.scope)} sub={<span className="font-(family-name:--font-data)">{formatWindowTarget(window, targetNames)}</span>} />
      ),
    },
    {
      key: "by",
      header: "Created by",
      cell: ({ window }) => (window.created_by ? <span className="font-(family-name:--font-data) text-[13px]">{window.created_by}</span> : <span className="text-(--muted)">—</span>),
    },
  ];

  const tableState =
    ordered.length === 0 ? (
      <EmptyState
        icon={CalendarClock}
        title="No maintenance windows"
        body="Alert notifications keep being sent and power actions stay refused until a window covers the device."
        actionLabel={canManage ? "New window" : undefined}
        onAction={canManage ? openCreate : undefined}
      />
    ) : shown.length === 0 ? (
      <EmptyState title="No windows match" body="Clear the filter to see every window." actionLabel="Clear filters" onAction={() => setFilter("all")} />
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Patching" }, { label: "Maintenance windows" }]}
        title="Maintenance windows"
        description={MAINTENANCE_WINDOWS_DESCRIPTION}
        actions={canManage ? <Button variant="primary" icon={Plus} onClick={openCreate}>New window</Button> : null}
      />

      {prefill.coverSeconds ? <PowerActionCallout coverSeconds={prefill.coverSeconds} /> : null}

      <StatRow>
        <StatTile
          icon={ShieldCheck}
          label="Open now"
          tone={openCount > 0 ? "ok" : "off"}
          value={openCount}
          sub={`As of ${formatMonitoringTimestamp(new Date(nowMs).toISOString())}`}
        />
        <StatTile
          icon={CalendarClock}
          label="Next window"
          value={nextWindow ? formatMonitoringTimestamp(nextWindow.starts_at) : "—"}
          sub={
            nextWindow
              ? nextWindow.name
              : betweenCount > 0
                ? `${betweenCount} repeating window${betweenCount === 1 ? "" : "s"} will reopen`
                : "Nothing scheduled"
          }
        />
        <StatTile icon={CalendarRange} label="Windows" value={windows.length} sub={`${waitingCount} waiting · ${expiredCount} expired`} />
      </StatRow>

      {canManage ? null : (
        <p role="status" className="m-0 text-sm text-(--muted)">
          Your role can review maintenance windows. Creating or ending one requires the operator role.
        </p>
      )}

      <p className="m-0 flex items-start gap-2 text-[13px] text-(--muted)">
        <ShieldCheck size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
        The management service checks for a covering window again when it signs a restart or shutdown. Nothing on this page weakens that check.
      </p>

      {created ? (
        <section role="status" className="flex flex-wrap items-start gap-3 rounded-lg bg-(--success-soft) px-4 py-3 text-sm text-(--slate)">
          <ShieldCheck aria-hidden="true" size={18} className="mt-0.5 shrink-0 text-(--success)" />
          <p className="m-0 grid flex-1 gap-0.5">
            <strong className="text-(--success)">{created.name} was created · {STATE_BADGE[windowStateAt(created, nowMs)].reason}</strong>
            <span>
              Scheduled from {formatMonitoringTimestamp(created.starts_at)} to {formatMonitoringTimestamp(created.ends_at)}. The management service will
              re-check coverage when the command is signed.
            </span>
          </p>
          {prefill.returnPath ? (
            <Link className={buttonClass("secondary", "compact")} href={prefill.returnPath}>
              Return to the command console <ArrowRight aria-hidden="true" size={14} />
            </Link>
          ) : null}
        </section>
      ) : null}

      <DataTable
        caption="Maintenance windows"
        columns={columns}
        rows={shown}
        rowKey={({ window }) => window.id}
        rowLabel={({ window }) => `Show schedule for ${window.name}`}
        onRowSelect={({ window }) => selectWindow(window.id)}
        state={tableState}
        minWidth={1000}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              <FilterChip selected={filter === "all"} count={windows.length} onClick={() => setFilter("all")}>All</FilterChip>
              <FilterChip selected={filter === "active"} count={openCount} onClick={() => setFilter("active")}>Active</FilterChip>
              <FilterChip selected={filter === "waiting"} count={waitingCount} onClick={() => setFilter("waiting")}>Waiting</FilterChip>
              <FilterChip selected={filter === "expired"} count={expiredCount} onClick={() => setFilter("expired")}>Expired</FilterChip>
            </div>
          </FilterBar>
        }
        footer={shown.length > 0 ? <TableFooter shown={shown.length} total={windows.length} sortNote="open now first, then by start time" /> : null}
      />

      {selected ? (
        <Drawer
          open
          onClose={() => selectWindow(null)}
          context={formatWindowScope(selected.window.scope)}
          title={selected.window.name}
          sub="Schedule"
          record={`Created ${formatMonitoringTimestamp(selected.window.created_at)}${selected.window.created_by ? ` by ${selected.window.created_by}` : ""}. Creating and ending a window are recorded in the audit log.`}
          footer={
            canManage ? (
              <Button
                variant="danger"
                icon={Trash2}
                onClick={() => openEnd(selected.window)}
                disabled={busy === selected.window.id || confirmName !== selected.window.name}
              >
                End window
              </Button>
            ) : null
          }
        >
          <div className="flex items-center gap-2">
            <StatusBadge tone={STATE_BADGE[selected.state].tone}>{STATE_BADGE[selected.state].label}</StatusBadge>
            <span className="text-[13px] text-(--muted)">{describeWindowState(selected.state)}</span>
          </div>
          <DefinitionList
            items={[
              { term: "Opens", value: formatMonitoringTimestamp(selected.window.starts_at) },
              { term: "Closes", value: formatMonitoringTimestamp(selected.window.ends_at) },
              ...(selected.state === "active"
                ? [{ term: "Time left", value: formatDurationSeconds(Math.max(0, Math.floor((Date.parse(selected.window.ends_at) - nowMs) / 1000))) }]
                : []),
              {
                term: "Length",
                value: formatDurationSeconds(Math.round((Date.parse(selected.window.ends_at) - Date.parse(selected.window.starts_at)) / 1000)),
              },
              { term: "Repeats", value: describeRecurrence(selected.window.recurrence) },
              { term: "Time zone", value: selected.window.timezone },
              {
                term: "Applies to",
                value: <span className="font-(family-name:--font-data) text-[13px]">{formatWindowTarget(selected.window, targetNames)}</span>,
              },
              { term: "Window ID", value: <span className="font-(family-name:--font-data) text-[13px]">{selected.window.id}</span> },
            ]}
          />
          {canManage ? (
            <Input
              label={`To end this window, type its name: ${selected.window.name}`}
              autoComplete="off"
              value={confirmName}
              onChange={(event) => setConfirmName(event.target.value)}
            />
          ) : null}
        </Drawer>
      ) : null}

      {canManage && creating ? (
        <Drawer
          open
          onClose={() => setCreating(false)}
          title="New maintenance window"
          sub="Absolute span. Restart and shutdown are authorized only while a covering window is open."
          footer={
            <>
              <Button
                type="submit"
                form="new-maintenance-window"
                variant="primary"
                icon={CalendarPlus}
                disabled={busy === "create" || !preview.ok}
                aria-busy={busy === "create" || undefined}
              >
                {busy === "create" ? "Creating…" : "Create window"}
              </Button>
              <Button onClick={() => setCreating(false)}>Cancel</Button>
            </>
          }
        >
          {prefill.coverSeconds ? <PowerActionCallout coverSeconds={prefill.coverSeconds} /> : null}
          <form id="new-maintenance-window" className="grid gap-4" onSubmit={create}>
            <Input
              label="Name"
              maxLength={MAX_WINDOW_NAME_LENGTH}
              onChange={(event) => setName(event.target.value)}
              placeholder="KB5120708 reboot — approved change 4821"
              required
              value={name}
            />
            <Select
              label="Scope"
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
            </Select>
            {scope === "global" ? (
              <Input label="Coverage" disabled readOnly value="Every managed endpoint" />
            ) : (
              <Select label={formatWindowScope(scope)} onChange={(event) => setScopeId(event.target.value)} required value={scopeId}>
                <option value="">Choose a target…</option>
                {targetOptions.some((option) => option.id === scopeId) || !scopeId ? null : (
                  <option value={scopeId}>{scopeId} (from the command console)</option>
                )}
                {targetOptions.map((option) => (
                  <option key={option.id} value={option.id}>{option.label} — {option.hint}</option>
                ))}
              </Select>
            )}
            <Select label="Time zone" onChange={(event) => changeZone(event.target.value)} value={timeZone}>
              {zoneOptions.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
            </Select>
            <Input
              label="Starts"
              onChange={(event) => setStartsAt(event.target.value)}
              required
              step={60}
              type="datetime-local"
              value={startsAt}
            />
            <Input
              label="Ends"
              onChange={(event) => setEndsAt(event.target.value)}
              required
              step={60}
              type="datetime-local"
              value={endsAt}
            />
            <fieldset className="m-0 grid gap-2 border-0 p-0">
              <legend className="mb-1.5 p-0 text-[13px] font-semibold text-(--slate)">Open now for</legend>
              <div className="flex flex-wrap gap-2">
                {DURATION_PRESETS.map((preset) => (
                  <Button key={preset.seconds} size="compact" onClick={() => applyDuration(preset.seconds)}>
                    {preset.label}
                  </Button>
                ))}
              </div>
            </fieldset>
            <p role="status" className={preview.ok ? "m-0 flex items-start gap-2 text-sm text-(--slate)" : "m-0 flex items-start gap-2 text-sm text-[#89500b]"}>
              {preview.ok ? (
                <>
                  <ShieldCheck aria-hidden="true" size={16} className="mt-0.5 shrink-0 text-(--success)" />
                  <span>
                    Covers {formatMonitoringTimestamp(new Date(preview.startsAtMs).toISOString())} →{" "}
                    {formatMonitoringTimestamp(new Date(preview.endsAtMs).toISOString())} (
                    {formatDurationSeconds(Math.round((preview.endsAtMs - preview.startsAtMs) / 1000))}).
                  </span>
                </>
              ) : (
                <>
                  <TriangleAlert aria-hidden="true" size={16} className="mt-0.5 shrink-0" />
                  <span>{preview.error}</span>
                </>
              )}
            </p>
            {error ? (
              <p role="alert" className="m-0 flex items-center gap-2 text-sm text-(--red)">
                <CircleAlert size={16} aria-hidden="true" />
                {error}
              </p>
            ) : null}
          </form>
        </Drawer>
      ) : null}

      <ConfirmDialog
        open={canManage && ending !== null}
        onCancel={cancelEnd}
        onConfirm={() => (ending ? endWindow(ending) : undefined)}
        title={ending ? `End ${ending.name}?` : "End window?"}
        consequence="The window closes for good. Restarts and shutdowns it covers are no longer authorized, and alert notifications for its devices are sent again."
        confirmLabel="End window"
        busy={ending !== null && busy === ending.id}
        error={endError || undefined}
      />
    </PageStack>
  );
}
