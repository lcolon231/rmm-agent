// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  Send,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { MAX_UPDATE_TARGETS, validateDispatchInput, type DispatchInput } from "@/lib/command-console-core";
import {
  formatInventoryTimestamp,
  statusExplanation,
  type InventorySectionStatus,
} from "@/lib/inventory-core";
import {
  filterMissingWindowsUpdates,
  isDriverUpdate,
  normalizedKBID,
  normalizedUpdateID,
  summarizeWindowsUpdateSelection,
  WINDOWS_UPDATE_PAGE_SIZE,
  windowsUpdateClassifications,
  windowsUpdatePage,
  windowsUpdatePageCount,
  windowsUpdateInstallTargets,
  windowsUpdateSelectionKey,
  type MissingUpdateView,
  type WindowsUpdatesView,
} from "@/lib/windows-updates-core";

import { InventoryStatus } from "./endpoint/inventory-section-card";
import { inlineLink, monoText, Notice, Panel } from "./endpoint/section-header";
import { Button } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { FilterBar, SearchField } from "./ui/filter-bar";
import { StatusBadge } from "./ui/status-badge";

type InstallationStep =
  | { name: "select" }
  | { name: "confirm"; input: DispatchInput; updates: MissingUpdateView[] }
  | { name: "dispatched"; commandId: string; updateCount: number };

export function WindowsUpdateInstallation({
  canDispatch,
  endpointId,
  hostname,
  isStale,
  sectionStatus,
  trusted,
  view,
}: {
  canDispatch: boolean;
  endpointId: string;
  hostname: string;
  isStale: boolean;
  sectionStatus: InventorySectionStatus;
  trusted: boolean;
  view: WindowsUpdatesView;
}) {
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("");
  const [excludeDrivers, setExcludeDrivers] = useState(true);
  const [page, setPage] = useState(1);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [step, setStep] = useState<InstallationStep>({ name: "select" });
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const classifications = useMemo(
    () => windowsUpdateClassifications(view.missing),
    [view.missing],
  );
  const filtered = useMemo(
    () => filterMissingWindowsUpdates(view.missing, { query, classification, excludeDrivers }),
    [classification, excludeDrivers, query, view.missing],
  );
  const pageCount = windowsUpdatePageCount(filtered.length);
  const currentPage = Math.min(page, pageCount);
  const visibleUpdates = windowsUpdatePage(filtered, currentPage);
  const visibleSelectable = Array.from(new Set(visibleUpdates
    .map(windowsUpdateSelectionKey)
    .filter((value): value is string => value !== null)));
  const selectedUpdates = view.missing.filter((update) => {
    const key = windowsUpdateSelectionKey(update);
    return key !== null && selectedKeys.has(key);
  });
  const selectedSummary = summarizeWindowsUpdateSelection(selectedUpdates);
  const driverCount = view.missing.filter(isDriverUpdate).length;
  const updateIDOnlyCount = view.missing.filter(
    (update) => normalizedKBID(update.kb_id) === null && normalizedUpdateID(update.update_id) !== null,
  ).length;
  const unselectableCount = view.missing.filter((update) => windowsUpdateSelectionKey(update) === null).length;
  const scanCanBeUsed = (sectionStatus === "ok" || sectionStatus === "partial")
    && !view.error_code;

  function updateFilters(change: () => void) {
    change();
    setPage(1);
  }

  function toggleUpdate(key: string, checked: boolean) {
    setSelectedKeys((current) => {
      const next = new Set(current);
      if (checked) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  function toggleVisible() {
    const allSelected = visibleSelectable.length > 0
      && visibleSelectable.every((key) => selectedKeys.has(key));
    setSelectedKeys((current) => {
      const next = new Set(current);
      for (const key of visibleSelectable) {
        if (allSelected) next.delete(key);
        else next.add(key);
      }
      return next;
    });
  }

  function reviewSelection() {
    setError("");
    // Targets come from the current scan rows, never the raw selection set, so
    // an identifier that is no longer in the inventory cannot be dispatched.
    const targets = windowsUpdateInstallTargets(selectedUpdates);
    if (!scanCanBeUsed) {
      setError("Run a successful Windows Update scan before installing from this inventory.");
      return;
    }
    if (targets.length === 0) {
      setError("Select at least one update with a KB ID or Windows Update ID before reviewing the install.");
      return;
    }
    if (targets.length > MAX_UPDATE_TARGETS) {
      setError(`Select at most ${MAX_UPDATE_TARGETS} update identifiers per install.`);
      return;
    }
    const input = validateDispatchInput({
      install_all: false,
      kind: "install_updates",
      script: "",
      ttl_seconds: 3_600,
      update_targets: targets,
    });
    if (!input || input.install_all || input.update_targets.length === 0) {
      setError("The selected update identifiers could not be validated. Run a fresh scan and try again.");
      return;
    }
    setStep({ name: "confirm", input, updates: selectedUpdates });
  }

  async function dispatchSelection(input: DispatchInput, updateCount: number) {
    setError("");
    setIsSubmitting(true);
    try {
      const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/commands`, {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as
        | { command?: { id: string }; error?: string }
        | null;
      if (response.ok && body?.command?.id) {
        setSelectedKeys(new Set());
        setStep({ name: "dispatched", commandId: body.command.id, updateCount });
      } else {
        setError(body?.error ?? "The selected updates could not be dispatched. Try again.");
      }
    } catch {
      setError("The selected updates could not be dispatched. Try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  if (step.name === "confirm") {
    const summary = summarizeWindowsUpdateSelection(step.updates);
    return (
      <Panel id="windows-updates" title={`Review targeted install for ${hostname}`} sub="Windows updates · confirmation" action={<ShieldCheck aria-hidden="true" size={20} className="text-(--muted)" />}>
        <div className="grid gap-4 px-5 py-4" role="region" aria-label="Confirm selected Windows updates">
          <div className="grid grid-cols-3 gap-3">
            <Count label="Selected" value={summary.updateCount} sub="updates" />
            <Count label="Drivers" value={summary.driverCount} sub="selected" warn={summary.driverCount > 0} />
            <Count label="Reboot" value={summary.rebootCount} sub="flagged" warn={summary.rebootCount > 0} />
          </div>
          {summary.rebootCount > 0 ? (
            <Notice tone="warn" role="note" title="A restart may follow">
              One or more selected updates may restart the endpoint or leave it requiring a restart. Save active work before dispatching.
            </Notice>
          ) : (
            <p className={note}>Only the KB IDs and Windows Update IDs listed below will be signed and sent. An empty selection cannot be dispatched.</p>
          )}
          <ul className="m-0 grid list-none gap-0 rounded-lg border border-(--line) p-0">
            {step.updates.map((update, index) => (
              <li key={`${windowsUpdateSelectionKey(update)}-${index}`} className="flex flex-wrap items-start gap-3 border-t border-(--line) px-3 py-2 text-[13px] first:border-t-0">
                <code className={cx(monoText, "shrink-0 text-(--ink)")}>{normalizedKBID(update.kb_id) ?? "No KB"}</code>
                <span className="grid min-w-0 flex-1 gap-0.5 text-(--slate)">
                  {update.title}
                  <small className="text-xs text-(--muted)">
                    {normalizedUpdateID(update.update_id)
                      ? <>Update ID <code className={monoText}>{normalizedUpdateID(update.update_id)}</code></>
                      : "Update ID not reported"}
                  </small>
                </span>
                {isDriverUpdate(update) ? <Tag>Driver</Tag> : null}
                {update.reboot_required ? <Tag warn>Reboot</Tag> : null}
              </li>
            ))}
          </ul>
          {error ? <p className={errorText} role="alert">{error}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button disabled={isSubmitting} icon={ChevronLeft} onClick={() => setStep({ name: "select" })}>
              Back to selection
            </Button>
            <Button
              variant="primary"
              disabled={isSubmitting}
              icon={Send}
              onClick={() => void dispatchSelection(step.input, summary.updateCount)}
            >
              {isSubmitting ? "Dispatching…" : `Install ${summary.updateCount} selected`}
            </Button>
          </div>
        </div>
      </Panel>
    );
  }

  if (step.name === "dispatched") {
    return (
      <div id="windows-updates">
        <Notice
          tone="ok"
          icon={CheckCircle2}
          title={`${step.updateCount} selected update${step.updateCount === 1 ? "" : "s"} queued`}
          action={
            <Link className={cx(inlineLink, "inline-flex items-center gap-1 text-sm")} href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(step.commandId)}`}>
              Follow command <ChevronRight size={14} aria-hidden="true" />
            </Link>
          }
        >
          Follow the signed command for installed and failed updates, reboot state, and the agent message. Run a fresh scan after it finishes.
        </Notice>
      </div>
    );
  }

  const allVisibleSelected = visibleSelectable.length > 0
    && visibleSelectable.every((key) => selectedKeys.has(key));

  return (
    <Panel
      id="windows-updates"
      title={`${view.missing.length} missing update${view.missing.length === 1 ? "" : "s"}`}
      sub={`Windows updates · scanned ${formatInventoryTimestamp(view.scanned_at)} · ${view.installed.length} installed records`}
      action={
        <span className="flex flex-wrap items-center gap-2">
          <InventoryStatus status={sectionStatus} />
          {isStale ? <StatusBadge tone="warn">Behind</StatusBadge> : <span className="text-xs text-(--muted)">Current scan</span>}
        </span>
      }
    >
      <div className="grid gap-3 px-5 pt-4">
        {sectionStatus === "ok" ? null : <p className={note}>{statusExplanation(sectionStatus)}</p>}
        {view.error_code ? (
          <Notice tone="crit" role="alert" icon={AlertTriangle} title={`Scan failed with ${view.error_code}`}>
            Do not install from this inventory.
          </Notice>
        ) : null}
        {view.history_error_code ? (
          <Notice tone="warn" icon={AlertTriangle} title={`Installed-update history is incomplete (${view.history_error_code})`}>
            The missing list remains visible.
          </Notice>
        ) : null}
        {isStale ? (
          <Notice tone="warn" icon={AlertTriangle} title="This scan is at least 24 hours old or has no valid scan time">
            Run a fresh scan before installing.
          </Notice>
        ) : null}

        <p className="m-0 flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-(--slate)">
          <span><strong className="text-(--ink)">{view.missing.length}</strong> missing</span>
          <span><strong className="text-(--ink)">{driverCount}</strong> drivers</span>
          <span><strong className="text-(--ink)">{updateIDOnlyCount}</strong> by Update ID only</span>
          <span><strong className="text-(--ink)">{unselectableCount}</strong> without an installable ID</span>
          <span><strong className="text-(--ink)">{view.missing.filter((update) => update.reboot_required).length}</strong> reboot flagged</span>
        </p>
      </div>

      <div className="mt-3">
        <FilterBar
          trailing={
            <Button
              variant="primary"
              disabled={!canDispatch || !trusted || selectedUpdates.length === 0 || !scanCanBeUsed}
              icon={Download}
              onClick={reviewSelection}
            >
              Review targeted install
            </Button>
          }
        >
          <SearchField
            id="windows-update-search"
            label="Search updates"
            onChange={(event) => updateFilters(() => setQuery(event.target.value))}
            placeholder="Search title, KB, Update ID, product, or severity"
            value={query}
          />
          <label htmlFor="windows-update-classification">
            <span className="sr-only">Filter by classification</span>
            <select
              className={cx("h-10 rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-sm text-(--ink)", focusRing)}
              id="windows-update-classification"
              onChange={(event) => updateFilters(() => setClassification(event.target.value))}
              value={classification}
            >
              <option value="">All classifications</option>
              {classifications.map((value) => <option key={value}>{value}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-(--slate)" htmlFor="windows-update-exclude-drivers">
            <input
              checked={excludeDrivers}
              className={cx("size-4 accent-(--primary-strong)", focusRing)}
              id="windows-update-exclude-drivers"
              onChange={(event) => updateFilters(() => setExcludeDrivers(event.target.checked))}
              type="checkbox"
            />
            Exclude drivers
          </label>
        </FilterBar>
      </div>

      <div className="grid gap-3 px-5 py-3">
        <div className="flex flex-wrap items-center gap-3 text-[13px] text-(--slate)">
          <Button size="compact" disabled={visibleSelectable.length === 0} onClick={toggleVisible}>
            {allVisibleSelected ? "Clear this page" : "Select this page"}
          </Button>
          <span>{selectedSummary.updateCount} selected · {selectedSummary.driverCount} drivers · {selectedSummary.rebootCount} reboot flagged</span>
        </div>
        {!canDispatch ? (
          <p className={note}>Your role can review updates, but targeted installation requires operator access.</p>
        ) : !trusted ? (
          <p className={note}>This endpoint is quarantined or revoked. Restore trust before installing updates.</p>
        ) : null}
        {error ? <p className={errorText} role="alert">{error}</p> : null}
      </div>

      {filtered.length === 0 ? (
        <div className="grid gap-1 border-t border-(--line) px-5 py-8 text-center">
          <strong className="text-sm text-(--ink)">No updates match these filters</strong>
          <span className="text-[13px] text-(--muted)">Clear search filters or include drivers to review the complete scan.</span>
        </div>
      ) : (
        <div className="overflow-x-auto border-t border-(--line)">
          <table className="w-full min-w-[920px] border-collapse text-left text-sm">
            <caption className="sr-only">Missing Windows updates</caption>
            <thead className="bg-(--fog)">
              <tr>
                {["Select", "Update", "Classification / product", "Severity", "Download", "Reboot", "Deployment change"].map((heading, index) => (
                  <th key={heading} scope="col" className="px-4 py-2.5 text-xs font-semibold whitespace-nowrap text-(--muted)">
                    {index === 0 ? <span className="sr-only">{heading}</span> : heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visibleUpdates.map((update, index) => {
                const kbID = normalizedKBID(update.kb_id);
                const updateID = normalizedUpdateID(update.update_id);
                const key = windowsUpdateSelectionKey(update);
                const driver = isDriverUpdate(update);
                return (
                  <tr className={cx("border-t border-(--line) align-top text-(--slate)", !key && "bg-(--fog)")} key={`${update.update_id ?? update.kb_id ?? update.title}-${index}`}>
                    <td className="px-4 py-3">
                      <input
                        aria-label={key
                          ? `Select ${kbID ?? `Update ID ${key}`}: ${update.title}`
                          : `${update.title} cannot be selected because it has no valid KB ID or Windows Update ID`}
                        checked={key ? selectedKeys.has(key) : false}
                        className={cx("size-4 accent-(--primary-strong)", focusRing)}
                        disabled={!key}
                        onChange={(event) => key && toggleUpdate(key, event.target.checked)}
                        type="checkbox"
                      />
                    </td>
                    <td className="max-w-[360px] px-4 py-3">
                      <span className="grid gap-1">
                        <strong className="font-semibold text-(--ink)">{update.title}</strong>
                        <span className="flex flex-wrap items-center gap-1.5 text-xs text-(--muted)">
                          {kbID
                            ? <code className={monoText}>{kbID}</code>
                            : updateID
                              ? <code className={monoText} title="Installed by Windows Update ID">{updateID}</code>
                              : <em>No valid KB ID or Update ID · cannot be installed from here</em>}
                          {driver ? <Tag>Driver</Tag> : null}
                          {update.priority_grade ? <Tag>{update.priority_grade}</Tag> : null}
                        </span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="grid gap-0.5">
                        <span className="font-semibold text-(--ink)">{update.classification ?? "Unclassified"}</span>
                        <span className="text-xs text-(--muted)">{update.product ?? "Product not reported"}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">{update.severity ?? "Not rated"}</td>
                    <td className="px-4 py-3 whitespace-nowrap">{update.is_downloaded === null ? "Unknown" : update.is_downloaded ? "Downloaded" : "Not downloaded"}</td>
                    <td className={cx("px-4 py-3", update.reboot_required && "font-semibold text-[#89500b]")}>{update.reboot_required === null ? "Unknown" : update.reboot_required ? "Required" : "No"}</td>
                    <td className="px-4 py-3 whitespace-nowrap">{formatInventoryTimestamp(update.last_deployment_change, "Not reported")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-(--line) px-5 py-3 text-xs text-(--muted)">
        <span>
          Showing {filtered.length === 0 ? 0 : (currentPage - 1) * WINDOWS_UPDATE_PAGE_SIZE + 1}–
          {Math.min(currentPage * WINDOWS_UPDATE_PAGE_SIZE, filtered.length)} of {filtered.length}
        </span>
        <nav aria-label="Windows Update pages" className="flex items-center gap-1">
          <Button size="compact" disabled={currentPage <= 1} icon={ChevronLeft} onClick={() => setPage(currentPage - 1)}>Previous</Button>
          <span className="px-2">Page {currentPage} of {pageCount}</span>
          <Button size="compact" disabled={currentPage >= pageCount} onClick={() => setPage(currentPage + 1)}>Next <ChevronRight size={14} aria-hidden="true" /></Button>
        </nav>
        <Link className={cx(inlineLink, "inline-flex items-center gap-1 text-sm")} href={`/endpoints/${encodeURIComponent(endpointId)}/inventory/windows_updates`}>
          History and changes <ChevronRight size={14} aria-hidden="true" />
        </Link>
      </footer>
    </Panel>
  );
}

const note = "m-0 text-[13px] text-(--muted)";
const errorText = "m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm font-semibold text-(--red)";

function Count({ label, value, sub, warn = false }: { label: string; value: number; sub: string; warn?: boolean }) {
  return (
    <div className={cx("grid gap-0.5 rounded-lg border px-3 py-2", warn ? "border-(--amber) bg-(--amber-soft)" : "border-(--line) bg-(--paper)")}>
      <span className="text-xs text-(--muted)">{label}</span>
      <strong className={cx("text-xl font-semibold tabular-nums", warn ? "text-[#89500b]" : "text-(--ink)")}>{value}</strong>
      <small className="text-xs text-(--muted)">{sub}</small>
    </div>
  );
}

function Tag({ children, warn = false }: { children: string; warn?: boolean }) {
  return (
    <b className={cx("rounded-full px-2 py-0.5 text-xs font-semibold", warn ? "bg-(--amber-soft) text-[#89500b]" : "bg-(--fog) text-(--slate)")}>{children}</b>
  );
}
