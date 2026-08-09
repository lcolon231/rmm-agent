// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  Search,
  Send,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { validateDispatchInput, type DispatchInput } from "@/lib/command-console-core";
import {
  formatInventoryTimestamp,
  statusExplanation,
  statusLabel,
  statusTone,
  type InventorySectionStatus,
} from "@/lib/inventory-core";
import {
  filterMissingWindowsUpdates,
  isDriverUpdate,
  normalizedKBID,
  summarizeWindowsUpdateSelection,
  WINDOWS_UPDATE_PAGE_SIZE,
  windowsUpdateClassifications,
  windowsUpdatePage,
  windowsUpdatePageCount,
  type MissingUpdateView,
  type WindowsUpdatesView,
} from "@/lib/windows-updates-core";

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
  const [selectedKBs, setSelectedKBs] = useState<Set<string>>(new Set());
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
  const visibleSelectable = visibleUpdates
    .map((update) => normalizedKBID(update.kb_id))
    .filter((value): value is string => value !== null);
  const selectedUpdates = view.missing.filter((update) => {
    const kbID = normalizedKBID(update.kb_id);
    return kbID !== null && selectedKBs.has(kbID);
  });
  const selectedSummary = summarizeWindowsUpdateSelection(selectedUpdates);
  const driverCount = view.missing.filter(isDriverUpdate).length;
  const noKBCount = view.missing.filter((update) => normalizedKBID(update.kb_id) === null).length;
  const tone = statusTone(sectionStatus);
  const scanCanBeUsed = (sectionStatus === "ok" || sectionStatus === "partial")
    && !view.error_code;

  function updateFilters(change: () => void) {
    change();
    setPage(1);
  }

  function toggleUpdate(kbID: string, checked: boolean) {
    setSelectedKBs((current) => {
      const next = new Set(current);
      if (checked) next.add(kbID);
      else next.delete(kbID);
      return next;
    });
  }

  function toggleVisible() {
    const allSelected = visibleSelectable.length > 0
      && visibleSelectable.every((kbID) => selectedKBs.has(kbID));
    setSelectedKBs((current) => {
      const next = new Set(current);
      for (const kbID of visibleSelectable) {
        if (allSelected) next.delete(kbID);
        else next.add(kbID);
      }
      return next;
    });
  }

  function reviewSelection() {
    setError("");
    const kbIDs = Array.from(selectedKBs);
    const input = validateDispatchInput({
      install_all: false,
      kind: "install_updates",
      script: "",
      ttl_seconds: 3_600,
      update_targets: kbIDs,
    });
    if (!scanCanBeUsed) {
      setError("Run a successful Windows Update scan before installing from this inventory.");
      return;
    }
    if (!input || selectedUpdates.length === 0) {
      setError("Select at least one KB-backed update before reviewing the install.");
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
        setSelectedKBs(new Set());
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
      <section className="enrollment-panel inventory-card windows-update-workflow" id="windows-updates">
        <header>
          <div>
            <span>Windows Updates · confirmation</span>
            <h2>Review targeted install for {hostname}</h2>
          </div>
          <ShieldCheck aria-hidden="true" size={22} />
        </header>
        <div className="windows-update-confirmation" role="region" aria-label="Confirm selected Windows updates">
          <div className="windows-update-risk-totals">
            <article><span>Selected</span><strong>{summary.updateCount}</strong><small>updates</small></article>
            <article className={summary.driverCount > 0 ? "warn" : ""}><span>Drivers</span><strong>{summary.driverCount}</strong><small>selected</small></article>
            <article className={summary.rebootCount > 0 ? "warn" : ""}><span>Reboot</span><strong>{summary.rebootCount}</strong><small>flagged</small></article>
          </div>
          <p className={summary.rebootCount > 0 ? "windows-update-reboot-warning" : "windows-update-confirm-note"}>
            {summary.rebootCount > 0
              ? "One or more selected updates may restart the endpoint or leave it requiring a restart. Save active work before dispatching."
              : "Only the KB IDs listed below will be signed and sent. An empty selection cannot be dispatched."}
          </p>
          <ul className="windows-update-confirm-list">
            {step.updates.map((update, index) => (
              <li key={`${update.kb_id}-${index}`}>
                <code>{normalizedKBID(update.kb_id)}</code>
                <span>{update.title}</span>
                {isDriverUpdate(update) ? <b>Driver</b> : null}
                {update.reboot_required ? <b>Reboot</b> : null}
              </li>
            ))}
          </ul>
          {error ? <p className="dispatch-error" role="alert">{error}</p> : null}
          <div className="windows-update-confirm-actions">
            <button disabled={isSubmitting} onClick={() => setStep({ name: "select" })} type="button">
              <ChevronLeft size={15} /> Back to selection
            </button>
            <button
              className="danger"
              disabled={isSubmitting}
              onClick={() => void dispatchSelection(step.input, summary.updateCount)}
              type="button"
            >
              <Send size={15} /> {isSubmitting ? "Dispatching…" : `Install ${summary.updateCount} selected`}
            </button>
          </div>
        </div>
      </section>
    );
  }

  if (step.name === "dispatched") {
    return (
      <section className="enrollment-panel inventory-card windows-update-workflow" id="windows-updates">
        <div className="windows-update-dispatched" role="status">
          <CheckCircle2 aria-hidden="true" size={24} />
          <div>
            <strong>{step.updateCount} selected update{step.updateCount === 1 ? "" : "s"} queued</strong>
            <span>
              Follow the signed command for installed and failed KBs, reboot state, and the agent message. Run a fresh scan after it finishes.
            </span>
          </div>
          <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(step.commandId)}`}>
            Follow command <ChevronRight size={14} />
          </Link>
        </div>
      </section>
    );
  }

  const allVisibleSelected = visibleSelectable.length > 0
    && visibleSelectable.every((kbID) => selectedKBs.has(kbID));

  return (
    <section className="enrollment-panel inventory-card windows-update-workflow" id="windows-updates">
      <header>
        <div>
          <span>Windows Updates · targeted installation</span>
          <h2>{view.missing.length} missing update{view.missing.length === 1 ? "" : "s"}</h2>
          <small>
            Scanned {formatInventoryTimestamp(view.scanned_at)} · {view.installed.length} installed records
          </small>
        </div>
        <div className="windows-update-status-stack">
          <span className={`audit-tone ${tone}`}>{statusLabel(sectionStatus)}</span>
          <span className={`windows-update-freshness ${isStale ? "stale" : "current"}`}>
            {isStale ? "Stale scan" : "Current scan"}
          </span>
        </div>
      </header>

      {sectionStatus === "ok" ? null : (
        <p className="inventory-status-note">{statusExplanation(sectionStatus)}</p>
      )}
      {view.error_code ? (
        <p className="windows-update-alert" role="alert">
          <AlertTriangle size={16} /> Scan failed with {view.error_code}. Do not install from this inventory.
        </p>
      ) : null}
      {view.history_error_code ? (
        <p className="windows-update-alert" role="status">
          <AlertTriangle size={16} /> Installed-update history is incomplete ({view.history_error_code}); the missing list remains visible.
        </p>
      ) : null}
      {isStale ? (
        <p className="windows-update-alert" role="status">
          <AlertTriangle size={16} /> This scan is at least 24 hours old or has no valid scan time. Run a fresh scan before installing.
        </p>
      ) : null}

      <div className="windows-update-summary-strip">
        <span><strong>{view.missing.length}</strong> missing</span>
        <span><strong>{driverCount}</strong> drivers</span>
        <span><strong>{noKBCount}</strong> without KB IDs</span>
        <span><strong>{view.missing.filter((update) => update.reboot_required).length}</strong> reboot flagged</span>
      </div>

      <div className="windows-update-toolbar">
        <label className="windows-update-search" htmlFor="windows-update-search">
          <Search aria-hidden="true" size={15} />
          <span className="sr-only">Search updates</span>
          <input
            id="windows-update-search"
            onChange={(event) => updateFilters(() => setQuery(event.target.value))}
            placeholder="Search title, KB, product, or severity"
            type="search"
            value={query}
          />
        </label>
        <label htmlFor="windows-update-classification">
          <span className="sr-only">Filter by classification</span>
          <select
            id="windows-update-classification"
            onChange={(event) => updateFilters(() => setClassification(event.target.value))}
            value={classification}
          >
            <option value="">All classifications</option>
            {classifications.map((value) => <option key={value}>{value}</option>)}
          </select>
        </label>
        <label className="windows-update-driver-filter" htmlFor="windows-update-exclude-drivers">
          <input
            checked={excludeDrivers}
            id="windows-update-exclude-drivers"
            onChange={(event) => updateFilters(() => setExcludeDrivers(event.target.checked))}
            type="checkbox"
          />
          Exclude drivers
        </label>
      </div>

      <div className="windows-update-selection-bar">
        <button disabled={visibleSelectable.length === 0} onClick={toggleVisible} type="button">
          {allVisibleSelected ? "Clear this page" : "Select this page"}
        </button>
        <span>{selectedSummary.updateCount} selected · {selectedSummary.driverCount} drivers · {selectedSummary.rebootCount} reboot flagged</span>
        <button
          className="primary"
          disabled={!canDispatch || !trusted || selectedKBs.size === 0 || !scanCanBeUsed}
          onClick={reviewSelection}
          type="button"
        >
          <Download size={15} /> Review targeted install
        </button>
      </div>

      {!canDispatch ? (
        <p className="windows-update-readonly">Your role can review updates, but targeted installation requires operator access.</p>
      ) : !trusted ? (
        <p className="windows-update-readonly">This endpoint is quarantined or revoked. Restore trust before installing updates.</p>
      ) : null}
      {error ? <p className="dispatch-error" role="alert">{error}</p> : null}

      {filtered.length === 0 ? (
        <div className="windows-update-empty">
          <strong>No updates match these filters</strong>
          <span>Clear search filters or include drivers to review the complete scan.</span>
        </div>
      ) : (
        <div className="windows-update-table-scroll">
          <table className="windows-update-table">
            <thead>
              <tr>
                <th><span className="sr-only">Select</span></th>
                <th>Update</th>
                <th>Classification / product</th>
                <th>Severity</th>
                <th>Download</th>
                <th>Reboot</th>
                <th>Deployment change</th>
              </tr>
            </thead>
            <tbody>
              {visibleUpdates.map((update, index) => {
                const kbID = normalizedKBID(update.kb_id);
                const driver = isDriverUpdate(update);
                return (
                  <tr className={kbID ? "" : "not-selectable"} key={`${update.update_id ?? update.kb_id ?? update.title}-${index}`}>
                    <td>
                      <input
                        aria-label={kbID ? `Select ${kbID}: ${update.title}` : `${update.title} cannot be selected because it has no KB ID`}
                        checked={kbID ? selectedKBs.has(kbID) : false}
                        disabled={!kbID}
                        onChange={(event) => kbID && toggleUpdate(kbID, event.target.checked)}
                        type="checkbox"
                      />
                    </td>
                    <td>
                      <strong>{update.title}</strong>
                      <span>
                        {kbID ? <code>{kbID}</code> : <em>No KB ID · not individually selectable</em>}
                        {driver ? <b>Driver</b> : null}
                        {update.priority_grade ? <b>{update.priority_grade}</b> : null}
                      </span>
                    </td>
                    <td><strong>{update.classification ?? "Unclassified"}</strong><span>{update.product ?? "Product not reported"}</span></td>
                    <td>{update.severity ?? "Not rated"}</td>
                    <td>{update.is_downloaded === null ? "Unknown" : update.is_downloaded ? "Downloaded" : "Not downloaded"}</td>
                    <td className={update.reboot_required ? "warn" : ""}>{update.reboot_required === null ? "Unknown" : update.reboot_required ? "Required" : "No"}</td>
                    <td>{formatInventoryTimestamp(update.last_deployment_change, "Not reported")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <footer className="windows-update-pagination">
        <span>
          Showing {filtered.length === 0 ? 0 : (currentPage - 1) * WINDOWS_UPDATE_PAGE_SIZE + 1}–
          {Math.min(currentPage * WINDOWS_UPDATE_PAGE_SIZE, filtered.length)} of {filtered.length}
        </span>
        <nav aria-label="Windows Update pages">
          <button disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)} type="button"><ChevronLeft size={14} /> Previous</button>
          <span>Page {currentPage} of {pageCount}</span>
          <button disabled={currentPage >= pageCount} onClick={() => setPage(currentPage + 1)} type="button">Next <ChevronRight size={14} /></button>
        </nav>
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/inventory/windows_updates`}>History &amp; changes <ChevronRight size={14} /></Link>
      </footer>
    </section>
  );
}
