// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowLeft, CalendarClock, Send, ShieldCheck, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";

import { clockSnapshot, subscribeToClock } from "@/lib/dashboard-clock";

import {
  commandKindDefinitions,
  commandKindDefinitionsForPermission,
  eventLogChannelTier,
  ttlOptions,
  validateDispatchInput,
  EVENT_LOG_CHANNELS,
  type CommandKind,
  type DispatchInput,
} from "@/lib/command-console-core";
import {
  formatDurationSeconds,
  isMaintenanceWindowErrorCode,
  maintenanceWindowPromptHref,
  powerWindowCoverage,
  type MaintenanceTarget,
  type MaintenanceWindow,
} from "@/lib/maintenance-windows-core";
import { formatMonitoringTimestamp } from "@/lib/monitoring-core";

type DispatchFormProps = {
  endpointId: string;
  hostname: string;
  canExecuteScripts: boolean;
  isAdmin: boolean;
  /** Null when the window inventory could not be verified; coverage is then
   * left entirely to the server rather than guessed at here. */
  maintenanceWindows: MaintenanceWindow[] | null;
  maintenanceTarget: MaintenanceTarget;
  serverNowMs: number;
};

type Step =
  | { name: "compose" }
  | { name: "confirm"; input: DispatchInput }
  | { name: "dispatched"; commandId: string };

export function CommandDispatchForm({
  endpointId,
  hostname,
  canExecuteScripts,
  isAdmin,
  maintenanceWindows,
  maintenanceTarget,
  serverNowMs,
}: DispatchFormProps) {
  const router = useRouter();
  const [kind, setKind] = useState<CommandKind>(
    canExecuteScripts ? "powershell" : "collect_inventory",
  );
  const [script, setScript] = useState("");
  const [updateTargets, setUpdateTargets] = useState("");
  const [installAll, setInstallAll] = useState(false);
  const [targetPath, setTargetPath] = useState("");
  const [expectedDigest, setExpectedDigest] = useState("");
  const [uploadContent, setUploadContent] = useState("");
  const [uploadDigest, setUploadDigest] = useState("");
  const [uploadName, setUploadName] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [registryHive, setRegistryHive] = useState<"HKLM" | "HKCU">("HKLM");
  const [registryKey, setRegistryKey] = useState("Software\\NodeLink\\Managed");
  const [registryValueName, setRegistryValueName] = useState("");
  const [registryView, setRegistryView] = useState<32 | 64>(64);
  const [registryType, setRegistryType] = useState("string");
  const [registryData, setRegistryData] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [backupId, setBackupId] = useState("");
  const [powerReason, setPowerReason] = useState("");
  const [powerDelaySeconds, setPowerDelaySeconds] = useState(60);
  const [userConsent, setUserConsent] = useState<"confirmed" | "no_user_session">("confirmed");
  const [powerConfirmation, setPowerConfirmation] = useState("");
  const [eventChannel, setEventChannel] = useState<string>("System");
  const [eventTierAck, setEventTierAck] = useState(false);
  const [eventWindowSeconds, setEventWindowSeconds] = useState(3600);
  const [eventMaxEvents, setEventMaxEvents] = useState(100);
  const [eventProviders, setEventProviders] = useState("");
  const [eventLevels, setEventLevels] = useState("");
  const [eventIds, setEventIds] = useState("");
  const [eventCursor, setEventCursor] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(300);
  const [step, setStep] = useState<Step>({ name: "compose" });
  const [error, setError] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  // Server-rendered instant during hydration, then the live clock: coverage is
  // time-sensitive and a stale "covered" reading would mislead.
  const nowMs = useSyncExternalStore(subscribeToClock, clockSnapshot, () => serverNowMs);

  const isPowerAction = kind === "reboot" || kind === "shutdown";
  const coverage = maintenanceWindows && isPowerAction
    ? powerWindowCoverage(maintenanceWindows, maintenanceTarget, powerDelaySeconds, nowMs)
    : null;
  const windowHref = maintenanceWindowPromptHref({
    endpointId,
    hostname,
    delaySeconds: isPowerAction ? powerDelaySeconds : null,
    returnPath: `/endpoints/${encodeURIComponent(endpointId)}/commands`,
  });

  function CoverageNotice() {
    if (!isPowerAction) return null;
    if (coverage === null) {
      return (
        <div className="power-window-notice unknown" role="status">
          <TriangleAlert aria-hidden="true" size={16} />
          <div>
            <strong>Maintenance window coverage is unverified</strong>
            <span>
              The window inventory could not be read, so coverage is unknown here. The server still
              refuses the dispatch unless a window covers this endpoint.
            </span>
          </div>
          <MaintenanceWindowLink label="Manage windows" />
        </div>
      );
    }
    if (coverage.status === "no_window") {
      return (
        <div className="power-window-notice blocked" role="status">
          <TriangleAlert aria-hidden="true" size={16} />
          <div>
            <strong>No maintenance window covers this endpoint</strong>
            <span>
              The server will refuse this restart or shutdown. Open a window covering{" "}
              {hostname} for at least {formatDurationSeconds(powerDelaySeconds)}, then confirm again.
            </span>
          </div>
          <MaintenanceWindowLink label="Create a window" />
        </div>
      );
    }
    if (coverage.status === "delay_exceeds_window") {
      return (
        <div className="power-window-notice blocked" role="status">
          <TriangleAlert aria-hidden="true" size={16} />
          <div>
            <strong>The delay outlives the covering window</strong>
            <span>
              {coverage.window.name} closes at {formatMonitoringTimestamp(coverage.window.ends_at)} —
              in {formatDurationSeconds(coverage.secondsRemaining)}, less than the{" "}
              {formatDurationSeconds(powerDelaySeconds)} delay. Shorten the delay or open a longer window.
            </span>
          </div>
          <MaintenanceWindowLink label="Extend coverage" />
        </div>
      );
    }
    return (
      <div className="power-window-notice covered" role="status">
        <ShieldCheck aria-hidden="true" size={16} />
        <div>
          <strong>Covered by {coverage.window.name}</strong>
          <span>
            The window closes at {formatMonitoringTimestamp(coverage.window.ends_at)}, in{" "}
            {formatDurationSeconds(coverage.secondsRemaining)}. The server re-checks coverage when
            it signs the command.
          </span>
        </div>
        <MaintenanceWindowLink label="Manage windows" />
      </div>
    );
  }

  function DispatchError() {
    if (!error) return null;
    return (
      <p className="dispatch-error" role="alert">
        {error}
        {isMaintenanceWindowErrorCode(errorCode) ? (
          <>
            {" "}
            <MaintenanceWindowLink label="Open the maintenance-window workflow" />
          </>
        ) : null}
      </p>
    );
  }

  function MaintenanceWindowLink({ label }: { label: string }) {
    // Opened in a new tab so the reviewed command, its typed confirmation, and
    // its reason survive the detour to create the window.
    return (
      <Link className="power-window-link" href={windowHref} rel="noopener" target="_blank">
        <CalendarClock aria-hidden="true" size={14} /> {label}
      </Link>
    );
  }

  const definition = commandKindDefinitions.find((d) => d.kind === kind)!;
  const availableDefinitions =
    commandKindDefinitionsForPermission(canExecuteScripts, isAdmin)
      .filter((item) => item.kind !== "install_updates");

  function operationPayload(): Record<string, unknown> | undefined {
    if (kind === "reboot" || kind === "shutdown") {
      return {
        confirm: powerConfirmation === hostname,
        reason: powerReason.trim(),
        delay_seconds: powerDelaySeconds,
        user_consent: userConsent,
      };
    }
    if (kind === "cancel_power_action") {
      return { confirm: powerConfirmation === hostname, reason: powerReason.trim() };
    }
    if (kind === "file_upload") {
      return { path: targetPath.trim(), content_base64: uploadContent, sha256: uploadDigest, overwrite };
    }
    if (kind === "file_download") {
      return { path: targetPath.trim(), ...(expectedDigest.trim() ? { expected_sha256: expectedDigest.trim().toLowerCase() } : {}) };
    }
    if (kind === "remediation_rollback") return { backup_id: backupId.trim().toLowerCase() };
    if (kind === "query_event_log") {
      const toIntList = (raw: string) =>
        raw.split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean).map(Number);
      const providers = eventProviders.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      const levels = toIntList(eventLevels);
      const ids = toIntList(eventIds);
      const cursorRaw = eventCursor.trim();
      return {
        channel: eventChannel,
        ...(eventLogChannelTier(eventChannel) === "elevated" ? { tier_ack: eventTierAck } : {}),
        time_window_seconds: eventWindowSeconds,
        max_events: eventMaxEvents,
        ...(providers.length ? { providers } : {}),
        ...(levels.length ? { levels } : {}),
        ...(ids.length ? { event_ids: ids } : {}),
        ...(cursorRaw ? { cursor: Number(cursorRaw) } : {}),
      };
    }
    if (["registry_read", "registry_write", "registry_delete"].includes(kind)) {
      const base: Record<string, unknown> = {
        hive: registryHive,
        key: registryKey.trim(),
        value_name: registryValueName.trim(),
        view: registryView,
      };
      if (kind === "registry_read") return base;
      if (expectedDigest.trim()) base.expected_current_sha256 = expectedDigest.trim().toLowerCase();
      if (kind === "registry_delete") return { ...base, confirm: confirmDelete };
      let data: unknown = registryData;
      if (registryType === "dword" || registryType === "qword") data = Number(registryData);
      if (registryType === "multi_string") data = registryData.split(/\r?\n/).filter(Boolean);
      return { ...base, type: registryType, data };
    }
    return undefined;
  }

  async function loadUpload(file: File | undefined) {
    setError("");
    setUploadContent("");
    setUploadDigest("");
    setUploadName(file?.name ?? "");
    if (!file) return;
    if (file.size > 32 * 1024) {
      setError("Managed uploads are limited to 32 KiB.");
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      setUploadDigest(Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""));
      setUploadContent(btoa(String.fromCharCode(...bytes)));
    } catch {
      setError("The selected file could not be read and hashed.");
    }
  }

  function handleReview() {
    setError("");
    setErrorCode(null);
    const input = validateDispatchInput({
      kind,
      script,
      update_targets: updateTargets,
      install_all: installAll,
      ttl_seconds: ttlSeconds,
      operation_payload: operationPayload(),
    });
    if (!input) {
      setError(
        definition.input === "script"
          ? "Enter a script within the size limit before dispatching."
            : definition.input === "update_targets"
              ? "Enter valid KB or Windows Update IDs, or explicitly choose Install all applicable updates."
            : definition.input === "none"
              ? "This typed operation does not accept additional input."
              : definition.input === "power_action"
                ? `Enter a reason, delay and consent policy, then type ${hostname} exactly.`
                : definition.input === "power_cancel"
                  ? `Enter a cancellation reason and type ${hostname} exactly.`
                : definition.input === "event_log_query"
                  ? "Choose an allowlisted channel, a time window and event cap; acknowledge the elevated tier for Security or Defender. Provider, level (1-5), and event-ID filters are optional."
              : "Enter a valid managed path, registry location/value, digest, or backup ID for this operation.",
      );
      return;
    }
    setStep({ name: "confirm", input });
  }

  async function handleConfirm(input: DispatchInput) {
    setError("");
    setErrorCode(null);
    setIsSubmitting(true);
    try {
      const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/commands`, {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as
        | { command?: { id: string }; error?: string; code?: string }
        | null;
      if (response.ok && body?.command?.id) {
        setStep({ name: "dispatched", commandId: body.command.id });
        setScript("");
        setUpdateTargets("");
        setInstallAll(false);
        setUploadContent("");
        setUploadDigest("");
        setUploadName("");
        setRegistryData("");
        router.refresh();
      } else {
        setError(body?.error ?? "The command could not be dispatched. Try again.");
        setErrorCode(isMaintenanceWindowErrorCode(body?.code) ? body.code : null);
        setStep({ name: "compose" });
      }
    } catch {
      setError("The command could not be dispatched. Try again.");
      setStep({ name: "compose" });
    }
    setIsSubmitting(false);
  }

  if (step.name === "dispatched") {
    return (
      <div className="dispatch-confirmation" role="status">
        <ShieldCheck size={18} />
        <div>
          <strong>Command signed and queued</strong>
          <span>
            The agent will pick it up at its next check-in.{" "}
            <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(step.commandId)}`}>
              Follow this command
            </Link>
          </span>
        </div>
        <button onClick={() => setStep({ name: "compose" })} type="button">Dispatch another</button>
      </div>
    );
  }

  if (step.name === "confirm") {
    const ttlLabel = ttlOptions.find((option) => option.seconds === step.input.ttl_seconds)?.label
      ?? `${step.input.ttl_seconds} seconds`;
    return (
      <div className="dispatch-review" role="region" aria-label="Confirm command dispatch">
        <p>
          Review before dispatch. This will sign and queue a{" "}
          <strong>{commandKindDefinitions.find((d) => d.kind === step.input.kind)?.label}</strong>{" "}
          command for <strong>{hostname}</strong>, valid for <strong>{ttlLabel}</strong>.
          {step.input.kind === "reboot" || step.input.kind === "shutdown"
            ? " The delayed OS action can be cancelled with a separate Cancel pending power action command."
            : " An unpicked command dies at its signed expiry."}
        </p>
        {step.input.script ? <pre>{step.input.script}</pre> : step.input.kind === "install_updates" ? (
          <pre>
            {step.input.install_all
              ? "All applicable non-hidden updates"
              : step.input.update_targets.join("\n")}
          </pre>
        ) : step.input.operation_payload ? (
          <pre>{JSON.stringify({
            ...step.input.operation_payload,
            ...(step.input.kind === "file_upload" ? { content_base64: `[${uploadName || "file"}; ${Math.floor(uploadContent.length * 0.75)} bytes]` } : {}),
            ...(step.input.kind === "registry_write" ? { data: "[value withheld from confirmation transcript]" } : {}),
          }, null, 2)}</pre>
        ) : (
          <p className="dispatch-noscript">No script payload — this is a bounded typed operation.</p>
        )}
        {step.input.kind === "reboot" || step.input.kind === "shutdown" ? <CoverageNotice /> : null}
        <div className="dispatch-review-actions">
          <button disabled={isSubmitting} onClick={() => setStep({ name: "compose" })} type="button">
            <ArrowLeft size={15} /> Edit
          </button>
          <button className="danger" disabled={isSubmitting} onClick={() => handleConfirm(step.input)} type="button">
            <Send size={15} /> {isSubmitting ? "Dispatching…" : "Confirm dispatch"}
          </button>
        </div>
        <DispatchError />
      </div>
    );
  }

  return (
    <form
      className="dispatch-form"
      onSubmit={(event) => {
        event.preventDefault();
        handleReview();
      }}
    >
      <div className="dispatch-fields">
        <label htmlFor="command-kind">Command kind</label>
        <select
          id="command-kind"
          onChange={(event) => {
            setKind(event.target.value as CommandKind);
            setScript("");
            setUpdateTargets("");
            setInstallAll(false);
            setTargetPath("");
            setExpectedDigest("");
            setUploadContent("");
            setUploadDigest("");
            setUploadName("");
            setOverwrite(false);
            setRegistryData("");
            setConfirmDelete(false);
            setBackupId("");
            setPowerReason("");
            setPowerDelaySeconds(60);
            setUserConsent("confirmed");
            setPowerConfirmation("");
            setEventChannel("System");
            setEventTierAck(false);
            setEventWindowSeconds(3600);
            setEventMaxEvents(100);
            setEventProviders("");
            setEventLevels("");
            setEventIds("");
            setEventCursor("");
          }}
          value={kind}
        >
          {availableDefinitions.map((d) => (
            <option key={d.kind} value={d.kind}>{d.label}</option>
          ))}
        </select>
        <label htmlFor="command-ttl">Valid for</label>
        <select
          id="command-ttl"
          onChange={(event) => setTtlSeconds(Number(event.target.value))}
          value={ttlSeconds}
        >
          {ttlOptions.map((option) => (
            <option key={option.seconds} value={option.seconds}>{option.label}</option>
          ))}
        </select>
      </div>
      <p className="dispatch-kind-note">{definition.description}</p>
      {definition.adminOnly ? (
        <div className="remediation-policy-band" role="note">
          <ShieldCheck size={16} />
          <div>
            <strong>Managed boundary</strong>
            <span>
              {definition.input.startsWith("file_")
                ? "Only C:\\ProgramData\\NodeLink\\Managed and C:\\Windows\\Temp\\NodeLink."
                : definition.input.startsWith("registry_")
                  ? "Only HKLM/HKCU Software\\NodeLink\\Managed in the selected registry view."
                  : definition.input.startsWith("power_")
                    ? "Administrator only. Restart and shutdown also require an active maintenance window and an explicit user-session policy."
                  : definition.input === "event_log_query"
                    ? "Administrator only. Bounded to allowlisted channels; Security and Defender need elevated-tier acknowledgment. Results are metadata-only — no message text ever leaves the endpoint."
                  : "The backup must exist in this endpoint's local NodeLink rollback journal."}
            </span>
          </div>
        </div>
      ) : null}
      {definition.input === "script" ? (
        <>
          <label htmlFor="command-script">Script</label>
          <textarea
            id="command-script"
            onChange={(event) => setScript(event.target.value)}
            placeholder={kind === "powershell" ? "Get-Service | Where-Object Status -eq 'Stopped'" : "systeminfo"}
            rows={6}
            spellCheck={false}
            value={script}
          />
        </>
      ) : definition.input === "update_targets" ? (
        <>
          <label htmlFor="update-targets">KB or Windows Update IDs</label>
          <textarea
            disabled={installAll}
            id="update-targets"
            onChange={(event) => setUpdateTargets(event.target.value)}
            placeholder={"KB5101650\n12345678-1234-1234-1234-1234567890ab"}
            rows={5}
            spellCheck={false}
            value={updateTargets}
          />
          <label className="dispatch-checkbox" htmlFor="install-all-updates">
            <input
              checked={installAll}
              id="install-all-updates"
              onChange={(event) => {
                setInstallAll(event.target.checked);
                if (event.target.checked) setUpdateTargets("");
              }}
              type="checkbox"
            />
            Install all applicable non-hidden updates
          </label>
          <p className="dispatch-kind-note">
            Use the Update ID shown in Windows Updates inventory for drivers or firmware that do not have a KB number.
          </p>
        </>
      ) : definition.input === "file_upload" ? (
        <>
          <label htmlFor="managed-upload-path">Managed destination path</label>
          <input id="managed-upload-path" onChange={(event) => setTargetPath(event.target.value)} placeholder="C:\\ProgramData\\NodeLink\\Managed\\patch.bin" value={targetPath} />
          <label htmlFor="managed-upload-file">File (32 KiB maximum)</label>
          <input id="managed-upload-file" onChange={(event) => void loadUpload(event.target.files?.[0])} type="file" />
          {uploadDigest ? <p className="dispatch-kind-note">SHA-256 <code>{uploadDigest}</code></p> : null}
          <label className="dispatch-checkbox" htmlFor="managed-upload-overwrite">
            <input checked={overwrite} id="managed-upload-overwrite" onChange={(event) => setOverwrite(event.target.checked)} type="checkbox" />
            Replace an existing file after creating rollback metadata
          </label>
        </>
      ) : definition.input === "file_download" ? (
        <>
          <label htmlFor="managed-download-path">Managed source path</label>
          <input id="managed-download-path" onChange={(event) => setTargetPath(event.target.value)} placeholder="C:\\ProgramData\\NodeLink\\Managed\\diagnostic.txt" value={targetPath} />
          <label htmlFor="managed-download-digest">Expected SHA-256 (optional)</label>
          <input id="managed-download-digest" onChange={(event) => setExpectedDigest(event.target.value)} placeholder="64 lowercase hexadecimal characters" value={expectedDigest} />
        </>
      ) : ["registry_read", "registry_write", "registry_delete"].includes(definition.input) ? (
        <>
          <div className="dispatch-fields">
            <label htmlFor="registry-hive">Hive</label>
            <select id="registry-hive" onChange={(event) => setRegistryHive(event.target.value as "HKLM" | "HKCU")} value={registryHive}><option>HKLM</option><option>HKCU</option></select>
            <label htmlFor="registry-view">Registry view</label>
            <select id="registry-view" onChange={(event) => setRegistryView(Number(event.target.value) as 32 | 64)} value={registryView}><option value={64}>64-bit</option><option value={32}>32-bit</option></select>
          </div>
          <label htmlFor="registry-key">Managed key</label>
          <input id="registry-key" onChange={(event) => setRegistryKey(event.target.value)} value={registryKey} />
          <label htmlFor="registry-value-name">Value name</label>
          <input id="registry-value-name" onChange={(event) => setRegistryValueName(event.target.value)} value={registryValueName} />
          {definition.input === "registry_write" ? (
            <>
              <label htmlFor="registry-type">Value type</label>
              <select id="registry-type" onChange={(event) => setRegistryType(event.target.value)} value={registryType}>
                <option value="string">String</option><option value="expand_string">Expandable string</option><option value="dword">DWORD</option><option value="qword">QWORD</option><option value="multi_string">Multi-string (one per line)</option><option value="binary">Binary (base64)</option>
              </select>
              <label htmlFor="registry-data">Value data</label>
              <textarea id="registry-data" onChange={(event) => setRegistryData(event.target.value)} rows={4} value={registryData} />
            </>
          ) : null}
          {definition.input !== "registry_read" ? (
            <>
              <label htmlFor="registry-expected-digest">Current-value SHA-256 (optional compare-and-set)</label>
              <input id="registry-expected-digest" onChange={(event) => setExpectedDigest(event.target.value)} value={expectedDigest} />
            </>
          ) : null}
          {definition.input === "registry_delete" ? (
            <label className="dispatch-checkbox" htmlFor="registry-delete-confirm"><input checked={confirmDelete} id="registry-delete-confirm" onChange={(event) => setConfirmDelete(event.target.checked)} type="checkbox" />Confirm deletion of exactly this value</label>
          ) : null}
        </>
      ) : definition.input === "rollback" ? (
        <>
          <label htmlFor="remediation-backup-id">Endpoint-local backup ID</label>
          <input id="remediation-backup-id" onChange={(event) => setBackupId(event.target.value)} placeholder="32 lowercase hexadecimal characters" value={backupId} />
        </>
      ) : definition.input === "power_action" || definition.input === "power_cancel" ? (
        <>
          <div className="power-operation-band" role="note">
            <ShieldCheck aria-hidden="true" size={18} />
            <div>
              <strong>{definition.input === "power_action" ? "Disruptive endpoint action" : "Safety-preserving cancellation"}</strong>
              <span>
                {definition.input === "power_action"
                  ? "The server verifies the maintenance window and latest user-session evidence before signing."
                  : "Cancellation is allowed without a maintenance window and is safe when no action is pending."}
              </span>
            </div>
          </div>
          <label htmlFor="power-reason">Operational reason</label>
          <textarea
            id="power-reason"
            maxLength={512}
            minLength={10}
            onChange={(event) => setPowerReason(event.target.value)}
            placeholder={definition.input === "power_action" ? "Approved maintenance ticket and expected impact" : "Why the pending action must be cancelled"}
            required
            rows={3}
            value={powerReason}
          />
          {definition.input === "power_action" ? (
            <div className="dispatch-fields">
              <label htmlFor="power-delay">Delay before action</label>
              <select id="power-delay" onChange={(event) => setPowerDelaySeconds(Number(event.target.value))} value={powerDelaySeconds}>
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={300}>5 minutes</option>
                <option value={900}>15 minutes</option>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
              </select>
              <label htmlFor="power-consent">User-session policy</label>
              <select id="power-consent" onChange={(event) => setUserConsent(event.target.value as "confirmed" | "no_user_session")} value={userConsent}>
                <option value="confirmed">User consent confirmed</option>
                <option value="no_user_session">Proceed only with no signed-in user</option>
              </select>
            </div>
          ) : null}
          {definition.input === "power_action" ? <CoverageNotice /> : null}
          <label htmlFor="power-confirmation">Type <code>{hostname}</code> to confirm</label>
          <input
            autoComplete="off"
            id="power-confirmation"
            onChange={(event) => setPowerConfirmation(event.target.value)}
            spellCheck={false}
            value={powerConfirmation}
          />
        </>
      ) : definition.input === "event_log_query" ? (
        <>
          <div className="dispatch-fields">
            <label htmlFor="event-channel">Channel</label>
            <select
              id="event-channel"
              onChange={(event) => {
                setEventChannel(event.target.value);
                setEventTierAck(false);
              }}
              value={eventChannel}
            >
              {EVENT_LOG_CHANNELS.map((channel) => (
                <option key={channel} value={channel}>{channel}</option>
              ))}
            </select>
            <label htmlFor="event-window">Time window</label>
            <select id="event-window" onChange={(event) => setEventWindowSeconds(Number(event.target.value))} value={eventWindowSeconds}>
              <option value={3600}>Last hour</option>
              <option value={21600}>Last 6 hours</option>
              <option value={86400}>Last 24 hours</option>
              <option value={604800}>Last 7 days</option>
            </select>
            <label htmlFor="event-max">Maximum events</label>
            <select id="event-max" onChange={(event) => setEventMaxEvents(Number(event.target.value))} value={eventMaxEvents}>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </div>
          {eventLogChannelTier(eventChannel) === "elevated" ? (
            <label className="dispatch-checkbox" htmlFor="event-tier-ack">
              <input checked={eventTierAck} id="event-tier-ack" onChange={(event) => setEventTierAck(event.target.checked)} type="checkbox" />
              I acknowledge this is an elevated-tier channel (audited separately).
            </label>
          ) : null}
          <label htmlFor="event-providers">Providers (optional, one per line)</label>
          <textarea id="event-providers" onChange={(event) => setEventProviders(event.target.value)} placeholder={"Microsoft-Windows-Security-Auditing"} rows={2} spellCheck={false} value={eventProviders} />
          <div className="dispatch-fields">
            <label htmlFor="event-levels">Levels (optional, 1-5)</label>
            <input id="event-levels" onChange={(event) => setEventLevels(event.target.value)} placeholder="2, 3" value={eventLevels} />
            <label htmlFor="event-ids">Event IDs (optional)</label>
            <input id="event-ids" onChange={(event) => setEventIds(event.target.value)} placeholder="4624, 4625" value={eventIds} />
          </div>
          <label htmlFor="event-cursor">Continue from cursor (optional)</label>
          <input id="event-cursor" inputMode="numeric" onChange={(event) => setEventCursor(event.target.value)} placeholder="next_cursor from a prior page" value={eventCursor} />
        </>
      ) : null}
      <DispatchError />
      <button type="submit">Review dispatch</button>
    </form>
  );
}
