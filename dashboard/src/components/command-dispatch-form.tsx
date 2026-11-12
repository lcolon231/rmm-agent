// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowLeft, CalendarClock, Send, ShieldCheck } from "lucide-react";
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

import { inlineLink, Notice } from "./endpoint/section-header";
import { Button } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { CodeBlock } from "./ui/drawer";
import { Input, Select, Textarea } from "./ui/field";

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
        <Notice tone="warn" title="Maintenance window coverage is unverified" action={<MaintenanceWindowLink label="Manage windows" />}>
          The window inventory could not be read, so coverage is unknown here. The server still
          refuses the dispatch unless a window covers this endpoint.
        </Notice>
      );
    }
    if (coverage.status === "no_window") {
      return (
        <Notice tone="crit" title="No maintenance window covers this endpoint" action={<MaintenanceWindowLink label="Create a window" />}>
          The server will refuse this restart or shutdown. Open a window covering{" "}
          {hostname} for at least {formatDurationSeconds(powerDelaySeconds)}, then confirm again.
        </Notice>
      );
    }
    if (coverage.status === "delay_exceeds_window") {
      return (
        <Notice tone="crit" title="The delay outlives the covering window" action={<MaintenanceWindowLink label="Extend coverage" />}>
          {coverage.window.name} closes at {formatMonitoringTimestamp(coverage.window.ends_at)} —
          in {formatDurationSeconds(coverage.secondsRemaining)}, less than the{" "}
          {formatDurationSeconds(powerDelaySeconds)} delay. Shorten the delay or open a longer window.
        </Notice>
      );
    }
    return (
      <Notice tone="ok" icon={ShieldCheck} title={`Covered by ${coverage.window.name}`} action={<MaintenanceWindowLink label="Manage windows" />}>
        The window closes at {formatMonitoringTimestamp(coverage.window.ends_at)}, in{" "}
        {formatDurationSeconds(coverage.secondsRemaining)}. The server re-checks coverage when
        it signs the command.
      </Notice>
    );
  }

  function DispatchError() {
    if (!error) return null;
    return (
      <p className="m-0 rounded-lg bg-(--red-soft) px-4 py-3 text-sm font-semibold text-(--red)" role="alert">
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
      <Link className={cx("inline-flex items-center gap-1 text-sm", inlineLink)} href={windowHref} rel="noopener" target="_blank">
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
      <Notice
        tone="ok"
        icon={ShieldCheck}
        title="Command signed and queued"
        action={<Button size="compact" onClick={() => setStep({ name: "compose" })}>Dispatch another</Button>}
      >
        The agent will pick it up at its next check-in.{" "}
        <Link className={inlineLink} href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(step.commandId)}`}>
          Follow this command
        </Link>
      </Notice>
    );
  }

  if (step.name === "confirm") {
    const ttlLabel = ttlOptions.find((option) => option.seconds === step.input.ttl_seconds)?.label
      ?? `${step.input.ttl_seconds} seconds`;
    return (
      <div className="grid gap-4 rounded-[10px] border border-(--line-strong) bg-(--fog) p-4" role="region" aria-label="Confirm command dispatch">
        <p className="m-0 text-sm text-(--slate)">
          Review before dispatch. This will sign and queue a{" "}
          <strong className="text-(--ink)">{commandKindDefinitions.find((d) => d.kind === step.input.kind)?.label}</strong>{" "}
          command for <strong className="font-(family-name:--font-data) text-(--ink)">{hostname}</strong>, valid for <strong className="text-(--ink)">{ttlLabel}</strong>.
          {step.input.kind === "reboot" || step.input.kind === "shutdown"
            ? " The delayed OS action can be cancelled with a separate Cancel pending power action command."
            : " An unpicked command dies at its signed expiry."}
        </p>
        {step.input.script ? <CodeBlock label="Script to sign">{step.input.script}</CodeBlock> : step.input.kind === "install_updates" ? (
          <CodeBlock label="Updates to install">
            {step.input.install_all
              ? "All applicable non-hidden updates"
              : step.input.update_targets.join("\n")}
          </CodeBlock>
        ) : step.input.operation_payload ? (
          <CodeBlock label="Operation to sign">{JSON.stringify({
            ...step.input.operation_payload,
            ...(step.input.kind === "file_upload" ? { content_base64: `[${uploadName || "file"}; ${Math.floor(uploadContent.length * 0.75)} bytes]` } : {}),
            ...(step.input.kind === "registry_write" ? { data: "[value withheld from confirmation transcript]" } : {}),
          }, null, 2)}</CodeBlock>
        ) : (
          <p className="m-0 text-sm text-(--muted)">No script payload — this is a bounded typed operation.</p>
        )}
        {step.input.kind === "reboot" || step.input.kind === "shutdown" ? <CoverageNotice /> : null}
        <div className="flex flex-wrap gap-2">
          <Button disabled={isSubmitting} icon={ArrowLeft} onClick={() => setStep({ name: "compose" })}>
            Edit
          </Button>
          <Button variant="primary" disabled={isSubmitting} icon={Send} onClick={() => handleConfirm(step.input)}>
            {isSubmitting ? "Dispatching…" : "Confirm dispatch"}
          </Button>
        </div>
        <DispatchError />
      </div>
    );
  }

  return (
    <form
      className="grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        handleReview();
      }}
    >
      <div className={fieldRow}>
        <Select
          id="command-kind"
          label="Command kind"
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
        </Select>
        <Select
          id="command-ttl"
          label="Valid for"
          onChange={(event) => setTtlSeconds(Number(event.target.value))}
          value={ttlSeconds}
        >
          {ttlOptions.map((option) => (
            <option key={option.seconds} value={option.seconds}>{option.label}</option>
          ))}
        </Select>
      </div>
      <p className={hintText}>{definition.description}</p>
      {definition.adminOnly ? (
        <Notice tone="info" icon={ShieldCheck} role="note" title="Managed boundary">
          {definition.input.startsWith("file_")
            ? "Only C:\\ProgramData\\NodeLink\\Managed and C:\\Windows\\Temp\\NodeLink."
            : definition.input.startsWith("registry_")
              ? "Only HKLM/HKCU Software\\NodeLink\\Managed in the selected registry view."
              : definition.input.startsWith("power_")
                ? "Administrator only. Restart and shutdown also require an active maintenance window and an explicit user-session policy."
              : definition.input === "event_log_query"
                ? "Administrator only. Bounded to allowlisted channels; Security and Defender need elevated-tier acknowledgment. Results are metadata-only — no message text ever leaves the endpoint."
              : "The backup must exist in this endpoint's local NodeLink rollback journal."}
        </Notice>
      ) : null}
      {definition.input === "script" ? (
        <Textarea
          className={monoField}
          id="command-script"
          label="Script"
          onChange={(event) => setScript(event.target.value)}
          placeholder={kind === "powershell" ? "Get-Service | Where-Object Status -eq 'Stopped'" : "systeminfo"}
          rows={6}
          spellCheck={false}
          value={script}
        />
      ) : definition.input === "update_targets" ? (
        <>
          <Textarea
            className={monoField}
            disabled={installAll}
            id="update-targets"
            label="KB or Windows Update IDs"
            onChange={(event) => setUpdateTargets(event.target.value)}
            placeholder={"KB5101650\n12345678-1234-1234-1234-1234567890ab"}
            rows={5}
            spellCheck={false}
            value={updateTargets}
          />
          <Check
            checked={installAll}
            id="install-all-updates"
            label="Install all applicable non-hidden updates"
            onChange={(checked) => {
              setInstallAll(checked);
              if (checked) setUpdateTargets("");
            }}
          />
          <p className={hintText}>
            Use the Update ID shown in Windows Updates inventory for drivers or firmware that do not have a KB number.
          </p>
        </>
      ) : definition.input === "file_upload" ? (
        <>
          <Input className={monoField} id="managed-upload-path" label="Managed destination path" onChange={(event) => setTargetPath(event.target.value)} placeholder="C:\\ProgramData\\NodeLink\\Managed\\patch.bin" value={targetPath} />
          <Input className="py-2" id="managed-upload-file" label="File (32 KiB maximum)" onChange={(event) => void loadUpload(event.target.files?.[0])} type="file" />
          {uploadDigest ? <p className={hintText}>Fingerprint (SHA-256) <code className="font-(family-name:--font-data) break-all">{uploadDigest}</code></p> : null}
          <Check checked={overwrite} id="managed-upload-overwrite" label="Replace an existing file after creating rollback metadata" onChange={setOverwrite} />
        </>
      ) : definition.input === "file_download" ? (
        <>
          <Input className={monoField} id="managed-download-path" label="Managed source path" onChange={(event) => setTargetPath(event.target.value)} placeholder="C:\\ProgramData\\NodeLink\\Managed\\diagnostic.txt" value={targetPath} />
          <Input className={monoField} id="managed-download-digest" label="Expected SHA-256 (optional)" onChange={(event) => setExpectedDigest(event.target.value)} placeholder="64 lowercase hexadecimal characters" value={expectedDigest} />
        </>
      ) : ["registry_read", "registry_write", "registry_delete"].includes(definition.input) ? (
        <>
          <div className={fieldRow}>
            <Select id="registry-hive" label="Hive" onChange={(event) => setRegistryHive(event.target.value as "HKLM" | "HKCU")} value={registryHive}><option>HKLM</option><option>HKCU</option></Select>
            <Select id="registry-view" label="Registry view" onChange={(event) => setRegistryView(Number(event.target.value) as 32 | 64)} value={registryView}><option value={64}>64-bit</option><option value={32}>32-bit</option></Select>
          </div>
          <Input className={monoField} id="registry-key" label="Managed key" onChange={(event) => setRegistryKey(event.target.value)} value={registryKey} />
          <Input className={monoField} id="registry-value-name" label="Value name" onChange={(event) => setRegistryValueName(event.target.value)} value={registryValueName} />
          {definition.input === "registry_write" ? (
            <>
              <Select id="registry-type" label="Value type" onChange={(event) => setRegistryType(event.target.value)} value={registryType}>
                <option value="string">String</option><option value="expand_string">Expandable string</option><option value="dword">DWORD</option><option value="qword">QWORD</option><option value="multi_string">Multi-string (one per line)</option><option value="binary">Binary (base64)</option>
              </Select>
              <Textarea className={monoField} id="registry-data" label="Value data" onChange={(event) => setRegistryData(event.target.value)} rows={4} value={registryData} />
            </>
          ) : null}
          {definition.input !== "registry_read" ? (
            <Input className={monoField} id="registry-expected-digest" label="Current-value SHA-256 (optional compare-and-set)" onChange={(event) => setExpectedDigest(event.target.value)} value={expectedDigest} />
          ) : null}
          {definition.input === "registry_delete" ? (
            <Check checked={confirmDelete} id="registry-delete-confirm" label="Confirm deletion of exactly this value" onChange={setConfirmDelete} />
          ) : null}
        </>
      ) : definition.input === "rollback" ? (
        <Input className={monoField} id="remediation-backup-id" label="Endpoint-local backup ID" onChange={(event) => setBackupId(event.target.value)} placeholder="32 lowercase hexadecimal characters" value={backupId} />
      ) : definition.input === "power_action" || definition.input === "power_cancel" ? (
        <>
          <Notice
            tone={definition.input === "power_action" ? "warn" : "info"}
            icon={ShieldCheck}
            role="note"
            title={definition.input === "power_action" ? "Disruptive endpoint action" : "Safety-preserving cancellation"}
          >
            {definition.input === "power_action"
              ? "The server verifies the maintenance window and latest user-session evidence before signing."
              : "Cancellation is allowed without a maintenance window and is safe when no action is pending."}
          </Notice>
          <Textarea
            id="power-reason"
            label="Operational reason"
            maxLength={512}
            minLength={10}
            onChange={(event) => setPowerReason(event.target.value)}
            placeholder={definition.input === "power_action" ? "Approved maintenance ticket and expected impact" : "Why the pending action must be cancelled"}
            required
            rows={3}
            value={powerReason}
          />
          {definition.input === "power_action" ? (
            <div className={fieldRow}>
              <Select id="power-delay" label="Delay before action" onChange={(event) => setPowerDelaySeconds(Number(event.target.value))} value={powerDelaySeconds}>
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={300}>5 minutes</option>
                <option value={900}>15 minutes</option>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
              </Select>
              <Select id="power-consent" label="User-session policy" onChange={(event) => setUserConsent(event.target.value as "confirmed" | "no_user_session")} value={userConsent}>
                <option value="confirmed">User consent confirmed</option>
                <option value="no_user_session">Proceed only with no signed-in user</option>
              </Select>
            </div>
          ) : null}
          {definition.input === "power_action" ? <CoverageNotice /> : null}
          <div className="grid gap-1.5">
            <label className={labelText} htmlFor="power-confirmation">Type <code className="font-(family-name:--font-data) text-(--ink)">{hostname}</code> to confirm</label>
            <input
              autoComplete="off"
              className={cx(plainControl, monoField)}
              id="power-confirmation"
              onChange={(event) => setPowerConfirmation(event.target.value)}
              spellCheck={false}
              value={powerConfirmation}
            />
          </div>
        </>
      ) : definition.input === "event_log_query" ? (
        <>
          <div className={fieldRow}>
            <Select
              id="event-channel"
              label="Channel"
              onChange={(event) => {
                setEventChannel(event.target.value);
                setEventTierAck(false);
              }}
              value={eventChannel}
            >
              {EVENT_LOG_CHANNELS.map((channel) => (
                <option key={channel} value={channel}>{channel}</option>
              ))}
            </Select>
            <Select id="event-window" label="Time window" onChange={(event) => setEventWindowSeconds(Number(event.target.value))} value={eventWindowSeconds}>
              <option value={3600}>Last hour</option>
              <option value={21600}>Last 6 hours</option>
              <option value={86400}>Last 24 hours</option>
              <option value={604800}>Last 7 days</option>
            </Select>
            <Select id="event-max" label="Maximum events" onChange={(event) => setEventMaxEvents(Number(event.target.value))} value={eventMaxEvents}>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </Select>
          </div>
          {eventLogChannelTier(eventChannel) === "elevated" ? (
            <Check checked={eventTierAck} id="event-tier-ack" label="I acknowledge this is an elevated-tier channel (audited separately)." onChange={setEventTierAck} />
          ) : null}
          <Textarea className={monoField} id="event-providers" label="Providers (optional, one per line)" onChange={(event) => setEventProviders(event.target.value)} placeholder={"Microsoft-Windows-Security-Auditing"} rows={2} spellCheck={false} value={eventProviders} />
          <div className={fieldRow}>
            <Input id="event-levels" label="Levels (optional, 1-5)" onChange={(event) => setEventLevels(event.target.value)} placeholder="2, 3" value={eventLevels} />
            <Input id="event-ids" label="Event IDs (optional)" onChange={(event) => setEventIds(event.target.value)} placeholder="4624, 4625" value={eventIds} />
          </div>
          <Input id="event-cursor" inputMode="numeric" label="Continue from cursor (optional)" onChange={(event) => setEventCursor(event.target.value)} placeholder="next_cursor from a prior page" value={eventCursor} />
        </>
      ) : null}
      <DispatchError />
      <div>
        <Button type="submit" variant="primary">Review dispatch</Button>
      </div>
    </form>
  );
}

const fieldRow = "grid gap-4 min-[640px]:grid-cols-2";
const hintText = "m-0 text-xs text-(--muted)";
const labelText = "text-[13px] font-semibold text-(--slate)";
const monoField = "font-(family-name:--font-data) text-[13px]";
const plainControl = cx(
  "h-10 w-full rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-sm text-(--ink)",
  focusRing,
);

function Check({ id, label, checked, onChange }: { id: string; label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-start gap-2 text-sm text-(--slate)" htmlFor={id}>
      <input
        checked={checked}
        className={cx("mt-0.5 size-4 shrink-0 accent-(--primary-strong)", focusRing)}
        id={id}
        onChange={(event) => onChange(event.target.checked)}
        type="checkbox"
      />
      {label}
    </label>
  );
}
