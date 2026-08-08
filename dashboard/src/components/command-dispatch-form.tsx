// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowLeft, Send, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";

import {
  commandKindDefinitions,
  commandKindDefinitionsForPermission,
  ttlOptions,
  validateDispatchInput,
  type CommandKind,
  type DispatchInput,
} from "@/lib/command-console-core";

type DispatchFormProps = {
  endpointId: string;
  hostname: string;
  canExecuteScripts: boolean;
};

type Step =
  | { name: "compose" }
  | { name: "confirm"; input: DispatchInput }
  | { name: "dispatched"; commandId: string };

export function CommandDispatchForm({
  endpointId,
  hostname,
  canExecuteScripts,
}: DispatchFormProps) {
  const router = useRouter();
  const [kind, setKind] = useState<CommandKind>(
    canExecuteScripts ? "powershell" : "collect_inventory",
  );
  const [script, setScript] = useState("");
  const [updateTargets, setUpdateTargets] = useState("");
  const [installAll, setInstallAll] = useState(false);
  const [ttlSeconds, setTtlSeconds] = useState(300);
  const [step, setStep] = useState<Step>({ name: "compose" });
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const definition = commandKindDefinitions.find((d) => d.kind === kind)!;
  const availableDefinitions =
    commandKindDefinitionsForPermission(canExecuteScripts);

  function handleReview() {
    setError("");
    const input = validateDispatchInput({
      kind,
      script,
      update_targets: updateTargets,
      install_all: installAll,
      ttl_seconds: ttlSeconds,
    });
    if (!input) {
      setError(
        definition.input === "script"
          ? "Enter a script within the size limit before dispatching."
          : definition.input === "update_targets"
            ? "Enter valid KB or Windows Update IDs, or explicitly choose Install all applicable updates."
            : "This typed operation does not accept additional input.",
      );
      return;
    }
    setStep({ name: "confirm", input });
  }

  async function handleConfirm(input: DispatchInput) {
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
        setStep({ name: "dispatched", commandId: body.command.id });
        setScript("");
        setUpdateTargets("");
        setInstallAll(false);
        router.refresh();
      } else {
        setError(body?.error ?? "The command could not be dispatched. Try again.");
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
          command for <strong>{hostname}</strong>, valid for <strong>{ttlLabel}</strong>. Dispatched
          commands cannot be cancelled — an unpicked command dies at its signed expiry.
        </p>
        {step.input.script ? <pre>{step.input.script}</pre> : step.input.kind === "install_updates" ? (
          <pre>
            {step.input.install_all
              ? "All applicable non-hidden updates"
              : step.input.update_targets.join("\n")}
          </pre>
        ) : (
          <p className="dispatch-noscript">No script payload — this is a bounded typed operation.</p>
        )}
        <div className="dispatch-review-actions">
          <button disabled={isSubmitting} onClick={() => setStep({ name: "compose" })} type="button">
            <ArrowLeft size={15} /> Edit
          </button>
          <button className="danger" disabled={isSubmitting} onClick={() => handleConfirm(step.input)} type="button">
            <Send size={15} /> {isSubmitting ? "Dispatching…" : "Confirm dispatch"}
          </button>
        </div>
        {error ? <p className="dispatch-error" role="alert">{error}</p> : null}
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
      ) : null}
      {error ? <p className="dispatch-error" role="alert">{error}</p> : null}
      <button type="submit">Review dispatch</button>
    </form>
  );
}
