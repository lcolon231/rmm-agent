// SPDX-License-Identifier: AGPL-3.0-only

/** Presentation helpers for the endpoint Inventory and Commands subpages. */

import { commandKindDefinitions, type CommandDetailData } from "./command-console-core.ts";
import type { InventorySectionStatus } from "./inventory-core.ts";

type Tone = "ok" | "warn" | "crit" | "off" | "info";

export type InventoryBadge = { tone: Tone; label: "Completed" | "Notice" | "Failed" };

/**
 * Inventory section status in the fixed status vocabulary. A partial or
 * unsupported section is not a failure, but it is never shown as green either;
 * a section that could not be read is a failure, so an unread BitLocker state
 * never sits quietly next to a healthy one.
 */
export function inventoryBadge(status: InventorySectionStatus): InventoryBadge {
  switch (status) {
    case "ok":
      return { tone: "ok", label: "Completed" };
    case "partial":
    case "unsupported":
      return { tone: "off", label: "Notice" };
    case "unavailable":
    case "permission_denied":
      return { tone: "crit", label: "Failed" };
  }
}

/** done/failed only when the command record proves it; everything else is neutral. */
export type CustodyState = "done" | "failed" | "pending" | "unknown" | "expired";

export type CustodyStep = {
  key: "requested" | "signed" | "sent" | "finished" | "received" | "expired";
  label: string;
  detail: string;
  at: string | null;
  state: CustodyState;
};

/**
 * Chain of custody built only from fields on the command record. Steps the
 * record has no data for (policy check, approval, the audit entry, the agent's
 * own signature check) are left out rather than drawn as complete.
 */
export function custodySteps(command: CommandDetailData): CustodyStep[] {
  const steps: CustodyStep[] = [
    { key: "requested", label: "Requested", detail: "The command record was created.", at: command.created_at, state: "done" },
  ];

  // Signed is proven only by a recorded signing key alongside a stored signature.
  if (command.signing_key_id && command.signature) {
    steps.push({ key: "signed", label: "Signed", detail: `Signing key ${command.signing_key_id}`, at: command.issued_at, state: "done" });
  } else if (command.signature) {
    steps.push({
      key: "signed",
      label: "Signing key not recorded",
      detail: `A signature is stored (envelope ${command.envelope_version}), but this record does not name the key that made it.`,
      at: null,
      state: "unknown",
    });
  } else {
    steps.push({ key: "signed", label: "No signature recorded", detail: "This record carries no signature.", at: null, state: "unknown" });
  }

  if (command.dispatched_at) {
    steps.push({ key: "sent", label: "Sent to the device", detail: "Handed to the device at its check-in.", at: command.dispatched_at, state: "done" });
  } else if (command.status === "expired") {
    steps.push({ key: "sent", label: "Not sent", detail: "No dispatch time is recorded for this expired command.", at: null, state: "pending" });
  } else {
    steps.push({ key: "sent", label: "Not sent yet", detail: "Waiting for the device to check in.", at: null, state: "pending" });
  }

  const exit = command.exit_code === null ? "" : ` Exit code ${command.exit_code}.`;
  if (command.agent_completed_at) {
    const failed = command.status === "failed";
    steps.push({
      key: "finished",
      label: failed ? "Finished with an error" : "Finished on the device",
      detail: (failed ? "The device reported a failure." : "The device reported when it finished.") + exit,
      at: command.agent_completed_at,
      state: failed ? "failed" : "done",
    });
  } else if (command.status === "succeeded" || command.status === "failed") {
    steps.push({ key: "finished", label: "Finish time not reported", detail: "The device sent a result but not when it finished.", at: null, state: "unknown" });
  } else if (command.status !== "expired") {
    steps.push({ key: "finished", label: "Not finished yet", detail: "The device has not reported a result.", at: null, state: "pending" });
  }

  if (command.completed_at && (command.status === "succeeded" || command.status === "failed")) {
    steps.push({
      key: "received",
      label: "Result received by NodeLink",
      detail: command.status === "failed" ? `The result was stored; the command failed.${exit}` : `The result was stored.${exit}`,
      at: command.completed_at,
      state: "done",
    });
  } else if (command.status === "result_pending") {
    steps.push({ key: "received", label: "Result not received yet", detail: "The device kept the result and will retry until NodeLink stores it.", at: null, state: "pending" });
  } else if (command.status !== "expired") {
    steps.push({ key: "received", label: "Result not received yet", detail: "Nothing has been stored for this command yet.", at: null, state: "pending" });
  }

  if (command.status === "expired") {
    steps.push({ key: "expired", label: "Expired", detail: "The command is marked expired.", at: command.expires_at, state: "expired" });
  }

  return steps;
}


/** Shared by server-rendered command records and the client history table. */
export function commandKindLabel(kind: string) {
  return commandKindDefinitions.find((definition) => definition.kind === kind)?.label ?? kind;
}
