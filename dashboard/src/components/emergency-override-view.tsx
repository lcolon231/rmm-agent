// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CheckCircle2, Play, ShieldAlert, Siren, XCircle } from "lucide-react";
import type { FormEvent } from "react";
import { useCallback, useState } from "react";

import {
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  OVERRIDE_COMMAND_KINDS,
  canReview,
  canRevoke,
  canRun,
  formatTimeRemaining,
  isValidJustification,
  notificationLabel,
  parsePayloadText,
  sortForReview,
  statusLabel,
  type EmergencyOverride,
  type EmergencyOverrideDetail,
} from "@/lib/emergency-overrides-core";
import type { EndpointListItem } from "@/lib/endpoint-list";

type EmergencyOverrideViewProps = {
  initialError: string;
  initialOverrides: EmergencyOverride[] | null;
  initialEndpoints: EndpointListItem[];
  viewerOperatorId: string | null;
  viewerIsAdmin: boolean;
};

/**
 * Justified emergency overrides (issue #65).
 *
 * The screen is deliberately uncomfortable, like the break-glass page. An
 * override is the one place a single person's word stands in for a second
 * reviewer, so the page leads with the debts it creates — unreviewed
 * overrides — and keeps the activation form at the bottom, behind a warning.
 *
 * Nothing here is a security decision. The management service refuses an
 * override unless the policy opted in and the activator is a tenant admin who
 * could run the command anyway; it binds the override to the exact payload,
 * spends it once, expires it on its own clock, and refuses self-review.
 */
export function EmergencyOverrideView({
  initialError,
  initialOverrides,
  initialEndpoints,
  viewerOperatorId,
  viewerIsAdmin,
}: EmergencyOverrideViewProps) {
  const [overrides, setOverrides] = useState<EmergencyOverride[]>(initialOverrides ?? []);
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [justification, setJustification] = useState("");
  const [payloadText, setPayloadText] = useState("");

  const failFrom = useCallback(async (response: Response) => {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    setError(body?.error ?? "That request could not be completed. Try again.");
  }, []);

  const replace = useCallback((updated: EmergencyOverrideDetail) => {
    setOverrides((current) => {
      const exists = current.some((entry) => entry.id === updated.id);
      return exists
        ? current.map((entry) => (entry.id === updated.id ? updated : entry))
        : [updated, ...current];
    });
  }, []);

  const act = useCallback(
    async (overrideId: string, action: "revoke" | "review" | "run", text?: string) => {
      setError("");
      setNotice("");
      setBusyId(overrideId);
      try {
        const body =
          action === "run" ? undefined : JSON.stringify(action === "revoke" ? { reason: text } : { note: text });
        const response = await fetch(`/api/emergency-overrides/${overrideId}/${action}`, {
          ...(body ? { body, headers: { "Content-Type": "application/json" } } : {}),
          method: "POST",
        });
        const payload = (await response.json().catch(() => null)) as
          | { override?: EmergencyOverrideDetail; error?: string }
          | null;
        if (!response.ok || !payload?.override) {
          setError(payload?.error ?? "That request could not be completed. Try again.");
          return;
        }
        replace(payload.override);
        setNotice(
          action === "run"
            ? `Command dispatched as ${payload.override.consumed_command_id?.slice(0, 8) ?? "a run"}. The override is spent.`
            : action === "revoke"
              ? "Override revoked."
              : "Override reviewed.",
        );
      } finally {
        setBusyId(null);
      }
    },
    [replace],
  );

  function revoke(override: EmergencyOverride) {
    const reason = window.prompt("Why are you revoking this override? (recorded)", "");
    if (reason === null) return;
    void act(override.id, "revoke", reason);
  }

  function review(override: EmergencyOverride) {
    const note = window.prompt(
      `Review note for ${override.activated_by_email}'s override (recorded, 10-512 characters)`,
      "",
    );
    if (note === null) return;
    void act(override.id, "review", note);
  }

  function run(override: EmergencyOverride) {
    if (
      !window.confirm(
        `Run the ${override.kind} command on endpoint ${override.agent_id.slice(0, 8)} now, citing this override? It can be used once.`,
      )
    ) {
      return;
    }
    void act(override.id, "run");
  }

  async function activate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const agentId = String(data.get("agent_id") ?? "").trim();
    const kind = String(data.get("kind") ?? "");
    const minutes = Number(data.get("ttl_minutes") ?? DEFAULT_TTL_SECONDS / 60);
    const payload = parsePayloadText(payloadText);
    if (payload === null) {
      setError("The payload must be a JSON object (or empty).");
      return;
    }
    if (!isValidJustification(justification)) {
      setError("Enter a printable justification of 20 to 512 characters.");
      return;
    }
    setError("");
    setNotice("");
    setBusyId("activate");
    try {
      const response = await fetch("/api/emergency-overrides", {
        body: JSON.stringify({
          agent_id: agentId,
          kind,
          payload,
          justification,
          ttl_seconds: Math.min(MAX_TTL_SECONDS, Math.max(MIN_TTL_SECONDS, Math.round(minutes * 60))),
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      const body = (await response.json()) as { override: EmergencyOverrideDetail };
      replace(body.override);
      form.reset();
      setJustification("");
      setPayloadText("");
      setNotice(
        body.override.notified_at
          ? "Override activated and recipients notified. Use it before it expires; it must still be reviewed."
          : "Override activated, but nobody was notified. Tell someone yourself; it must still be reviewed.",
      );
    } finally {
      setBusyId(null);
    }
  }

  if (initialOverrides === null) {
    return (
      <div className="enrollment-empty" role="alert">
        <ShieldAlert size={24} />
        <h3>Emergency overrides could not be loaded</h3>
        <p>{initialError || "The management service did not answer. Try again."}</p>
      </div>
    );
  }

  const now = new Date();
  const ordered = sortForReview(overrides);
  const unreviewed = ordered.filter((entry) => entry.reviewed_at === null && entry.status !== "active");
  const live = ordered.filter((entry) => entry.status === "active" && Date.parse(entry.expires_at) > now.getTime());

  return (
    <section className="mfa-settings approval-queue emergency-overrides">
      <header>
        <h1>Emergency overrides</h1>
        <p>
          A justified exception to an approval policy: one tenant or platform
          administrator takes sole responsibility for one exact command, for a
          few minutes, instead of waiting for a second approver. The policy stays
          in force. Every override notifies the alert recipients immediately, is
          spent once, and stays open here until a different administrator
          reviews it.
        </p>
      </header>

      {unreviewed.length > 0 ? (
        <p className="mfa-banner mfa-banner-warning" role="alert">
          <Siren aria-hidden="true" size={16} /> {unreviewed.length}{" "}
          {unreviewed.length === 1 ? "override" : "overrides"} awaiting review.
        </p>
      ) : null}
      {live.length > 0 ? (
        <p className="mfa-banner mfa-banner-warning" role="status">
          <ShieldAlert aria-hidden="true" size={16} /> {live.length} live{" "}
          {live.length === 1 ? "override" : "overrides"} can run without a second approver right now.
        </p>
      ) : null}

      {error ? <p className="login-error" role="alert">{error}</p> : null}
      {notice ? <p className="mfa-banner" role="status">{notice}</p> : null}

      <h2>Overrides</h2>
      {ordered.length === 0 ? (
        <p>No emergency override has ever been activated.</p>
      ) : (
        <ul className="session-list">
          {ordered.map((override) => {
            const isActivator = override.activated_by_operator_id === viewerOperatorId;
            const runnable = canRun(override, viewerOperatorId, now);
            const revocable = canRevoke(override, viewerOperatorId, viewerIsAdmin, now);
            const reviewable = canReview(override, viewerOperatorId, viewerIsAdmin);
            const busy = busyId === override.id;
            return (
              <li key={override.id}>
                <div>
                  <strong>
                    {override.kind}
                    <span
                      className={
                        override.status === "active"
                          ? "session-badge session-badge-alarm"
                          : override.reviewed_at
                            ? "session-badge"
                            : "session-badge session-badge-warn"
                      }
                    >
                      {statusLabel(override.status)}
                      {override.reviewed_at ? " · reviewed" : " · unreviewed"}
                    </span>
                  </strong>
                  <small>
                    {override.activated_by_email}
                    {isActivator ? " (you)" : ""}
                    {" · endpoint "}
                    {override.agent_id.slice(0, 8)}
                    {" · stood in for "}
                    {override.required_approvals}{" "}
                    {override.required_approvals === 1 ? "approval" : "approvals"}
                    {override.status === "active"
                      ? ` · ${formatTimeRemaining(override.expires_at, now)}`
                      : ""}
                  </small>
                  <small>{override.justification}</small>
                  <small>
                    {notificationLabel(override)}
                    {" · binding "}
                    <code>{override.payload_sha256.slice(0, 16)}</code>
                    {override.reviewed_by_email ? ` · reviewed by ${override.reviewed_by_email}` : ""}
                    {override.revoked_by_email ? ` · revoked by ${override.revoked_by_email}` : ""}
                  </small>
                  {override.status !== "active" && !override.reviewed_at && isActivator ? (
                    <small className="approval-blocked">
                      You activated this override, so someone else must review it.
                    </small>
                  ) : null}
                </div>
                {runnable || revocable || reviewable ? (
                  <div className="approval-actions">
                    {runnable ? (
                      <button disabled={busy} onClick={() => run(override)} type="button">
                        <Play aria-hidden="true" size={15} /> Run now
                      </button>
                    ) : null}
                    {revocable ? (
                      <button disabled={busy} onClick={() => revoke(override)} type="button">
                        <XCircle aria-hidden="true" size={15} /> Revoke
                      </button>
                    ) : null}
                    {reviewable ? (
                      <button disabled={busy} onClick={() => review(override)} type="button">
                        <CheckCircle2 aria-hidden="true" size={15} /> Review
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {viewerIsAdmin ? (
        <>
          <h2>Activate an override</h2>
          <p className="mfa-banner mfa-banner-warning" role="note">
            <ShieldAlert aria-hidden="true" size={16} /> This skips the second
            reviewer the approval policy requires. Use it only when the delay
            itself is the harm. The alert recipients are emailed the moment you
            submit, the override expires in minutes, it runs exactly one
            command, and another administrator must review it afterwards.
          </p>
          <form onSubmit={activate}>
            <label htmlFor="eo-agent">Endpoint</label>
            {initialEndpoints.length > 0 ? (
              <select id="eo-agent" name="agent_id" required defaultValue="">
                <option value="" disabled>
                  Choose an endpoint
                </option>
                {initialEndpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>
                    {endpoint.hostname} · {endpoint.client_name} / {endpoint.site_name}
                  </option>
                ))}
              </select>
            ) : (
              <input
                autoComplete="off"
                id="eo-agent"
                maxLength={36}
                name="agent_id"
                placeholder="Endpoint id"
                required
                type="text"
              />
            )}
            <label htmlFor="eo-kind">Command kind</label>
            <select id="eo-kind" name="kind" required defaultValue="powershell">
              {OVERRIDE_COMMAND_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>
            <label htmlFor="eo-payload">Payload (JSON object, exactly as it will run)</label>
            <textarea
              id="eo-payload"
              name="payload"
              onChange={(event) => setPayloadText(event.target.value)}
              placeholder='{"script": "Restart-Service -Name Spooler"}'
              rows={4}
              value={payloadText}
            />
            <label htmlFor="eo-justification">Justification (recorded, sent to recipients)</label>
            <textarea
              id="eo-justification"
              maxLength={512}
              name="justification"
              onChange={(event) => setJustification(event.target.value)}
              placeholder="What is broken, for whom, the ticket, and why approvers cannot be reached"
              required
              rows={3}
              value={justification}
            />
            <label htmlFor="eo-ttl">Expires after (minutes, 1 to 60)</label>
            <input
              defaultValue={DEFAULT_TTL_SECONDS / 60}
              id="eo-ttl"
              max={MAX_TTL_SECONDS / 60}
              min={MIN_TTL_SECONDS / 60}
              name="ttl_minutes"
              required
              type="number"
            />
            <button disabled={busyId === "activate"} type="submit">
              <Siren aria-hidden="true" size={15} /> Activate emergency override
            </button>
          </form>
        </>
      ) : null}
    </section>
  );
}
