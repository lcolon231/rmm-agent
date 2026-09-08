// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { LogOut, Monitor, ShieldAlert, Siren } from "lucide-react";
import { useCallback, useState } from "react";

import {
  adminSessionErrorMessage,
  describeAuthMethods,
  describeClient,
  describeEndReason,
  inventoryWarning,
  orderSessions,
  sessionIsPasswordOnly,
  type SessionRecord,
} from "@/lib/admin-sessions-core";

type SessionInventoryViewProps = {
  initialError: string;
  initialSessions: SessionRecord[] | null;
};

/**
 * "Where am I signed in?" (issue #69).
 *
 * The point of this list is recognition: an operator should be able to look at
 * it and notice a device that is not theirs. So each row leads with the things
 * a person can actually recognise -- client, location, when it was last used --
 * and the opaque session id is not shown at all.
 */
export function SessionInventoryView({
  initialError,
  initialSessions,
}: SessionInventoryViewProps) {
  const [sessions, setSessions] = useState(initialSessions);
  const [error, setError] = useState(initialError);
  const [notice, setNotice] = useState("");
  const [isBusy, setIsBusy] = useState(false);

  const failFrom = useCallback(async (response: Response) => {
    const body = await response.json().catch(() => null) as
      | { error?: string; code?: string }
      | null;
    setError(
      body?.error
        ?? adminSessionErrorMessage(body?.code)
        ?? "That request could not be completed. Try again.",
    );
  }, []);

  const refresh = useCallback(async () => {
    const response = await fetch("/api/auth/sessions", { method: "GET" });
    if (response.ok) setSessions(await response.json() as SessionRecord[]);
  }, []);

  async function revoke(session: SessionRecord) {
    if (session.is_current) {
      setError("This is the session you are using. Sign out instead.");
      return;
    }
    const reason = window.prompt(
      "Why are you ending this session? This is recorded in the audit log.",
      "",
    );
    if (reason === null || reason.trim().length < 3) return;

    setError("");
    setNotice("");
    setIsBusy(true);
    try {
      const response = await fetch(`/api/auth/sessions/${session.id}/revoke`, {
        body: JSON.stringify({ reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      setNotice("Session ended. It stops working immediately.");
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  async function revokeOthers() {
    if (!window.confirm(
      "Sign out every other device? You will stay signed in here.",
    )) {
      return;
    }
    const reason = window.prompt(
      "Why are you signing out your other devices?",
      "Suspected credential compromise",
    );
    if (reason === null || reason.trim().length < 3) return;

    setError("");
    setNotice("");
    setIsBusy(true);
    try {
      const response = await fetch("/api/auth/sessions/revoke-others", {
        body: JSON.stringify({ reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        await failFrom(response);
        return;
      }
      const body = await response.json() as { revoked: number };
      setNotice(
        `Ended ${body.revoked} other ${body.revoked === 1 ? "session" : "sessions"}.`,
      );
      await refresh();
    } finally {
      setIsBusy(false);
    }
  }

  if (!sessions) {
    return (
      <section className="mfa-settings" role="alert">
        <h2>Active sessions</h2>
        <p>{error || "Your sessions could not be loaded."}</p>
      </section>
    );
  }

  const ordered = orderSessions(sessions);
  const live = ordered.filter((session) => session.ended_at === null);
  const ended = ordered.filter((session) => session.ended_at !== null).slice(0, 10);
  const warning = inventoryWarning(sessions);

  return (
    <section className="mfa-settings session-inventory">
      <header>
        <h1>Active sessions</h1>
        <p>
          Every device signed in to this account. Ending a session takes effect on
          its next request — the sign-in stops working immediately rather than
          when its token would have expired.
        </p>
      </header>

      {warning ? (
        <p className="mfa-banner mfa-banner-warning" role="alert">
          <ShieldAlert aria-hidden="true" size={16} /> {warning}
        </p>
      ) : null}
      {error ? <p className="login-error" role="alert">{error}</p> : null}
      {notice ? <p className="mfa-banner" role="status">{notice}</p> : null}

      <ul className="session-list">
        {live.map((session) => (
          <li key={session.id} className={session.is_current ? "session-current" : undefined}>
            <div>
              <strong>
                {session.is_break_glass ? <Siren aria-hidden="true" size={14} /> : <Monitor aria-hidden="true" size={14} />}
                {" "}
                {describeClient(session.user_agent)}
                {session.is_current ? <span className="session-badge">This device</span> : null}
                {session.is_break_glass ? <span className="session-badge session-badge-alarm">Emergency</span> : null}
                {sessionIsPasswordOnly(session) ? <span className="session-badge session-badge-warn">Password only</span> : null}
              </strong>
              <small>
                {describeAuthMethods(session.auth_methods)}
                {session.source_ip ? ` · ${session.source_ip}` : ""}
                {" · last used "}
                {new Date(session.last_seen_at).toLocaleString()}
                {" · expires "}
                {new Date(session.absolute_expires_at).toLocaleString()}
              </small>
            </div>
            <button
              disabled={isBusy || session.is_current}
              onClick={() => revoke(session)}
              type="button"
            >
              <LogOut size={14} /> End
            </button>
          </li>
        ))}
      </ul>

      <button disabled={isBusy || live.length < 2} onClick={revokeOthers} type="button">
        <LogOut size={16} /> Sign out all other devices
      </button>

      {ended.length > 0 ? (
        <>
          <h2>Recently ended</h2>
          <ul className="session-list session-list-ended">
            {ended.map((session) => (
              <li key={session.id}>
                <div>
                  <strong>{describeClient(session.user_agent)}</strong>
                  <small>
                    {describeEndReason(session.end_reason) ?? "Ended"}
                    {session.ended_at ? ` · ${new Date(session.ended_at).toLocaleString()}` : ""}
                  </small>
                </div>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
