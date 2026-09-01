// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowRight, Siren } from "lucide-react";
import type { FormEvent } from "react";
import { useState } from "react";

import { adminSessionErrorMessage } from "@/lib/admin-sessions-core";

/**
 * Emergency sign-in with a sealed credential (issue #69).
 *
 * Reachable without a session, because it is the way back in when no session
 * can be obtained. The copy is deliberately blunt about consequences: this is
 * not a convenience path, and someone who reaches it by accident should turn
 * back.
 */
export function BreakGlassActivateForm() {
  const [error, setError] = useState("");
  const [isBusy, setIsBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setError("");
    setIsBusy(true);
    try {
      const response = await fetch("/api/auth/break-glass/activate", {
        body: JSON.stringify({
          credential: String(data.get("credential") ?? ""),
          reason: String(data.get("reason") ?? ""),
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (response.ok) {
        window.location.replace("/security");
        return;
      }
      const body = await response.json().catch(() => null) as
        | { error?: string; code?: string }
        | null;
      setError(
        body?.error
          ?? adminSessionErrorMessage(body?.code)
          ?? "Emergency access could not be granted.",
      );
    } catch {
      setError("Emergency access could not be granted.");
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-panel" aria-labelledby="bg-title">
        <div className="login-brand">
          <span className="brand-mark"><span /><span /><span /></span>
          <strong>NodeLink</strong>
        </div>
        <span className="login-eyebrow"><Siren size={15} /> Emergency access</span>
        <h1 id="bg-title">Break-glass sign-in</h1>
        <p>
          For use only when normal sign-in is impossible. This grants a
          short-lived administrator session without a second factor. Every use is
          recorded, alerts the platform administrators, and must be reviewed
          afterwards. If you can sign in normally, do that instead.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="credential">Emergency credential</label>
          <input
            autoComplete="off"
            id="credential"
            maxLength={200}
            name="credential"
            placeholder="nlbg_…"
            required
            spellCheck={false}
            type="password"
          />
          <label htmlFor="reason">Why are you using it?</label>
          <input
            autoComplete="off"
            id="reason"
            maxLength={500}
            name="reason"
            placeholder="All administrators locked out after key loss"
            required
            type="text"
          />
          {error ? <p className="login-error" role="alert">{error}</p> : null}
          <button disabled={isBusy} type="submit">
            <Siren size={16} /> {isBusy ? "Verifying…" : "Break glass"} <ArrowRight size={16} />
          </button>
        </form>
        <small>
          The session this creates expires far sooner than a normal one, and is
          marked as emergency access everywhere it appears.
        </small>
      </section>
    </main>
  );
}
