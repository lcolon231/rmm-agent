// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";
import { useState } from "react";

type LoginFormProps = {
  initialError?: string;
};

export function LoginForm({ initialError }: LoginFormProps) {
  const [error, setError] = useState(initialError ?? "");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);

    const formData = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/auth/login", {
        body: JSON.stringify({
          email: formData.get("email"),
          password: formData.get("password"),
        }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });

      if (response.ok) {
        const body = await response.json().catch(() => null) as
          | { mfa_required?: boolean; mfa_enrollment_required?: boolean; mfa_methods?: string[] }
          | null;
        if (body?.mfa_required) {
          // The password was accepted but a second factor is owed. The methods
          // travel as a display hint only; the server re-decides them.
          const params = new URLSearchParams();
          if (body.mfa_methods?.length) params.set("methods", body.mfa_methods.join(","));
          if (body.mfa_enrollment_required) params.set("enroll", "1");
          const query = params.toString();
          window.location.replace(query ? `/login/mfa?${query}` : "/login/mfa");
          return;
        }
        window.location.replace("/");
        return;
      }

      const body = await response.json().catch(() => null) as { error?: string } | null;
      setError(body?.error ?? "Sign-in is unavailable. Try again later.");
    } catch {
      setError("Sign-in is unavailable. Try again later.");
    }

    setIsSubmitting(false);
  }

  return (
    <main className="login-page">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="login-brand"><span className="brand-mark"><span /><span /><span /></span><strong>NodeLink</strong></div>
        <span className="login-eyebrow"><ShieldCheck size={15} /> Technician access</span>
        <h1 id="login-title">Sign in to operations</h1>
        <p>Use your NodeLink operator account. Your session stays in an HTTP-only cookie and is verified on every dashboard request.</p>
        <form action="/api/auth/login" method="post" onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>
          <input autoComplete="email" id="email" name="email" required type="email" />
          <label htmlFor="password">Password</label>
          <input autoComplete="current-password" id="password" name="password" required type="password" />
          {error ? <p className="login-error" role="alert">{error}</p> : null}
          <button disabled={isSubmitting} type="submit">
            <LockKeyhole size={16} /> {isSubmitting ? "Signing in…" : "Sign in"} <ArrowRight size={16} />
          </button>
        </form>
        <small>Need access? Ask a NodeLink administrator to create or enable your operator account.</small>
      </section>
    </main>
  );
}
