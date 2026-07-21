// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";
import { useState } from "react";
import { useRouter } from "next/navigation";

type LoginFormProps = {
  initialError?: string;
};

export function LoginForm({ initialError }: LoginFormProps) {
  const router = useRouter();
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
        router.replace("/");
        router.refresh();
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
        <form onSubmit={handleSubmit}>
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
