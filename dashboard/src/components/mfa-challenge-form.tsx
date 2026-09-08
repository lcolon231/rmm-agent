// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ArrowRight, KeyRound, LifeBuoy, Mail, ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";
import { useCallback, useState } from "react";

import {
  ceremonyErrorCode,
  mfaErrorMessage,
  toAssertionPayload,
  toCreationOptions,
  toRegistrationPayload,
  toRequestOptions,
  type MfaMethod,
} from "@/lib/mfa-core";
import { useWebAuthnSupport } from "@/lib/use-webauthn-support";

type MfaChallengeFormProps = {
  enrollmentRequired: boolean;
  methods: MfaMethod[];
};

/**
 * The second step of signing in (issue #67).
 *
 * Three states, chosen by what the server said the operator may do:
 *
 * - **enrol** — policy requires a second factor and they have none yet, so the
 *   only thing on offer is registering one.
 * - **assert** — the normal path: touch the security key.
 * - **recovery** — the fallback, shown only when the server listed it, so the
 *   page never advertises an option that would fail.
 * - **email** — a mailed one-time code (issue #226), likewise only when the
 *   server listed it. The copy says plainly that it is the weaker factor and
 *   that the resulting session cannot change security settings, because an
 *   operator choosing between two options should be told what they are giving
 *   up rather than discovering it at a 403.
 *
 * The component decides nothing about whether a ceremony passed. It hands bytes
 * to the browser's authenticator, posts what comes back, and renders the
 * server's verdict.
 */
export function MfaChallengeForm({ enrollmentRequired, methods }: MfaChallengeFormProps) {
  const recoveryAvailable = methods.includes("recovery_code");
  const emailAvailable = methods.includes("email_code");
  const keyAvailable = methods.includes("webauthn");

  const [error, setError] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  // An operator whose only factor is a mailed code must not land on a screen
  // telling them to touch a key they do not own.
  const [mode, setMode] = useState<"assert" | "recovery" | "email">(
    keyAvailable || !emailAvailable ? "assert" : "email",
  );
  const [codeSent, setCodeSent] = useState(false);
  const [destination, setDestination] = useState("");

  const supported = useWebAuthnSupport();

  const failFromResponse = useCallback(async (response: Response) => {
    const body = await response.json().catch(() => null) as
      | { error?: string; code?: string }
      | null;
    setError(
      body?.error
        ?? mfaErrorMessage(body?.code)
        ?? "Multi-factor authentication is unavailable. Try again later.",
    );
  }, []);

  async function runAssertion() {
    setError("");
    setIsBusy(true);
    try {
      const optionsResponse = await fetch("/api/auth/mfa/login/options", {
        method: "POST",
      });
      if (!optionsResponse.ok) {
        await failFromResponse(optionsResponse);
        return;
      }
      const credential = await navigator.credentials.get({
        publicKey: toRequestOptions(await optionsResponse.json()),
      }) as PublicKeyCredential | null;
      if (!credential) {
        setError(mfaErrorMessage("cancelled") ?? "");
        return;
      }

      const verifyResponse = await fetch("/api/auth/mfa/login/verify", {
        body: JSON.stringify(toAssertionPayload(credential)),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (verifyResponse.ok) {
        window.location.replace("/");
        return;
      }
      await failFromResponse(verifyResponse);
    } catch (error) {
      // Classify rather than assume: a relying-party mismatch is a deployment
      // fault, and reporting it as a dismissed prompt sends the reader looking
      // in the wrong place.
      setError(mfaErrorMessage(ceremonyErrorCode(error)) ?? "");
    } finally {
      setIsBusy(false);
    }
  }

  async function runEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = String(new FormData(event.currentTarget).get("name") ?? "").trim();
    setError("");
    setIsBusy(true);
    try {
      const optionsResponse = await fetch("/api/auth/mfa/credentials/options", {
        method: "POST",
      });
      if (!optionsResponse.ok) {
        await failFromResponse(optionsResponse);
        return;
      }
      const credential = await navigator.credentials.create({
        publicKey: toCreationOptions(await optionsResponse.json()),
      }) as PublicKeyCredential | null;
      if (!credential) {
        setError(mfaErrorMessage("cancelled") ?? "");
        return;
      }

      const registerResponse = await fetch("/api/auth/mfa/credentials", {
        body: JSON.stringify(toRegistrationPayload(credential, name)),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (registerResponse.ok) {
        // Registration does not itself produce a session — the operator now
        // signs in with the factor they just created, which also proves it
        // works before they depend on it.
        await runAssertion();
        return;
      }
      await failFromResponse(registerResponse);
    } catch (error) {
      setError(mfaErrorMessage(ceremonyErrorCode(error)) ?? "");
    } finally {
      setIsBusy(false);
    }
  }

  async function requestEmailCode() {
    setError("");
    setIsBusy(true);
    try {
      const response = await fetch("/api/auth/mfa/login/email/send", {
        method: "POST",
      });
      if (!response.ok) {
        await failFromResponse(response);
        return;
      }
      const body = await response.json().catch(() => null) as
        | { destination?: string }
        | null;
      // The acknowledgement is deliberately the same whether or not a message
      // was really sent, so this only ever means "the request was accepted".
      setDestination(typeof body?.destination === "string" ? body.destination : "");
      setCodeSent(true);
    } catch {
      setError("Multi-factor authentication is unavailable. Try again later.");
    } finally {
      setIsBusy(false);
    }
  }

  async function submitEmailCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "");
    setError("");
    setIsBusy(true);
    try {
      const response = await fetch("/api/auth/mfa/login/email/verify", {
        body: JSON.stringify({ code }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (response.ok) {
        // Land on the security page, as the recovery-code path does: this
        // session cannot change security settings, and the place to fix that is
        // there.
        window.location.replace("/security");
        return;
      }
      await failFromResponse(response);
    } catch {
      setError("Multi-factor authentication is unavailable. Try again later.");
    } finally {
      setIsBusy(false);
    }
  }

  async function submitRecoveryCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "");
    setError("");
    setIsBusy(true);
    try {
      const response = await fetch("/api/auth/mfa/login/recovery-code", {
        body: JSON.stringify({ code }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (response.ok) {
        window.location.replace("/security");
        return;
      }
      await failFromResponse(response);
    } catch {
      setError("Multi-factor authentication is unavailable. Try again later.");
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-panel" aria-labelledby="mfa-title">
        <div className="login-brand">
          <span className="brand-mark"><span /><span /><span /></span>
          <strong>NodeLink</strong>
        </div>
        <span className="login-eyebrow"><ShieldCheck size={15} /> Second factor</span>

        {enrollmentRequired ? (
          <>
            <h1 id="mfa-title">Register a security key</h1>
            <p>
              Your account is required to hold a phishing-resistant second factor.
              Register a security key or your device&apos;s built-in authenticator to
              finish signing in. Nothing else is available until you do.
            </p>
            <form onSubmit={runEnrollment}>
              <label htmlFor="name">Device name</label>
              <input
                autoComplete="off"
                defaultValue=""
                id="name"
                maxLength={64}
                name="name"
                placeholder="Work laptop"
                required
                type="text"
              />
              {error ? <p className="login-error" role="alert">{error}</p> : null}
              <button disabled={isBusy || !supported} type="submit">
                <KeyRound size={16} /> {isBusy ? "Waiting for your key…" : "Register and continue"} <ArrowRight size={16} />
              </button>
            </form>
          </>
        ) : mode === "recovery" ? (
          <>
            <h1 id="mfa-title">Use a recovery code</h1>
            <p>
              Enter one of the codes you saved when you set up your security key. Each
              code works once. Signing in this way lets you register a replacement key,
              but not change your security settings until you do.
            </p>
            <form onSubmit={submitRecoveryCode}>
              <label htmlFor="code">Recovery code</label>
              <input
                autoComplete="one-time-code"
                id="code"
                maxLength={64}
                name="code"
                placeholder="ABCDE-FGHIJ-KLMNP-QRSTU"
                required
                spellCheck={false}
                type="text"
              />
              {error ? <p className="login-error" role="alert">{error}</p> : null}
              <button disabled={isBusy} type="submit">
                <LifeBuoy size={16} /> {isBusy ? "Checking…" : "Sign in with recovery code"} <ArrowRight size={16} />
              </button>
            </form>
            <button
              className="login-secondary"
              onClick={() => { setMode("assert"); setError(""); }}
              type="button"
            >
              Use my security key instead
            </button>
          </>
        ) : mode === "email" ? (
          <>
            <h1 id="mfa-title">Check your email</h1>
            {codeSent ? (
              <p>
                We sent a code to {destination || "your email address"}. It expires
                shortly and works once. Signing in this way lets you register a
                security key, but not change your security settings until you do.
              </p>
            ) : (
              <p>
                We can email a one-time code to your login address. An emailed code
                is not as strong as a security key -- it can be phished -- so this
                session will not be able to change your security settings.
              </p>
            )}
            {codeSent ? (
              <form onSubmit={submitEmailCode}>
                <label htmlFor="code">Emailed code</label>
                <input
                  autoComplete="one-time-code"
                  id="code"
                  inputMode="numeric"
                  maxLength={32}
                  name="code"
                  placeholder="123456"
                  required
                  spellCheck={false}
                  type="text"
                />
                {error ? <p className="login-error" role="alert">{error}</p> : null}
                <button disabled={isBusy} type="submit">
                  <Mail size={16} /> {isBusy ? "Checking..." : "Sign in with the code"} <ArrowRight size={16} />
                </button>
              </form>
            ) : (
              <>
                {error ? <p className="login-error" role="alert">{error}</p> : null}
                <button disabled={isBusy} onClick={requestEmailCode} type="button">
                  <Mail size={16} /> {isBusy ? "Sending..." : "Email me a code"} <ArrowRight size={16} />
                </button>
              </>
            )}
            {codeSent ? (
              <button
                className="login-secondary"
                disabled={isBusy}
                onClick={requestEmailCode}
                type="button"
              >
                Send another code
              </button>
            ) : null}
            {keyAvailable ? (
              <button
                className="login-secondary"
                onClick={() => { setMode("assert"); setError(""); }}
                type="button"
              >
                Use my security key instead
              </button>
            ) : null}
          </>
        ) : (
          <>
            <h1 id="mfa-title">Confirm it&apos;s you</h1>
            <p>
              Touch your security key, or approve the prompt from your device&apos;s
              built-in authenticator, to finish signing in.
            </p>
            {!supported ? (
              <p className="login-error" role="alert">
                {mfaErrorMessage("unsupported-browser")}
              </p>
            ) : null}
            {error ? <p className="login-error" role="alert">{error}</p> : null}
            <button disabled={isBusy || !supported} onClick={runAssertion} type="button">
              <KeyRound size={16} /> {isBusy ? "Waiting for your key…" : "Use security key"} <ArrowRight size={16} />
            </button>
            {recoveryAvailable ? (
              <button
                className="login-secondary"
                onClick={() => { setMode("recovery"); setError(""); }}
                type="button"
              >
                Lost your key? Use a recovery code
              </button>
            ) : null}
            {emailAvailable ? (
              <button
                className="login-secondary"
                onClick={() => { setMode("email"); setError(""); }}
                type="button"
              >
                Email me a code instead
              </button>
            ) : null}
          </>
        )}

        <small>
          Signing in from a different site will not work: your key is bound to this
          domain, which is what makes it resistant to phishing.
        </small>
      </section>
    </main>
  );
}
