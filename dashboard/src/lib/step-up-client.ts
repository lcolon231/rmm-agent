// SPDX-License-Identifier: AGPL-3.0-only

import {
  ceremonyErrorCode,
  mfaErrorMessage,
  toAssertionPayload,
  toRequestOptions,
} from "@/lib/mfa-core";

export type StepUpResult = { ok: true } | { ok: false; error: string };

async function failure(response: Response): Promise<StepUpResult> {
  const body = await response.json().catch(() => null) as { error?: string; code?: string } | null;
  return {
    ok: false,
    error: body?.error ?? mfaErrorMessage(body?.code) ?? "The security key could not be confirmed.",
  };
}

/**
 * Re-assert a WebAuthn credential to refresh this session's step-up, using the
 * same ceremony as the security settings page. The verify route swaps in the
 * upgraded session cookie, so the caller simply retries its request. Call it
 * only from an operator's click: an unprompted key request is a phishing tell.
 */
export async function performStepUp(): Promise<StepUpResult> {
  try {
    const optionsResponse = await fetch("/api/auth/mfa/step-up/options", { method: "POST" });
    if (!optionsResponse.ok) return failure(optionsResponse);
    const credential = await navigator.credentials.get({
      publicKey: toRequestOptions(await optionsResponse.json()),
    }) as PublicKeyCredential | null;
    if (!credential) return { ok: false, error: mfaErrorMessage("cancelled") ?? "Cancelled." };
    const response = await fetch("/api/auth/mfa/step-up/verify", {
      body: JSON.stringify(toAssertionPayload(credential)),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    return response.ok ? { ok: true } : failure(response);
  } catch (error) {
    return { ok: false, error: mfaErrorMessage(ceremonyErrorCode(error)) ?? "Cancelled." };
  }
}
