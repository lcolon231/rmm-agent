// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pure WebAuthn MFA logic for the dashboard (issue #67).
 *
 * Nothing here touches `next/headers`, `fetch`, or the DOM, so all of it is
 * unit-testable under `node --test`. The browser-only part — actually calling
 * `navigator.credentials` — is confined to the components, and the conversions
 * it needs in both directions live here where they can be tested against
 * fixtures.
 *
 * The server is the authority on every security decision. This file never
 * decides whether a ceremony succeeded, whether a session may skip a factor, or
 * whether step-up is satisfied; it shuttles bytes and renders what the server
 * said. Anything that looks like a policy check here is presentation only.
 */

export type MfaMethod = "webauthn" | "recovery_code" | "email_code" | "enrollment";

export type MfaLoginChallenge = {
  mfaRequired: true;
  enrollmentRequired: boolean;
  methods: MfaMethod[];
  mfaToken: string;
};

export type MfaCredentialRecord = {
  id: string;
  name: string;
  algorithm: number;
  aaguid: string;
  transports: string | null;
  attestation_format: string;
  backup_eligible: boolean;
  backup_state: boolean;
  created_at: string;
  last_used_at: string | null;
};

export type MfaStatus = {
  enforcement: "off" | "optional" | "required";
  enrollment_required: boolean;
  enrolled: boolean;
  credential_count: number;
  recovery_codes_remaining: number;
  step_up_satisfied: boolean;
  session_methods: string[];
  credentials: MfaCredentialRecord[];
  /** Configured position for the email factor (issue #226). */
  email_code_policy?: "off" | "fallback_only" | "always";
  email_factor?: MfaEmailFactorRecord | null;
};

export type MfaEmailFactorRecord = {
  verified: boolean;
  /** Masked; the full address is the operator's own login email. */
  destination: string | null;
  verified_at: string | null;
};

export type MfaErrorCode =
  | "invalid-request"
  | "challenge-failed"
  | "rate-limited"
  | "request-rejected"
  | "step-up-required"
  | "mfa-disabled"
  | "unsupported-browser"
  | "cancelled"
  | "relying-party-mismatch"
  | "insecure-context"
  | "already-registered"
  | "unavailable";

const mfaErrorMessages: Record<MfaErrorCode, string> = {
  "invalid-request": "That request could not be read. Try again.",
  // Deliberately as vague as the server's own response: the API returns one
  // message for every refused ceremony, and restating a guess here would
  // reintroduce the oracle the server took care to remove.
  "challenge-failed": "That security key could not be verified. Try again.",
  "rate-limited": "Too many attempts. Wait a moment and try again.",
  "request-rejected": "The request was rejected.",
  "step-up-required": "Re-authenticate with your security key to continue.",
  "mfa-disabled": "Multi-factor authentication is turned off for this deployment.",
  "unsupported-browser": "This browser does not support security keys.",
  "cancelled": "The security key prompt was dismissed or timed out.",
  // A configuration fault, not a user action. Says so plainly, because the
  // person seeing it usually cannot fix it and needs to know who can.
  "relying-party-mismatch":
    "This site is not configured for security keys: the server's relying-party"
    + " domain does not match the address in your browser. An administrator"
    + " needs to set MFA_RP_ID and MFA_ALLOWED_ORIGINS to this site's domain.",
  "insecure-context":
    "Security keys require a secure (HTTPS) connection to this site.",
  "already-registered":
    "That security key is already registered on this account.",
  unavailable: "Multi-factor authentication is unavailable. Try again later.",
};

export function mfaErrorMessage(value: unknown): string | undefined {
  if (typeof value !== "string" || !(value in mfaErrorMessages)) {
    return undefined;
  }
  return mfaErrorMessages[value as MfaErrorCode];
}

/**
 * Map an upstream HTTP status onto a display code.
 *
 * 401 and 400 both collapse to "challenge-failed" on purpose. The server
 * already refuses to say which rule rejected a ceremony, and a dashboard that
 * distinguished "no such credential" from "bad signature" would hand that
 * distinction back to an attacker.
 */
export function mfaErrorCodeForStatus(status: number, code?: string | null): MfaErrorCode {
  if (code === "step_up_required" || code === "mfa_verification_required") {
    return "step-up-required";
  }
  if (code === "mfa_disabled" || code === "mfa_not_configured") {
    return "mfa-disabled";
  }
  if (status === 429) {
    return "rate-limited";
  }
  if (status === 400 || status === 401) {
    return "challenge-failed";
  }
  if (status === 403) {
    return "request-rejected";
  }
  return "unavailable";
}

/**
 * Classify a `navigator.credentials` failure.
 *
 * Every one of these arrives as a DOMException, and lumping them together is
 * how a deployment fault ends up being reported to the user as "you dismissed
 * the prompt" -- which sends them looking in the wrong place entirely.
 *
 * The distinction that matters most is `SecurityError`: the browser raises it
 * when the relying-party ID is not a registrable suffix of the page's origin,
 * which is exactly what happens when the API and the dashboard are served from
 * different domains and `MFA_RP_ID` was left to derive from the API's own URL.
 * That is a configuration bug an administrator must fix, and the message says
 * so rather than blaming whoever was standing at the keyboard.
 */
export function ceremonyErrorCode(error: unknown): MfaErrorCode {
  const name = (error as { name?: unknown } | null)?.name;
  if (typeof name !== "string") {
    return "cancelled";
  }
  switch (name) {
    case "SecurityError":
      // Also covers an insecure context, but the RP-ID mismatch is by far the
      // likelier cause on a deployment that has HTTPS everywhere.
      return typeof window !== "undefined" && window.isSecureContext === false
        ? "insecure-context"
        : "relying-party-mismatch";
    case "InvalidStateError":
      // The authenticator already holds a credential for this account -- the
      // excludeCredentials list did its job.
      return "already-registered";
    case "NotSupportedError":
      return "unsupported-browser";
    case "NotAllowedError":
    case "AbortError":
    default:
      // NotAllowedError is genuinely "dismissed, timed out, or refused", and
      // is the only one the user themselves caused.
      return "cancelled";
  }
}

// --------------------------------------------------------------------------- //
// base64url <-> ArrayBuffer
// --------------------------------------------------------------------------- //
/**
 * The server speaks unpadded base64url everywhere; `navigator.credentials`
 * speaks ArrayBuffer. These two functions are the whole of that boundary.
 * `atob`/`btoa` are used rather than Buffer so the same code runs in the
 * browser, which is where it is actually needed.
 */
export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64Url(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --------------------------------------------------------------------------- //
// Ceremony option conversion
// --------------------------------------------------------------------------- //
type ServerDescriptor = { type: string; id: string; transports?: string[] | null };

function toDescriptors(descriptors: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(descriptors)) {
    return [];
  }
  return descriptors
    .filter((entry): entry is ServerDescriptor =>
      Boolean(entry) && typeof (entry as ServerDescriptor).id === "string")
    .map((entry) => ({
      type: "public-key" as const,
      id: base64UrlToBytes(entry.id) as unknown as BufferSource,
      ...(Array.isArray(entry.transports) && entry.transports.length > 0
        ? { transports: entry.transports as AuthenticatorTransport[] }
        : {}),
    }));
}

/** Convert the server's registration options into what the browser expects. */
export function toCreationOptions(
  options: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const rp = options.rp as { id: string; name: string };
  const user = options.user as { id: string; name: string; displayName: string };
  return {
    rp,
    user: {
      id: base64UrlToBytes(user.id) as unknown as BufferSource,
      name: user.name,
      displayName: user.displayName,
    },
    challenge: base64UrlToBytes(options.challenge as string) as unknown as BufferSource,
    pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: options.timeout as number,
    excludeCredentials: toDescriptors(options.excludeCredentials),
    authenticatorSelection: options.authenticatorSelection as AuthenticatorSelectionCriteria,
    attestation: options.attestation as AttestationConveyancePreference,
  };
}

/** Convert the server's assertion options into what the browser expects. */
export function toRequestOptions(
  options: Record<string, unknown>,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64UrlToBytes(options.challenge as string) as unknown as BufferSource,
    rpId: options.rpId as string,
    timeout: options.timeout as number,
    allowCredentials: toDescriptors(options.allowCredentials),
    userVerification: options.userVerification as UserVerificationRequirement,
  };
}

// --------------------------------------------------------------------------- //
// Ceremony result conversion
// --------------------------------------------------------------------------- //
export type RegistrationPayload = {
  name: string;
  client_data_json: string;
  attestation_object: string;
  transports?: string[];
};

export type AssertionPayload = {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
};

/**
 * Serialise a `navigator.credentials.create()` result for the API.
 *
 * The credential ID is not sent: the server parses it out of the signed
 * attestation object instead, so there is no value in transmitting a copy the
 * server would have to ignore.
 */
export function toRegistrationPayload(
  credential: PublicKeyCredential,
  name: string,
): RegistrationPayload {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === "function" ? response.getTransports() : [];
  return {
    name,
    client_data_json: bytesToBase64Url(response.clientDataJSON),
    attestation_object: bytesToBase64Url(response.attestationObject),
    ...(transports.length > 0 ? { transports } : {}),
  };
}

/** Serialise a `navigator.credentials.get()` result for the API. */
export function toAssertionPayload(credential: PublicKeyCredential): AssertionPayload {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credential_id: credential.id,
    client_data_json: bytesToBase64Url(response.clientDataJSON),
    authenticator_data: bytesToBase64Url(response.authenticatorData),
    signature: bytesToBase64Url(response.signature),
  };
}

// --------------------------------------------------------------------------- //
// Login-response interpretation
// --------------------------------------------------------------------------- //
/**
 * Read a `/auth/login` body without trusting its shape.
 *
 * Returns the challenge state when a second factor is owed, `null` when the
 * body describes a completed login. A malformed "MFA required" body with no
 * usable token is treated as *not* a challenge, so the caller falls through to
 * its error path rather than rendering a challenge page that cannot work.
 */
export function readLoginChallenge(body: unknown): MfaLoginChallenge | null {
  if (!body || typeof body !== "object") {
    return null;
  }
  const record = body as Record<string, unknown>;
  if (record.mfa_required !== true || typeof record.mfa_token !== "string") {
    return null;
  }
  if (record.mfa_token.length === 0) {
    return null;
  }
  const methods = Array.isArray(record.mfa_methods)
    ? record.mfa_methods.filter(
      (method): method is MfaMethod =>
        method === "webauthn"
        || method === "recovery_code"
        || method === "email_code"
        || method === "enrollment",
    )
    : [];
  return {
    mfaRequired: true,
    enrollmentRequired: record.mfa_enrollment_required === true,
    methods,
    mfaToken: record.mfa_token,
  };
}

export function validateDeviceName(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 64) {
    return null;
  }
  return trimmed;
}

export function validateRecoveryCode(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  // Length only. Normalisation of separators and case is the server's job, and
  // duplicating the alphabet here would mean two places to keep in step.
  if (trimmed.length === 0 || trimmed.length > 64) {
    return null;
  }
  return trimmed;
}

export function validateEmailCode(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  // Digits only, and only as many as a code can have. Stripping separators here
  // rather than rejecting them keeps a code pasted out of a mail client -- which
  // may arrive with a space in the middle -- from being refused and pushing the
  // operator into requesting another one.
  const digits = value.replace(/\D/g, "");
  if (digits.length < 6 || digits.length > 12) {
    return null;
  }
  return digits;
}

export function validateRevokeReason(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 500) {
    return null;
  }
  return trimmed;
}

// --------------------------------------------------------------------------- //
// The pending-MFA cookie
// --------------------------------------------------------------------------- //
/**
 * The restricted post-password token is held in its own cookie, separate from
 * the session cookie, for two reasons: it must not be mistaken for a session by
 * any code that reads the session cookie, and it must be disposable
 * independently — completing or abandoning a login clears it without touching
 * anything else.
 */
export function mfaCookieName(environment = process.env.NODE_ENV): string {
  return environment === "production" ? "__Host-nodelink-mfa" : "nodelink-mfa";
}

export function mfaCookieOptions(environment = process.env.NODE_ENV) {
  return {
    httpOnly: true,
    // Short enough to expire on its own well within the server's own token TTL,
    // so an abandoned half-login does not leave a usable artefact behind.
    maxAge: 10 * 60,
    path: "/",
    priority: "high" as const,
    sameSite: "lax" as const,
    secure: environment === "production",
  };
}

/** Options that delete the cookie rather than set it. */
export function clearedMfaCookieOptions(environment = process.env.NODE_ENV) {
  return { ...mfaCookieOptions(environment), maxAge: 0 };
}
