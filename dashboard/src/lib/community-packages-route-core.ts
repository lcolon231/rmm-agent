// SPDX-License-Identifier: AGPL-3.0-only
// Same-origin, role-gated BFF handlers for the community repository (#74).
// Each action has a fixed minimum role, a fixed server path built only from
// URL-encoded route params, and an allowlisted request body.

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  COMMUNITY_CAPABILITIES,
  installFromUnknown,
  packageFromUnknown,
  publisherFromUnknown,
} from "./community-packages-core.ts";

type Role = "readonly" | "operator" | "admin";
type Session = { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type ResultKind = "publisher" | "package" | "install";
export type CommunityAction =
  | "createPublisher" | "addKey" | "revokeKey" | "revokePublisher" | "submit"
  | "moderate" | "revokeVersion" | "install" | "update" | "rollback";
export type CommunityDependencies = {
  getSession: () => Promise<Session>;
  mutate: (token: string, path: string, body: unknown, kind: ResultKind) => Promise<unknown>;
};

const REQUEST_ID = /^[A-Za-z0-9._:-]{8,64}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const SEMVER = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;
const capabilitySet = new Set<string>(COMMUNITY_CAPABILITIES);

// Server refusal codes are stable and non-secret; surfacing them tells the
// operator exactly which trust check failed. Anything unknown stays generic.
const REFUSALS: Record<string, string> = {
  signature_invalid: "The package signature does not verify against the registered key.",
  content_digest_mismatch: "The script content does not match the signed digest.",
  content_not_canonical: "The script content is not in canonical form; re-sign it with the publisher tool.",
  manifest_invalid: "The signed manifest is malformed.",
  manifest_publisher_mismatch: "The signing key belongs to a different publisher namespace.",
  publisher_unknown: "The manifest names an unregistered publisher.",
  publisher_key_unknown: "The signing key is not registered for this publisher.",
  publisher_key_revoked: "The signing key has been revoked.",
  publisher_revoked: "The publisher has been revoked.",
  publisher_key_invalid: "Publisher keys must be PEM Ed25519 public keys.",
  publisher_key_exists: "That key ID or key is already registered.",
  publisher_slug_exists: "That publisher namespace already exists.",
  capability_unknown: "The manifest declares an unsupported capability.",
  capability_language_mismatch: "The declared interpreter capability does not match the language.",
  capability_platform_mismatch: "The declared platform capabilities do not match the supported platforms.",
  capability_escalation_unacknowledged: "This version adds capabilities; acknowledge the escalation to approve it.",
  package_version_exists: "That version already exists with different content. Versions are immutable.",
  package_version_not_monotonic: "A new version must be greater than every existing version.",
  moderation_self_review_forbidden: "You cannot moderate a version you submitted.",
  moderation_already_final: "This version already has a final moderation decision.",
  package_version_not_approved: "Only approved versions can be installed.",
  package_version_revoked: "That version has been revoked.",
  community_package_blocked: "The package's publisher or signing key has been revoked.",
  install_capabilities_mismatch: "Accept exactly the declared capability set to continue.",
  library_name_shadowed: "A local script already uses that name; community packages never replace local scripts.",
  package_already_installed: "This package is already installed.",
  install_request_conflict: "That request ID was already used for a different change.",
  install_downgrade_requires_rollback: "Updates must move forward; use rollback for an older version.",
  install_rollback_requires_older_version: "Rollback targets must be older than the installed version.",
};

function json(body: unknown, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function mappedError(error: unknown): Response {
  const data = error && typeof error === "object" ? error as { status?: unknown; code?: unknown } : {};
  const status = typeof data.status === "number" ? data.status : 503;
  const code = typeof data.code === "string" && data.code in REFUSALS ? data.code : null;
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: code ? REFUSALS[code] : "Your role cannot perform this repository action.", code }, 403);
  if (status === 404) return json({ error: "This publisher, package, or install is unavailable." }, 404);
  if (code && [409, 422].includes(status)) return json({ error: REFUSALS[code], code }, status);
  if (status === 409) return json({ error: "The repository changed. Refresh and try again." }, 409);
  if (status === 413 || status === 422) return json({ error: "The package content or metadata is unsupported." }, 422);
  return json({ error: "The repository change could not be confirmed. Try again." }, 503);
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function onlyKeys(body: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(body).every((key) => keys.includes(key));
}
function text(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.trim().length >= min && value.trim().length <= max;
}
function capabilityArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 32
    && value.every((item) => typeof item === "string" && capabilitySet.has(item));
}
function enc(value: string | undefined): string { return encodeURIComponent(value ?? ""); }

type Spec = {
  minimum: "operator" | "admin"; kind: ResultKind; status?: number;
  path: (params: Record<string, string>) => string;
  body: (body: Record<string, unknown>) => Record<string, unknown> | null;
};

const revokeBody = (body: Record<string, unknown>) =>
  onlyKeys(body, ["request_id", "reason"]) && typeof body.request_id === "string"
    && REQUEST_ID.test(body.request_id) && text(body.reason, 3, 500)
    ? { request_id: body.request_id, reason: (body.reason as string).trim() } : null;
const transitionBody = (body: Record<string, unknown>) =>
  onlyKeys(body, ["version", "accepted_capabilities", "request_id"])
    && typeof body.version === "string" && SEMVER.test(body.version)
    && capabilityArray(body.accepted_capabilities)
    && typeof body.request_id === "string" && REQUEST_ID.test(body.request_id)
    ? { version: body.version, accepted_capabilities: body.accepted_capabilities, request_id: body.request_id } : null;

const SPECS: Record<CommunityAction, Spec> = {
  createPublisher: {
    minimum: "admin", kind: "publisher", status: 201, path: () => "/publishers",
    body: (b) => onlyKeys(b, ["slug", "display_name"]) && typeof b.slug === "string" && SLUG.test(b.slug)
      && text(b.display_name, 1, 200) ? { slug: b.slug, display_name: (b.display_name as string).trim() } : null,
  },
  addKey: {
    minimum: "admin", kind: "publisher", status: 201, path: (p) => `/publishers/${enc(p.publisherId)}/keys`,
    body: (b) => onlyKeys(b, ["key_id", "public_key_pem"]) && typeof b.key_id === "string" && KEY_ID.test(b.key_id)
      && text(b.public_key_pem, 40, 1024) && (b.public_key_pem as string).includes("BEGIN PUBLIC KEY")
      ? { key_id: b.key_id, public_key_pem: (b.public_key_pem as string).trim() } : null,
  },
  revokeKey: {
    minimum: "admin", kind: "publisher",
    path: (p) => `/publishers/${enc(p.publisherId)}/keys/${enc(p.keyId)}/revoke`, body: revokeBody,
  },
  revokePublisher: {
    minimum: "admin", kind: "publisher", path: (p) => `/publishers/${enc(p.publisherId)}/revoke`, body: revokeBody,
  },
  submit: {
    // The signed submission is forwarded byte-for-byte as JSON; the server is
    // the only party that verifies the signature.
    minimum: "operator", kind: "package", status: 201, path: () => "/submissions",
    body: (b) => onlyKeys(b, ["manifest", "content", "key_id", "signature"]) && object(b.manifest)
      && text(b.content, 1, 57_344) && typeof b.key_id === "string" && KEY_ID.test(b.key_id)
      && text(b.signature, 1, 128) ? { manifest: b.manifest, content: b.content, key_id: b.key_id, signature: b.signature } : null,
  },
  moderate: {
    minimum: "admin", kind: "package",
    path: (p) => `/packages/${enc(p.packageId)}/versions/${enc(p.version)}/moderation`,
    body: (b) => onlyKeys(b, ["state", "reason", "acknowledge_capability_escalation"])
      && (b.state === "approved" || b.state === "rejected") && text(b.reason, 3, 500)
      && (b.acknowledge_capability_escalation === undefined || typeof b.acknowledge_capability_escalation === "boolean")
      ? { state: b.state, reason: (b.reason as string).trim(),
        acknowledge_capability_escalation: b.acknowledge_capability_escalation === true } : null,
  },
  revokeVersion: {
    minimum: "admin", kind: "package",
    path: (p) => `/packages/${enc(p.packageId)}/versions/${enc(p.version)}/revoke`, body: revokeBody,
  },
  install: {
    minimum: "admin", kind: "install", status: 201, path: () => "/installs",
    body: (b) => {
      const transition = transitionBody(Object.fromEntries(
        Object.entries(b).filter(([key]) => !["package_id", "library_name"].includes(key))));
      if (!transition || !onlyKeys(b, ["package_id", "version", "accepted_capabilities", "request_id", "library_name"])
          || !text(b.package_id, 1, 36) || (b.library_name !== undefined && !text(b.library_name, 1, 200))) return null;
      return { ...transition, package_id: b.package_id,
        ...(b.library_name === undefined ? {} : { library_name: (b.library_name as string).trim() }) };
    },
  },
  update: { minimum: "admin", kind: "install", path: (p) => `/installs/${enc(p.installId)}/update`, body: transitionBody },
  rollback: { minimum: "admin", kind: "install", path: (p) => `/installs/${enc(p.installId)}/rollback`, body: transitionBody },
};

/** Resolve catch-all route segments to exactly one allowlisted action. */
export function resolveCommunityRoute(segments: string[]): { action: CommunityAction; params: Record<string, string> } | null {
  const [a, b, c, d, e] = segments; const n = segments.length;
  if (n === 1 && a === "publishers") return { action: "createPublisher", params: {} };
  if (n === 3 && a === "publishers" && c === "keys") return { action: "addKey", params: { publisherId: b } };
  if (n === 3 && a === "publishers" && c === "revoke") return { action: "revokePublisher", params: { publisherId: b } };
  if (n === 5 && a === "publishers" && c === "keys" && e === "revoke")
    return { action: "revokeKey", params: { publisherId: b, keyId: d } };
  if (n === 1 && a === "submissions") return { action: "submit", params: {} };
  if (n === 5 && a === "packages" && c === "versions" && SEMVER.test(d ?? "") && (e === "moderation" || e === "revoke"))
    return { action: e === "moderation" ? "moderate" : "revokeVersion", params: { packageId: b, version: d } };
  if (n === 1 && a === "installs") return { action: "install", params: {} };
  if (n === 3 && a === "installs" && (c === "update" || c === "rollback")) return { action: c, params: { installId: b } };
  return null;
}

const PARSERS: Record<ResultKind, (value: unknown) => unknown> = {
  publisher: publisherFromUnknown, package: packageFromUnknown, install: installFromUnknown,
};

export async function handleCommunityAction(
  request: Request, action: CommunityAction, params: Record<string, string>, dependencies: CommunityDependencies,
): Promise<Response> {
  const spec = SPECS[action];
  if (!isSameOrigin(request.headers.get("origin"), requestOrigin(request.url, request.headers.get("host"))))
    return json({ error: "The repository request was rejected." }, 403);
  const session = await dependencies.getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  const allowed = spec.minimum === "admin" ? session.operator.role === "admin" : session.operator.role !== "readonly";
  if (!allowed) return json({ error: "Your role cannot perform this repository action." }, 403);
  const raw = object(await request.json().catch(() => null));
  const body = raw ? spec.body(raw) : null;
  if (!body) return json({ error: "The request is missing required fields or contains unsupported ones." }, 400);
  try {
    const value = await dependencies.mutate(session.sessionToken, spec.path(params), body, spec.kind);
    const parsed = PARSERS[spec.kind](value);
    return parsed ? json({ result: parsed }, spec.status ?? 200)
      : json({ error: "The service returned invalid repository evidence." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}
