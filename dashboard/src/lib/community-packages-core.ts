// SPDX-License-Identifier: AGPL-3.0-only
// Fail-closed parsers and pure helpers for the moderated community script
// repository (issue #74). Every server response is allowlisted field by field;
// a value outside the documented contract yields null, never a coerced value.

export type CommunityVersionState = "submitted" | "approved" | "rejected" | "revoked" | "blocked";
export type CommunityStatus = "active" | "revoked";

export type CommunityPublisherKey = {
  key_id: string; fingerprint: string; status: CommunityStatus;
  created_by: string; created_at: string; revoked_at: string | null;
};
export type CommunityPublisher = {
  id: string; slug: string; display_name: string; status: CommunityStatus;
  created_by: string; created_at: string; revoked_at: string | null; revoked_by: string | null;
  keys: CommunityPublisherKey[];
};
export type CommunityModeration = {
  state: "approved" | "rejected"; moderated_by: string; reason_sha256: string;
  reason_bytes: number; acknowledged_capability_escalation: boolean; created_at: string;
};
export type CommunityPackageVersion = {
  id: string; version: string; state: CommunityVersionState; language: "powershell" | "shell";
  content_sha256: string; content_bytes: number; manifest_sha256: string;
  signing_key_id: string; signing_key_fingerprint: string; capabilities: string[];
  supported_platforms: string[]; description: string | null; submitted_by: string;
  submitted_at: string; revoked_at: string | null; moderation: CommunityModeration | null;
  capability_escalation: string[];
};
export type CommunityPackage = {
  id: string; publisher: string; name: string; qualified_name: string;
  publisher_status: CommunityStatus; created_at: string; updated_at: string;
  versions: CommunityPackageVersion[];
};
export type CommunityInstall = {
  id: string; package_id: string; qualified_name: string; script_id: string;
  script_version_id: string; library_version: number; installed_version: string;
  installed_by: string; created_at: string; updated_at: string;
};

export const COMMUNITY_CAPABILITIES = [
  "script.run.powershell", "script.run.shell", "platform.windows", "platform.linux",
  "platform.macos", "requires.elevation", "network.egress", "filesystem.write",
  "registry.write", "service.control",
] as const;
const capabilities = new Set<string>(COMMUNITY_CAPABILITIES);
const effectCapabilities = new Set(["requires.elevation", "network.egress", "filesystem.write",
  "registry.write", "service.control"]);
const versionStates = new Set<CommunityVersionState>(["submitted", "approved", "rejected", "revoked", "blocked"]);
const SEMVER = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;
const HEX64 = /^[0-9a-f]{64}$/;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function string(value: unknown): string | null { return typeof value === "string" && value.length > 0 ? value : null; }
function nullableString(value: unknown): string | null | undefined { return value === null ? null : string(value) ?? undefined; }
function timestamp(value: unknown): string | null {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) ? value : null;
}
function nullableTimestamp(value: unknown): string | null | undefined { return value === null ? null : timestamp(value) ?? undefined; }
function digest(value: unknown): string | null { return typeof value === "string" && HEX64.test(value) ? value : null; }
function count(value: unknown): number | null { return Number.isInteger(value) && (value as number) >= 0 ? value as number : null; }
function status(value: unknown): CommunityStatus | null { return value === "active" || value === "revoked" ? value : null; }
function capabilityList(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && capabilities.has(item))
    ? [...value] as string[] : null;
}
function all<T>(value: unknown, parse: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) return null;
  const parsed = value.map(parse);
  return parsed.some((item) => item === null) ? null : parsed as T[];
}

function keyFromUnknown(value: unknown): CommunityPublisherKey | null {
  const data = record(value); if (!data) return null;
  const keyId = string(data.key_id); const fingerprint = digest(data.fingerprint); const keyStatus = status(data.status);
  const createdBy = string(data.created_by); const createdAt = timestamp(data.created_at);
  const revokedAt = nullableTimestamp(data.revoked_at);
  if (!keyId || !fingerprint || !keyStatus || !createdBy || !createdAt || revokedAt === undefined) return null;
  return { key_id: keyId, fingerprint, status: keyStatus, created_by: createdBy, created_at: createdAt, revoked_at: revokedAt };
}

export function publisherFromUnknown(value: unknown): CommunityPublisher | null {
  const data = record(value); if (!data) return null;
  const id = string(data.id); const slug = string(data.slug); const displayName = string(data.display_name);
  const publisherStatus = status(data.status); const createdBy = string(data.created_by);
  const createdAt = timestamp(data.created_at); const revokedAt = nullableTimestamp(data.revoked_at);
  const revokedBy = nullableString(data.revoked_by); const keys = all(data.keys, keyFromUnknown);
  if (!id || !slug || !displayName || !publisherStatus || !createdBy || !createdAt
      || revokedAt === undefined || revokedBy === undefined || !keys) return null;
  return { id, slug, display_name: displayName, status: publisherStatus, created_by: createdBy,
    created_at: createdAt, revoked_at: revokedAt, revoked_by: revokedBy, keys };
}

function moderationFromUnknown(value: unknown): CommunityModeration | null | undefined {
  if (value === null) return null;
  const data = record(value); if (!data) return undefined;
  const state = data.state === "approved" || data.state === "rejected" ? data.state : null;
  const moderatedBy = string(data.moderated_by); const reasonSha = digest(data.reason_sha256);
  const reasonBytes = count(data.reason_bytes); const createdAt = timestamp(data.created_at);
  const acknowledged = typeof data.acknowledged_capability_escalation === "boolean"
    ? data.acknowledged_capability_escalation : null;
  if (!state || !moderatedBy || !reasonSha || reasonBytes === null || !createdAt || acknowledged === null) return undefined;
  return { state, moderated_by: moderatedBy, reason_sha256: reasonSha, reason_bytes: reasonBytes,
    acknowledged_capability_escalation: acknowledged, created_at: createdAt };
}

export function packageVersionFromUnknown(value: unknown): CommunityPackageVersion | null {
  const data = record(value); if (!data) return null;
  const id = string(data.id); const version = typeof data.version === "string" && SEMVER.test(data.version) ? data.version : null;
  const state = versionStates.has(data.state as CommunityVersionState) ? data.state as CommunityVersionState : null;
  const language = data.language === "powershell" || data.language === "shell" ? data.language : null;
  const contentSha = digest(data.content_sha256); const contentBytes = count(data.content_bytes);
  const manifestSha = digest(data.manifest_sha256); const keyId = string(data.signing_key_id);
  const keyFingerprint = digest(data.signing_key_fingerprint); const caps = capabilityList(data.capabilities);
  const platforms = Array.isArray(data.supported_platforms)
    && data.supported_platforms.every((item) => ["windows", "linux", "macos"].includes(String(item)))
    ? data.supported_platforms as string[] : null;
  const description = data.description === null ? null : typeof data.description === "string" ? data.description : undefined;
  const submittedBy = string(data.submitted_by); const submittedAt = timestamp(data.submitted_at);
  const revokedAt = nullableTimestamp(data.revoked_at); const moderation = moderationFromUnknown(data.moderation);
  const escalation = capabilityList(data.capability_escalation);
  if (!id || !version || !state || !language || !contentSha || contentBytes === null || !manifestSha
      || !keyId || !keyFingerprint || !caps || !platforms || description === undefined || !submittedBy
      || !submittedAt || revokedAt === undefined || moderation === undefined || !escalation) return null;
  return { id, version, state, language, content_sha256: contentSha, content_bytes: contentBytes,
    manifest_sha256: manifestSha, signing_key_id: keyId, signing_key_fingerprint: keyFingerprint,
    capabilities: caps, supported_platforms: platforms, description, submitted_by: submittedBy,
    submitted_at: submittedAt, revoked_at: revokedAt, moderation, capability_escalation: escalation };
}

export function packageFromUnknown(value: unknown): CommunityPackage | null {
  const data = record(value); if (!data) return null;
  const id = string(data.id); const publisher = string(data.publisher); const name = string(data.name);
  const qualified = string(data.qualified_name); const publisherStatus = status(data.publisher_status);
  const createdAt = timestamp(data.created_at); const updatedAt = timestamp(data.updated_at);
  const versions = all(data.versions, packageVersionFromUnknown);
  if (!id || !publisher || !name || qualified !== `${publisher}/${name}` || !publisherStatus
      || !createdAt || !updatedAt || !versions) return null;
  return { id, publisher, name, qualified_name: qualified, publisher_status: publisherStatus,
    created_at: createdAt, updated_at: updatedAt, versions };
}

export function installFromUnknown(value: unknown): CommunityInstall | null {
  const data = record(value); if (!data) return null;
  const id = string(data.id); const packageId = string(data.package_id); const qualified = string(data.qualified_name);
  const scriptId = string(data.script_id); const scriptVersionId = string(data.script_version_id);
  const libraryVersion = count(data.library_version);
  const installed = typeof data.installed_version === "string" && SEMVER.test(data.installed_version) ? data.installed_version : null;
  const installedBy = string(data.installed_by); const createdAt = timestamp(data.created_at); const updatedAt = timestamp(data.updated_at);
  if (!id || !packageId || !qualified || !scriptId || !scriptVersionId || libraryVersion === null || libraryVersion < 1
      || !installed || !installedBy || !createdAt || !updatedAt) return null;
  return { id, package_id: packageId, qualified_name: qualified, script_id: scriptId,
    script_version_id: scriptVersionId, library_version: libraryVersion, installed_version: installed,
    installed_by: installedBy, created_at: createdAt, updated_at: updatedAt };
}

export function publisherListFromUnknown(value: unknown): CommunityPublisher[] | null {
  return all(record(value)?.items, publisherFromUnknown);
}
export function packageListFromUnknown(value: unknown): { items: CommunityPackage[]; total: number } | null {
  const data = record(value); const items = all(data?.items, packageFromUnknown); const total = count(data?.total);
  return items && total !== null ? { items, total } : null;
}
export function installListFromUnknown(value: unknown): CommunityInstall[] | null {
  return all(record(value)?.items, installFromUnknown);
}

/** Side-effect capabilities (as opposed to interpreter/platform bindings). */
export function effectCapabilitiesOf(caps: string[]): string[] {
  return caps.filter((item) => effectCapabilities.has(item));
}

/** Exact-set equality: an install must accept precisely the declared set. */
export function sameCapabilitySet(left: string[], right: string[]): boolean {
  const a = [...new Set(left)].sort(); const b = [...new Set(right)].sort();
  return a.length === left.length && b.length === right.length && a.join("\n") === b.join("\n");
}

export function compareSemver(left: string, right: string): number {
  const a = left.split(".").map(Number); const b = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}

export function versionStateLabel(state: CommunityVersionState): string {
  return {
    submitted: "Awaiting moderation", approved: "Approved", rejected: "Rejected",
    revoked: "Revoked", blocked: "Blocked (publisher or key revoked)",
  }[state];
}
