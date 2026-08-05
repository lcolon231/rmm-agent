// SPDX-License-Identifier: AGPL-3.0-only

export type OperatorRole = "readonly" | "operator" | "admin";
export type ScriptLanguage = "powershell" | "shell";
export type ScriptReviewState = "approved" | "rejected";
export type ScriptPlatform = "windows" | "linux" | "macos";

export type ScriptReview = {
  state: ScriptReviewState;
  reviewed_by: string;
  reason_sha256: string;
  reason_bytes: number;
  created_at: string;
};

export type ScriptVersion = {
  id: string;
  version: number;
  language: ScriptLanguage;
  content_sha256: string;
  content_bytes: number;
  description: string | null;
  tags: string[];
  supported_platforms: ScriptPlatform[];
  created_by: string;
  created_at: string;
  review: ScriptReview | null;
  content?: string;
};

export type ScriptItem = {
  id: string;
  name: string;
  latest_version: number;
  record_version: number;
  deprecated_at: string | null;
  deprecated_by: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  latest: ScriptVersion;
  versions?: ScriptVersion[];
};

export type ScriptList = {
  items: ScriptItem[];
  page: number;
  page_size: number;
  total: number;
};

const languages = new Set<ScriptLanguage>(["powershell", "shell"]);
const reviewStates = new Set<ScriptReviewState>(["approved", "rejected"]);
const platforms = new Set<ScriptPlatform>(["windows", "linux", "macos"]);

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function string(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function positiveInteger(value: unknown): number | null {
  return Number.isInteger(value) && (value as number) >= 0 ? value as number : null;
}

function timestamp(value: unknown): string | null {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) ? value : null;
}

function stringArray(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value : null;
}

function reviewFromUnknown(value: unknown): ScriptReview | null | undefined {
  if (value === null) return null;
  const data = record(value);
  if (!data) return undefined;
  const state = string(data.state) as ScriptReviewState | null;
  const reviewedBy = string(data.reviewed_by);
  const reasonSha = string(data.reason_sha256);
  const reasonBytes = positiveInteger(data.reason_bytes);
  const createdAt = timestamp(data.created_at);
  if (!state || !reviewStates.has(state) || !reviewedBy || !reasonSha
      || reasonSha.length !== 64 || reasonBytes === null || !createdAt) return undefined;
  return { state, reviewed_by: reviewedBy, reason_sha256: reasonSha,
    reason_bytes: reasonBytes, created_at: createdAt };
}

export function scriptVersionFromUnknown(value: unknown): ScriptVersion | null {
  const data = record(value);
  if (!data) return null;
  const id = string(data.id);
  const version = positiveInteger(data.version);
  const language = string(data.language) as ScriptLanguage | null;
  const digest = string(data.content_sha256);
  const bytes = positiveInteger(data.content_bytes);
  const description = data.description === null ? null : string(data.description);
  const tags = stringArray(data.tags);
  const supported = stringArray(data.supported_platforms) as ScriptPlatform[] | null;
  const createdBy = string(data.created_by);
  const createdAt = timestamp(data.created_at);
  const review = reviewFromUnknown(data.review);
  if (!id || version === null || version < 1 || !language || !languages.has(language)
      || !digest || digest.length !== 64 || bytes === null || description === undefined
      || !tags || !supported || !supported.every((item) => platforms.has(item))
      || !createdBy || !createdAt || review === undefined) return null;
  const content = data.content === undefined ? undefined : string(data.content);
  if (content === null) return null;
  return { id, version, language, content_sha256: digest, content_bytes: bytes,
    description, tags, supported_platforms: supported, created_by: createdBy,
    created_at: createdAt, review, ...(content === undefined ? {} : { content }) };
}

export function scriptItemFromUnknown(value: unknown): ScriptItem | null {
  const data = record(value);
  if (!data) return null;
  const id = string(data.id); const name = string(data.name);
  const latestVersion = positiveInteger(data.latest_version);
  const recordVersion = positiveInteger(data.record_version);
  const deprecatedAt = data.deprecated_at === null ? null : timestamp(data.deprecated_at);
  const deprecatedBy = data.deprecated_by === null ? null : string(data.deprecated_by);
  const createdBy = string(data.created_by); const createdAt = timestamp(data.created_at);
  const updatedAt = timestamp(data.updated_at); const latest = scriptVersionFromUnknown(data.latest);
  const versions = data.versions === undefined ? undefined
    : Array.isArray(data.versions) ? data.versions.map(scriptVersionFromUnknown) : null;
  if (!id || !name || latestVersion === null || latestVersion < 1 || recordVersion === null
      || recordVersion < 1 || deprecatedAt === undefined || deprecatedBy === undefined
      || !createdBy || !createdAt || !updatedAt || !latest
      || versions === null || versions?.some((item) => item === null)) return null;
  const latestMetadata = { ...latest };
  delete latestMetadata.content;
  const versionMetadata = versions?.map((item) => {
    const metadata = { ...item } as ScriptVersion;
    delete metadata.content;
    return metadata;
  });
  return { id, name, latest_version: latestVersion, record_version: recordVersion,
    deprecated_at: deprecatedAt, deprecated_by: deprecatedBy, created_by: createdBy,
    created_at: createdAt, updated_at: updatedAt, latest: latestMetadata,
    ...(versionMetadata === undefined ? {} : { versions: versionMetadata }) };
}

export function scriptListFromUnknown(value: unknown): ScriptList | null {
  const data = record(value);
  if (!data || !Array.isArray(data.items)) return null;
  const items = data.items.map(scriptItemFromUnknown);
  const page = positiveInteger(data.page); const pageSize = positiveInteger(data.page_size);
  const total = positiveInteger(data.total);
  if (items.some((item) => item === null) || page === null || page < 1
      || pageSize === null || pageSize < 1 || total === null) return null;
  return { items: items as ScriptItem[], page, page_size: pageSize, total };
}

export function scriptState(script: ScriptItem): "deprecated" | "draft" | ScriptReviewState {
  if (script.deprecated_at) return "deprecated";
  return script.latest.review?.state ?? "draft";
}

export function formatScriptTimestamp(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium", timeStyle: "short", timeZone: "UTC",
  }).format(new Date(value));
}
