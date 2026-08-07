// SPDX-License-Identifier: AGPL-3.0-only

export type OperatorRole = "readonly" | "operator" | "admin";
export type ScriptLanguage = "powershell" | "shell";
export type ScriptReviewState = "approved" | "rejected";
export type ScriptPlatform = "windows" | "linux" | "macos";
export type ScriptParameterKind = "string" | "number" | "boolean" | "choice" | "secret";
export type ScriptParameterValue = string | number | boolean;

export type ScriptParameter = {
  key: string;
  label: string;
  description: string | null;
  kind: ScriptParameterKind;
  required: boolean;
  has_default: boolean;
  default_value: ScriptParameterValue | null;
  min_length: number | null;
  max_length: number | null;
  minimum: number | null;
  maximum: number | null;
  choices: string[] | null;
};

export type ScriptParameterValueSet = {
  id: string; script_id: string; script_version_id: string; version: number;
  request_id: string; state: "available" | "expired";
  provided_keys: string[]; defaulted_keys: string[]; secret_keys: string[];
  values_fingerprint: string; created_by: string; created_at: string; expires_at: string;
};

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
  parameters: ScriptParameter[];
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
const parameterKinds = new Set<ScriptParameterKind>(["string", "number", "boolean", "choice", "secret"]);

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

function nullableNumber(value: unknown): number | null | undefined {
  return value === null ? null : typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function parameterFromUnknown(value: unknown): ScriptParameter | null {
  const data = record(value); if (!data) return null;
  const key = string(data.key); const label = string(data.label);
  const description = data.description === null ? null : string(data.description);
  const kind = string(data.kind) as ScriptParameterKind | null;
  const required = typeof data.required === "boolean" ? data.required : null;
  const hasDefault = typeof data.has_default === "boolean" ? data.has_default : null;
  const defaultValue = data.default_value === null ? null
    : typeof data.default_value === "string" || typeof data.default_value === "boolean"
      || typeof data.default_value === "number" && Number.isFinite(data.default_value)
      ? data.default_value as ScriptParameterValue : undefined;
  const minLength = nullableNumber(data.min_length); const maxLength = nullableNumber(data.max_length);
  const minimum = nullableNumber(data.minimum); const maximum = nullableNumber(data.maximum);
  const choices = data.choices === null ? null : stringArray(data.choices);
  if (!key || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || !label || !kind
      || !parameterKinds.has(kind) || required === null || hasDefault === null
      || description === undefined || defaultValue === undefined || minLength === undefined
      || maxLength === undefined || minimum === undefined || maximum === undefined
      || choices === null && data.choices !== null || kind === "secret" && hasDefault) return null;
  return { key, label, description, kind, required, has_default: hasDefault,
    default_value: defaultValue, min_length: minLength, max_length: maxLength,
    minimum, maximum, choices };
}

export function scriptParameterValueSetFromUnknown(value: unknown): ScriptParameterValueSet | null {
  const data = record(value); if (!data) return null;
  const id = string(data.id); const scriptId = string(data.script_id);
  const scriptVersionId = string(data.script_version_id); const version = positiveInteger(data.version);
  const requestId = string(data.request_id); const state = string(data.state);
  const provided = stringArray(data.provided_keys); const defaulted = stringArray(data.defaulted_keys);
  const secret = stringArray(data.secret_keys); const fingerprint = string(data.values_fingerprint);
  const createdBy = string(data.created_by); const createdAt = timestamp(data.created_at);
  const expiresAt = timestamp(data.expires_at);
  if (!id || !scriptId || !scriptVersionId || version === null || version < 1 || !requestId
      || state !== "available" && state !== "expired" || !provided || !defaulted || !secret
      || !fingerprint || fingerprint.length !== 64 || !createdBy || !createdAt || !expiresAt) return null;
  return { id, script_id: scriptId, script_version_id: scriptVersionId, version,
    request_id: requestId, state, provided_keys: provided, defaulted_keys: defaulted,
    secret_keys: secret, values_fingerprint: fingerprint, created_by: createdBy,
    created_at: createdAt, expires_at: expiresAt };
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
  const parameters = Array.isArray(data.parameters) ? data.parameters.map(parameterFromUnknown) : null;
  const createdBy = string(data.created_by);
  const createdAt = timestamp(data.created_at);
  const review = reviewFromUnknown(data.review);
  if (!id || version === null || version < 1 || !language || !languages.has(language)
      || !digest || digest.length !== 64 || bytes === null || description === undefined
      || !tags || !supported || !supported.every((item) => platforms.has(item))
      || !parameters || parameters.some((item) => item === null)
      || !createdBy || !createdAt || review === undefined) return null;
  const content = data.content === undefined ? undefined : string(data.content);
  if (content === null) return null;
  return { id, version, language, content_sha256: digest, content_bytes: bytes,
    description, tags, supported_platforms: supported, parameters: parameters as ScriptParameter[], created_by: createdBy,
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
