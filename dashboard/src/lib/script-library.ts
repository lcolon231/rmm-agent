// SPDX-License-Identifier: AGPL-3.0-only
import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  scriptItemFromUnknown,
  scriptListFromUnknown,
  scriptVersionFromUnknown,
  scriptParameterValueSetFromUnknown,
  type ScriptItem,
  type ScriptLanguage,
  type ScriptList,
  type ScriptPlatform,
  type ScriptParameterKind,
  type ScriptParameterValueSet,
  type ScriptReviewState,
  type ScriptVersion,
} from "@/lib/script-library-core";

export type ScriptVersionInput = {
  language: ScriptLanguage; content: string; description?: string;
  tags: string[]; supported_platforms: ScriptPlatform[];
  parameters: Array<{
    key: string; label: string; description?: string; kind: ScriptParameterKind;
    required: boolean; default_value?: string | number | boolean;
    min_length?: number; max_length?: number; minimum?: number; maximum?: number;
    choices?: string[];
  }>;
};

function requireValue<T>(value: T | null, message: string): T {
  if (!value) throw new Error(message);
  return value;
}
export async function listScripts(token: string): Promise<ScriptList> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/script-library?page_size=100", { sessionToken: token });
  return requireValue(scriptListFromUnknown(value), "Invalid script list response.");
}

export async function getScript(token: string, id: string): Promise<ScriptItem> {
  const value = await nodelinkApiRequest<unknown>(`/api/v1/script-library/${encodeURIComponent(id)}`, { sessionToken: token });
  return requireValue(scriptItemFromUnknown(value), "Invalid script detail response.");
}

export async function getScriptVersion(token: string, id: string, version: number): Promise<ScriptVersion> {
  const value = await nodelinkApiRequest<unknown>(`/api/v1/script-library/${encodeURIComponent(id)}/versions/${version}`, { sessionToken: token });
  return requireValue(scriptVersionFromUnknown(value), "Invalid script version response.");
}

async function mutate(token: string, path: string, body: unknown): Promise<ScriptItem> {
  const value = await nodelinkApiRequest<unknown>(path, { sessionToken: token,
    method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
  return requireValue(scriptItemFromUnknown(value), "Invalid script mutation response.");
}

export function createScript(token: string, input: ScriptVersionInput & { name: string }) {
  return mutate(token, "/api/v1/script-library", input);
}
export function addScriptVersion(token: string, id: string, input: ScriptVersionInput) {
  return mutate(token, `/api/v1/script-library/${encodeURIComponent(id)}/versions`, input);
}
export function reviewScript(token: string, id: string, version: number, state: ScriptReviewState, reason: string) {
  return mutate(token, `/api/v1/script-library/${encodeURIComponent(id)}/versions/${version}/review`, { state, reason });
}
export function deprecateScript(token: string, id: string, expectedRecordVersion: number, requestId: string, reason: string) {
  return mutate(token, `/api/v1/script-library/${encodeURIComponent(id)}/deprecate`, {
    expected_record_version: expectedRecordVersion, request_id: requestId, reason,
  });
}

export async function prepareScriptParameterValues(
  token: string, id: string, version: number, requestId: string,
  values: Record<string, string | number | boolean>,
): Promise<ScriptParameterValueSet> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/script-library/${encodeURIComponent(id)}/versions/${version}/parameter-value-sets`,
    { sessionToken: token, method: "POST", body: JSON.stringify({ request_id: requestId, values }),
      headers: { "Content-Type": "application/json" } },
  );
  return requireValue(scriptParameterValueSetFromUnknown(value), "Invalid parameter evidence response.");
}
