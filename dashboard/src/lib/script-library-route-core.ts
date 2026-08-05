// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import { scriptItemFromUnknown, type ScriptReviewState } from "./script-library-core.ts";

type Role = "readonly" | "operator" | "admin";
type Session = { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type GetSession = () => Promise<Session>;

function json(body: unknown, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}
function statusOf(error: unknown): number {
  return error && typeof error === "object" && typeof (error as { status?: unknown }).status === "number"
    ? (error as { status: number }).status : 503;
}

function mappedError(error: unknown): Response {
  const status = statusOf(error);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: "Your role cannot perform this library action." }, 403);
  if (status === 404) return json({ error: "This script or version is unavailable." }, 404);
  if (status === 409) return json({ error: "The script changed or is in a final state. Refresh and try again." }, 409);
  if (status === 413 || status === 422) return json({ error: "The script content or metadata is unsupported." }, 422);
  return json({ error: "The script-library change could not be confirmed. Try again." }, 503);
}

async function authorize(request: Request, getSession: GetSession, minimum: "operator" | "admin") {
  if (!isSameOrigin(request.headers.get("origin"), requestOrigin(request.url, request.headers.get("host"))))
    return json({ error: "The script-library request was rejected." }, 403);
  const session = await getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  const allowed = minimum === "admin" ? session.operator.role === "admin" : session.operator.role !== "readonly";
  return allowed ? { token: session.sessionToken } : json({ error: "Your role cannot perform this library action." }, 403);
}

function isResponse(value: Response | { token: string }): value is Response { return value instanceof Response; }
function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function validText(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.trim().length >= min && value.trim().length <= max;
}
function validVersionInput(body: Record<string, unknown>, includeName: boolean): boolean {
  const allowed = new Set(["language", "content", "description", "tags", "supported_platforms", ...(includeName ? ["name"] : [])]);
  return !Object.keys(body).some((key) => !allowed.has(key))
    && (!includeName || validText(body.name, 1, 200))
    && (body.language === "powershell" || body.language === "shell")
    && validText(body.content, 1, 57_344)
    && (body.description === undefined || validText(body.description, 0, 2_000))
    && Array.isArray(body.tags) && body.tags.length <= 20
    && body.tags.every((tag) => typeof tag === "string" && /^[a-z0-9][a-z0-9._-]{0,49}$/i.test(tag.trim()))
    && Array.isArray(body.supported_platforms) && body.supported_platforms.length >= 1
    && body.supported_platforms.length <= 3
    && body.supported_platforms.every((platform) => ["windows", "linux", "macos"].includes(String(platform)));
}

function mutationResult(value: unknown, status = 200) {
  const script = scriptItemFromUnknown(value);
  return script ? json({ script }, status) : json({ error: "The service returned invalid script evidence." }, 502);
}

export async function handleScriptCreate(request: Request, dependencies: {
  getSession: GetSession; createScript: (token: string, input: never) => Promise<unknown>;
}) {
  const auth = await authorize(request, dependencies.getSession, "operator"); if (isResponse(auth)) return auth;
  const body = object(await request.json().catch(() => null));
  if (!body || !validVersionInput(body, true)) return json({ error: "Name, language, content, and a supported platform are required." }, 400);
  try { return mutationResult(await dependencies.createScript(auth.token, body as never), 201); }
  catch (error) { return mappedError(error); }
}

export async function handleScriptVersionCreate(request: Request, scriptId: string, dependencies: {
  getSession: GetSession; addVersion: (token: string, id: string, input: never) => Promise<unknown>;
}) {
  const auth = await authorize(request, dependencies.getSession, "operator"); if (isResponse(auth)) return auth;
  const body = object(await request.json().catch(() => null));
  if (!body || !validVersionInput(body, false)) return json({ error: "Language, content, and a supported platform are required." }, 400);
  try { return mutationResult(await dependencies.addVersion(auth.token, scriptId, body as never), 201); }
  catch (error) { return mappedError(error); }
}

export async function handleScriptReview(request: Request, scriptId: string, version: number, dependencies: {
  getSession: GetSession; review: (token: string, id: string, version: number, state: ScriptReviewState, reason: string) => Promise<unknown>;
}) {
  const auth = await authorize(request, dependencies.getSession, "admin"); if (isResponse(auth)) return auth;
  const body = object(await request.json().catch(() => null));
  if (!body || Object.keys(body).some((key) => !["state", "reason"].includes(key))
      || (body.state !== "approved" && body.state !== "rejected") || !validText(body.reason, 3, 500)
      || !Number.isInteger(version) || version < 1) return json({ error: "A final decision and review reason are required." }, 400);
  try { return mutationResult(await dependencies.review(auth.token, scriptId, version, body.state, body.reason.trim())); }
  catch (error) { return mappedError(error); }
}

export async function handleScriptDeprecate(request: Request, scriptId: string, dependencies: {
  getSession: GetSession; deprecate: (token: string, id: string, expected: number, requestId: string, reason: string) => Promise<unknown>;
}) {
  const auth = await authorize(request, dependencies.getSession, "admin"); if (isResponse(auth)) return auth;
  const body = object(await request.json().catch(() => null));
  if (!body || !Number.isInteger(body.expected_record_version) || (body.expected_record_version as number) < 1
      || !validText(body.request_id, 8, 64) || !/^[A-Za-z0-9._:-]+$/.test(body.request_id)
      || !validText(body.reason, 3, 500)) return json({ error: "A current record version, request id, and reason are required." }, 400);
  try { return mutationResult(await dependencies.deprecate(auth.token, scriptId,
    body.expected_record_version as number, body.request_id, body.reason.trim())); }
  catch (error) { return mappedError(error); }
}
