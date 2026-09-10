// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  patchPolicyFromUnknown,
  buildToggleBody,
  type PatchApprovalPolicy,
  type PatchApprovalPolicyDetail,
  type PatchDefaultAction,
  type PatchPolicyCreateBody,
  type PatchScope,
  type RebootPolicy,
} from "./patch-policies-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type SessionDependency = () => Promise<RouteSession>;

const scopes = new Set<PatchScope>(["global", "client", "site", "agent"]);
const defaults = new Set<PatchDefaultAction>(["approve", "deny"]);
const rebootPolicies = new Set<RebootPolicy>(["never", "if_required", "forced"]);

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorStatus(error: unknown): number {
  return error && typeof error === "object"
    && typeof (error as { status?: unknown }).status === "number"
    ? (error as { status: number }).status : 503;
}

function mappedError(error: unknown): Response {
  const status = errorStatus(error);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: "Your role cannot manage patch policies." }, 403);
  if (status === 404) return json({ error: "This policy no longer exists." }, 404);
  if (status === 409) return json({ error: "A policy with that name already exists for this scope." }, 409);
  if (status === 400 || status === 422) return json({ error: "Check the policy fields and scope target." }, 422);
  return json({ error: "The change could not be confirmed. Try again." }, 503);
}

async function authorizeAdmin(
  request: Request,
  getSession: SessionDependency,
): Promise<Response | { sessionToken: string }> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The request was rejected." }, 403);
  const session = await getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  return session.operator.role === "admin"
    ? { sessionToken: session.sessionToken }
    : json({ error: "Your role cannot manage patch policies." }, 403);
}

function isResponse(value: Response | { sessionToken: string }): value is Response {
  return value instanceof Response;
}

function validCreateBody(body: unknown): body is PatchPolicyCreateBody {
  if (typeof body !== "object" || body === null) return false;
  const b = body as Record<string, unknown>;
  const allowed = new Set([
    "name", "scope", "scope_id", "enabled", "rules", "default_action",
    "require_maintenance_window", "reboot_policy", "reboot_delay_seconds",
    "reboot_requires_no_user", "max_install_attempts",
  ]);
  if (Object.keys(b).some((key) => !allowed.has(key))) return false;
  if (typeof b.name !== "string" || b.name.trim().length < 1 || b.name.trim().length > 200) return false;
  if (!scopes.has(b.scope as PatchScope)) return false;
  const globalScope = b.scope === "global";
  if (globalScope ? b.scope_id !== null : (typeof b.scope_id !== "string" || (b.scope_id as string).length < 1 || (b.scope_id as string).length > 36)) return false;
  if (typeof b.enabled !== "boolean") return false;
  if (!Array.isArray(b.rules) || b.rules.length !== 0) return false; // v1: rules always []
  if (!defaults.has(b.default_action as PatchDefaultAction)) return false;
  if (typeof b.require_maintenance_window !== "boolean") return false;
  if (!rebootPolicies.has(b.reboot_policy as RebootPolicy)) return false;
  if (!Number.isInteger(b.reboot_delay_seconds) || (b.reboot_delay_seconds as number) < 60 || (b.reboot_delay_seconds as number) > 3600) return false;
  if (typeof b.reboot_requires_no_user !== "boolean") return false;
  if (!Number.isInteger(b.max_install_attempts) || (b.max_install_attempts as number) < 1 || (b.max_install_attempts as number) > 5) return false;
  return true;
}

export async function handlePatchPolicyCreate(
  request: Request,
  dependencies: {
    getSession: SessionDependency;
    createPolicy: (token: string, input: PatchPolicyCreateBody) => Promise<PatchApprovalPolicy>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null);
  if (!validCreateBody(body)) {
    return json({ error: "Name, scope, and valid policy defaults are required." }, 400);
  }
  const normalized: PatchPolicyCreateBody = { ...body, name: body.name.trim() };
  try {
    const policy = patchPolicyFromUnknown(await dependencies.createPolicy(authorized.sessionToken, normalized));
    return policy
      ? json({ policy }, 201)
      : json({ error: "The service returned an invalid policy." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export async function handlePatchPolicyToggle(
  request: Request,
  policyId: string,
  dependencies: {
    getSession: SessionDependency;
    getPolicy: (token: string, policyId: string) => Promise<PatchApprovalPolicyDetail>;
    revisePolicy: (token: string, policyId: string, input: ReturnType<typeof buildToggleBody>) => Promise<PatchApprovalPolicy>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || Object.keys(body).some((key) => key !== "enabled") || typeof body.enabled !== "boolean") {
    return json({ error: "The enabled flag is required." }, 400);
  }
  try {
    const detail = await dependencies.getPolicy(authorized.sessionToken, policyId);
    const toggleBody = buildToggleBody(detail, body.enabled as boolean);
    const policy = patchPolicyFromUnknown(await dependencies.revisePolicy(authorized.sessionToken, policyId, toggleBody));
    return policy
      ? json({ policy })
      : json({ error: "The service returned an invalid policy." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export async function handlePatchPolicyDelete(
  request: Request,
  policyId: string,
  dependencies: {
    getSession: SessionDependency;
    deletePolicy: (token: string, policyId: string) => Promise<void>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  try {
    await dependencies.deletePolicy(authorized.sessionToken, policyId);
    return json({ deleted: true });
  } catch (error) {
    return mappedError(error);
  }
}
