// SPDX-License-Identifier: AGPL-3.0-only

import {
  describeOperatorActionError,
  operatorListFromUnknown,
  operatorRecordFromUnknown,
  validateOperatorCreateInput,
  validateScriptPermissionInput,
  validateScriptPermissionRevokeInput,
  type OperatorCreateInput,
  type OperatorRecord,
  type ScriptPermissionInput,
} from "./operator-management-core.ts";

type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | {
      kind: "authenticated";
      operator: { role: "readonly" | "operator" | "admin" };
      sessionToken: string;
    };

type SessionDependency = {
  getSession: () => Promise<RouteSession>;
};

type UpstreamErrorShape = {
  status: number;
  code?: string | null;
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function isSameOriginRequest(request: Request): boolean {
  return request.headers.get("origin") === new URL(request.url).origin;
}

async function requireAdmin(
  dependencies: SessionDependency,
): Promise<{ sessionToken: string } | Response> {
  let session: RouteSession;
  try {
    session = await dependencies.getSession();
  } catch {
    return json({ error: "Operator session verification is unavailable." }, 503);
  }
  if (session.kind === "anonymous") {
    return json({ error: "Your session expired. Sign in again to manage operators." }, 401);
  }
  if (session.kind === "unavailable") {
    return json({ error: "Operator session verification is unavailable." }, 503);
  }
  if (session.operator.role !== "admin") {
    return json({ error: "Only an administrator can manage operators." }, 403);
  }
  return { sessionToken: session.sessionToken };
}

function upstreamError(error: unknown): UpstreamErrorShape | null {
  if (!error || typeof error !== "object") return null;
  const status = (error as Record<string, unknown>).status;
  const code = (error as Record<string, unknown>).code;
  if (typeof status !== "number") return null;
  return { status, code: typeof code === "string" ? code : null };
}

function actionError(
  action: Parameters<typeof describeOperatorActionError>[0],
  error: unknown,
): Response {
  const upstream = upstreamError(error);
  const described = describeOperatorActionError(
    action,
    upstream?.status ?? 503,
    upstream?.code ?? null,
  );
  return json({ error: described.message }, described.status);
}

function operatorResponse(value: unknown, status = 200): Response {
  const operator = operatorRecordFromUnknown(value);
  return operator
    ? json({ operator }, status)
    : json({ error: "The management service returned an invalid operator record." }, 502);
}

export async function handleListOperators(
  _request: Request,
  dependencies: SessionDependency & {
    listOperators: (sessionToken: string) => Promise<unknown>;
  },
): Promise<Response> {
  const admin = await requireAdmin(dependencies);
  if (admin instanceof Response) return admin;
  try {
    const operators = operatorListFromUnknown(
      await dependencies.listOperators(admin.sessionToken),
    );
    return operators
      ? json({ operators })
      : json({ error: "The management service returned invalid operator records." }, 502);
  } catch (error) {
    return actionError("list", error);
  }
}

export async function handleCreateOperator(
  request: Request,
  dependencies: SessionDependency & {
    createOperator: (
      sessionToken: string,
      input: OperatorCreateInput,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) {
    return json({ error: "Operator creation request was rejected." }, 403);
  }
  const admin = await requireAdmin(dependencies);
  if (admin instanceof Response) return admin;
  const body = await request.json().catch(() => null);
  const input = validateOperatorCreateInput(body);
  if (!input) {
    return json({ error: "Check the operator email, password, and role." }, 400);
  }
  try {
    return operatorResponse(
      await dependencies.createOperator(admin.sessionToken, input),
      201,
    );
  } catch (error) {
    return actionError("create", error);
  }
}

export async function handleGrantScriptPermission(
  request: Request,
  operatorId: string,
  dependencies: SessionDependency & {
    grantScriptPermission: (
      sessionToken: string,
      targetOperatorId: string,
      input: ScriptPermissionInput,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) {
    return json({ error: "Script-permission request was rejected." }, 403);
  }
  const admin = await requireAdmin(dependencies);
  if (admin instanceof Response) return admin;
  const body = await request.json().catch(() => null);
  const input = validateScriptPermissionInput(body);
  if (!input) {
    return json(
      { error: "Check the permission scope, target, and 3–500 character audit reason." },
      400,
    );
  }
  try {
    return operatorResponse(
      await dependencies.grantScriptPermission(admin.sessionToken, operatorId, input),
    );
  } catch (error) {
    return actionError("grant-script-permission", error);
  }
}

export async function handleRevokeScriptPermission(
  request: Request,
  operatorId: string,
  dependencies: SessionDependency & {
    revokeScriptPermission: (
      sessionToken: string,
      targetOperatorId: string,
      input: { reason: string },
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) {
    return json({ error: "Script-permission revocation request was rejected." }, 403);
  }
  const admin = await requireAdmin(dependencies);
  if (admin instanceof Response) return admin;
  const body = await request.json().catch(() => null);
  const input = validateScriptPermissionRevokeInput(body);
  if (!input) {
    return json({ error: "Enter an audit reason between 3 and 500 characters." }, 400);
  }
  try {
    return operatorResponse(
      await dependencies.revokeScriptPermission(admin.sessionToken, operatorId, input),
    );
  } catch (error) {
    return actionError("revoke-script-permission", error);
  }
}

export async function handleRevokeOperatorTokens(
  request: Request,
  operatorId: string,
  dependencies: SessionDependency & {
    revokeOperatorTokens: (
      sessionToken: string,
      targetOperatorId: string,
    ) => Promise<void>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) {
    return json({ error: "Session-revocation request was rejected." }, 403);
  }
  const admin = await requireAdmin(dependencies);
  if (admin instanceof Response) return admin;
  try {
    await dependencies.revokeOperatorTokens(admin.sessionToken, operatorId);
    return new Response(null, {
      status: 204,
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    return actionError("revoke-tokens", error);
  }
}

export type { OperatorRecord };
