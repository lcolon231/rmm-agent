// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  clientRecordFromUnknown,
  describeClientSiteError,
  siteRecordFromUnknown,
  validateClientCreateInput,
  validateSiteCreateInput,
  type ClientCreateInput,
  type SiteCreateInput,
} from "./client-site-management-core.ts";

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

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function sameOrigin(request: Request): boolean {
  return isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  );
}

async function requireManager(
  dependencies: SessionDependency,
): Promise<{ sessionToken: string } | Response> {
  let session: RouteSession;
  try {
    session = await dependencies.getSession();
  } catch {
    return json({ error: "Operator session verification is unavailable." }, 503);
  }
  if (session.kind === "anonymous") {
    return json({ error: "Your session expired. Sign in again to continue setup." }, 401);
  }
  if (session.kind === "unavailable") {
    return json({ error: "Operator session verification is unavailable." }, 503);
  }
  if (session.operator.role === "readonly") {
    return json({ error: "Read-only operators cannot create clients or sites." }, 403);
  }
  return { sessionToken: session.sessionToken };
}

function upstream(error: unknown): { status: number; code: string | null } {
  if (!error || typeof error !== "object") return { status: 503, code: null };
  const record = error as Record<string, unknown>;
  return {
    status: typeof record.status === "number" ? record.status : 503,
    code: typeof record.code === "string" ? record.code : null,
  };
}

export async function handleCreateClient(
  request: Request,
  dependencies: SessionDependency & {
    createClient: (
      sessionToken: string,
      input: ClientCreateInput,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!sameOrigin(request)) {
    return json({ error: "Client creation request was rejected." }, 403);
  }
  const manager = await requireManager(dependencies);
  if (manager instanceof Response) return manager;
  const input = validateClientCreateInput(await request.json().catch(() => null));
  if (!input) {
    return json({ error: "Enter a client name between 1 and 200 characters." }, 400);
  }
  try {
    const client = clientRecordFromUnknown(
      await dependencies.createClient(manager.sessionToken, input),
    );
    return client
      ? json({ client }, 201)
      : json({ error: "The management service returned an invalid client record." }, 502);
  } catch (error) {
    const { status, code } = upstream(error);
    const described = describeClientSiteError("client", status, code);
    return json({ error: described.message }, described.status);
  }
}

export async function handleCreateSite(
  request: Request,
  dependencies: SessionDependency & {
    createSite: (
      sessionToken: string,
      input: SiteCreateInput,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!sameOrigin(request)) {
    return json({ error: "Site creation request was rejected." }, 403);
  }
  const manager = await requireManager(dependencies);
  if (manager instanceof Response) return manager;
  const input = validateSiteCreateInput(await request.json().catch(() => null));
  if (!input) {
    return json(
      { error: "Select a client and enter a site name between 1 and 200 characters." },
      400,
    );
  }
  try {
    const site = siteRecordFromUnknown(
      await dependencies.createSite(manager.sessionToken, input),
    );
    return site
      ? json({ site }, 201)
      : json({ error: "The management service returned an invalid site record." }, 502);
  } catch (error) {
    const { status, code } = upstream(error);
    const described = describeClientSiteError("site", status, code);
    return json({ error: described.message }, described.status);
  }
}
