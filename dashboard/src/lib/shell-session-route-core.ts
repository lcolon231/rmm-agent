// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for the interactive shell proxy (issue #280).
 *
 * Role floors mirror `server/app/api/shell_sessions.py`: reading a session is
 * readonly, everything that opens, drives, drains, or closes one is operator.
 * Every upstream record is re-parsed through the shell-session allowlist so a
 * field the API adds later never reaches the browser by accident.
 */

import {
  authorizeSession,
  isRecord,
  isSameOriginRequest,
  json,
  readJsonBody,
  upstreamError,
  type GetSession,
} from "./bff-route-core.ts";
import {
  shellFrameBatchFromUnknown,
  shellSessionFromUnknown,
  shellSessionOpenErrorMessage,
} from "./shell-session-core.ts";

type ShellCall = (sessionToken: string, endpointId: string, sessionId: string) => Promise<unknown>;

function sessionResponse(value: unknown, status = 200): Response {
  const session = shellSessionFromUnknown(value);
  return session
    ? json({ session }, status)
    : json({ error: "The management service returned an invalid shell session." }, 502);
}

function sessionError(error: unknown): Response {
  const upstream = upstreamError(error);
  if (!upstream) return json({ error: "The shell session could not be reached. Try again." }, 502);
  const status = upstream.status === 401 ? 401 : upstream.status === 404 ? 404 : 403;
  return json({ error: "The shell session is not available." }, status);
}

function clampStatus(status: number): number {
  return status >= 400 && status < 600 ? status : 502;
}

export async function handleOpenShellSession(
  request: Request,
  endpointId: string,
  deps: { getSession: GetSession; openShellSession: (sessionToken: string, endpointId: string) => Promise<unknown> },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Shell session request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to open a shell session.",
    forbidden: "Your role cannot open a shell session.",
  });
  if (auth instanceof Response) return auth;
  try {
    return sessionResponse(await deps.openShellSession(auth.sessionToken, endpointId), 201);
  } catch (error) {
    const upstream = upstreamError(error);
    if (!upstream) return json({ error: "The shell session could not be opened. Try again." }, 502);
    const status = upstream.status === 401 ? 401 : upstream.status === 404 ? 404 : 403;
    return json({ error: shellSessionOpenErrorMessage(upstream.code, upstream.status) }, status);
  }
}

export async function handleGetShellSession(
  _request: Request,
  endpointId: string,
  sessionId: string,
  deps: { getSession: GetSession; getShellSession: ShellCall },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: "Sign in to manage shell sessions.",
    forbidden: "Your role cannot view shell sessions.",
  });
  if (auth instanceof Response) return auth;
  try {
    return sessionResponse(await deps.getShellSession(auth.sessionToken, endpointId, sessionId));
  } catch (error) {
    return sessionError(error);
  }
}

export async function handleCloseShellSession(
  request: Request,
  endpointId: string,
  sessionId: string,
  deps: { getSession: GetSession; closeShellSession: ShellCall },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Shell session request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to manage shell sessions.",
    forbidden: "Your role cannot close shell sessions.",
  });
  if (auth instanceof Response) return auth;
  try {
    return sessionResponse(await deps.closeShellSession(auth.sessionToken, endpointId, sessionId));
  } catch (error) {
    return sessionError(error);
  }
}

export type ShellInputFrame = { seq: number; data_b64: string };

export function shellInputFromUnknown(value: unknown): ShellInputFrame | null {
  if (!isRecord(value)) return null;
  const { seq, data_b64: data } = value;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) return null;
  if (typeof data !== "string" || data.length > 24_000) return null;
  return { seq, data_b64: data };
}

export async function handleShellInput(
  request: Request,
  endpointId: string,
  sessionId: string,
  deps: {
    getSession: GetSession;
    sendShellInput: (
      sessionToken: string,
      endpointId: string,
      sessionId: string,
      frame: ShellInputFrame,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Shell input was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to use the shell.",
    forbidden: "Your role cannot use the shell.",
  });
  if (auth instanceof Response) return auth;
  const frame = shellInputFromUnknown(await readJsonBody(request));
  if (!frame) return json({ error: "Shell input is invalid." }, 400);
  try {
    return sessionResponse(await deps.sendShellInput(auth.sessionToken, endpointId, sessionId, frame));
  } catch (error) {
    const status = clampStatus(upstreamError(error)?.status ?? 502);
    return json(
      { error: status === 429 ? "The endpoint is catching up. Try again." : "Shell input could not be sent." },
      status,
    );
  }
}

function cursor(value: string | null): number | null {
  const parsed = Number(value ?? "0");
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

export async function handleShellOutput(
  request: Request,
  endpointId: string,
  sessionId: string,
  deps: {
    getSession: GetSession;
    readShellOutput: (
      sessionToken: string,
      endpointId: string,
      sessionId: string,
      after: number,
      ack: number,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to use the shell.",
    forbidden: "Your role cannot use the shell.",
  });
  if (auth instanceof Response) return auth;
  const search = new URL(request.url).searchParams;
  const after = cursor(search.get("after"));
  const ack = cursor(search.get("ack"));
  if (after === null || ack === null) return json({ error: "Shell cursor is invalid." }, 400);
  try {
    const batch = shellFrameBatchFromUnknown(
      await deps.readShellOutput(auth.sessionToken, endpointId, sessionId, after, ack),
    );
    return batch
      ? json(batch)
      : json({ error: "The management service returned invalid shell output." }, 502);
  } catch (error) {
    const status = clampStatus(upstreamError(error)?.status ?? 502);
    return json(
      { error: status === 409 ? "The live output window expired. Reopen the shell." : "Live output could not be reached." },
      status,
    );
  }
}
