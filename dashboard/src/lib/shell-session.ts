// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  type ShellSessionData,
  shellSessionFromUnknown,
} from "@/lib/shell-session-core";

class ShellSessionShapeError extends Error {}

function parse(value: unknown): ShellSessionData {
  const session = shellSessionFromUnknown(value);
  if (session === null) {
    throw new ShellSessionShapeError("Unexpected shell session response shape.");
  }
  return session;
}

export async function openShellSession(
  sessionToken: string,
  endpointId: string,
): Promise<ShellSessionData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/shell-sessions`,
    {
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  return parse(raw);
}

export async function getShellSession(
  sessionToken: string,
  endpointId: string,
  sessionId: string,
): Promise<ShellSessionData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(sessionId)}`,
    { method: "GET", sessionToken },
  );
  return parse(raw);
}

export async function closeShellSession(
  sessionToken: string,
  endpointId: string,
  sessionId: string,
): Promise<ShellSessionData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(sessionId)}/close`,
    {
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  return parse(raw);
}
