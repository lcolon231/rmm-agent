// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  type ShellFrameBatchData,
  type ShellSessionData,
  shellFrameBatchFromUnknown,
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

export async function sendShellInput(
  sessionToken: string,
  endpointId: string,
  sessionId: string,
  frame: { seq: number; data_b64: string; eof?: boolean },
): Promise<ShellSessionData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(sessionId)}/input`,
    {
      body: JSON.stringify({ ...frame, stream: "input" }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  return parse(raw);
}

export async function readShellOutput(
  sessionToken: string,
  endpointId: string,
  sessionId: string,
  after: number,
  ack: number,
): Promise<ShellFrameBatchData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(sessionId)}/output?after=${after}&ack=${ack}`,
    { method: "GET", sessionToken },
  );
  const parsed = shellFrameBatchFromUnknown(raw);
  if (parsed === null) throw new ShellSessionShapeError("Unexpected shell frame response shape.");
  return parsed;
}
