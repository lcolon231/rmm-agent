// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  buildDispatchRequestBody,
  type CommandDetailData,
  type CommandHistoryData,
  type DispatchInput,
} from "@/lib/command-console-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getCommandHistory(
  sessionToken: string,
  endpointId: string,
  options: { page?: number; pageSize?: number } = {},
): Promise<CommandHistoryData> {
  const query = new URLSearchParams({
    page: String(options.page ?? 1),
    page_size: String(options.pageSize ?? 25),
  });
  return nodelinkApiRequest<CommandHistoryData>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/commands?${query}`,
    { method: "GET", sessionToken },
  );
}

export async function getCommandDetail(
  sessionToken: string,
  endpointId: string,
  commandId: string,
): Promise<CommandDetailData> {
  return nodelinkApiRequest<CommandDetailData>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(commandId)}`,
    { method: "GET", sessionToken },
  );
}

export async function dispatchCommand(
  sessionToken: string,
  endpointId: string,
  input: DispatchInput,
): Promise<{ id: string; status: string }> {
  const command = await nodelinkApiRequest<{ id: string; status: string }>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/commands`,
    {
      body: JSON.stringify(buildDispatchRequestBody(input)),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  return { id: command.id, status: command.status };
}
