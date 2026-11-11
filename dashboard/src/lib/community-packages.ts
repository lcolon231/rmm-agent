// SPDX-License-Identifier: AGPL-3.0-only
import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  installFromUnknown,
  installListFromUnknown,
  packageFromUnknown,
  packageListFromUnknown,
  publisherFromUnknown,
  publisherListFromUnknown,
  type CommunityInstall,
  type CommunityPackage,
  type CommunityPublisher,
} from "@/lib/community-packages-core";

function requireValue<T>(value: T | null, message: string): T {
  if (!value) throw new Error(message);
  return value;
}

export async function listCommunityPublishers(token: string): Promise<CommunityPublisher[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/community/publishers", { sessionToken: token });
  return requireValue(publisherListFromUnknown(value), "Invalid publisher list response.");
}

export async function listCommunityPackages(token: string) {
  const value = await nodelinkApiRequest<unknown>("/api/v1/community/packages?page_size=100", { sessionToken: token });
  return requireValue(packageListFromUnknown(value), "Invalid package list response.");
}

export async function listCommunityInstalls(token: string): Promise<CommunityInstall[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/community/installs", { sessionToken: token });
  return requireValue(installListFromUnknown(value), "Invalid install list response.");
}

async function post(token: string, path: string, body: unknown): Promise<unknown> {
  return nodelinkApiRequest<unknown>(`/api/v1/community${path}`, {
    sessionToken: token, method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
  });
}

/** Map a dashboard mutation onto the one server endpoint it may reach. */
export async function communityMutation(
  token: string, path: string, body: unknown, kind: "publisher" | "package" | "install",
): Promise<CommunityPublisher | CommunityPackage | CommunityInstall> {
  const value = await post(token, path, body);
  const parsed = kind === "publisher" ? publisherFromUnknown(value)
    : kind === "package" ? packageFromUnknown(value) : installFromUnknown(value);
  return requireValue(parsed, "Invalid community repository response.");
}
