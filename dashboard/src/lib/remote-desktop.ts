// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";
import {
  type MeshLaunchData,
  type RemoteDesktopAvailabilityData,
  meshLaunchFromUnknown,
  remoteDesktopAvailabilityFromUnknown,
} from "@/lib/remote-desktop-core";

class RemoteDesktopShapeError extends Error {}

export async function launchRemoteDesktop(
  sessionToken: string,
  endpointId: string,
): Promise<MeshLaunchData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/remote-desktop/launches`,
    {
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  const launch = meshLaunchFromUnknown(raw);
  if (launch === null) {
    throw new RemoteDesktopShapeError("Unexpected remote desktop launch shape.");
  }
  return launch;
}

export async function getRemoteDesktopAvailability(
  sessionToken: string,
  endpointId: string,
): Promise<RemoteDesktopAvailabilityData> {
  const raw = await nodelinkApiRequest<unknown>(
    `/api/v1/agents/${encodeURIComponent(endpointId)}/remote-desktop/availability`,
    { method: "GET", sessionToken },
  );
  const availability = remoteDesktopAvailabilityFromUnknown(raw);
  if (availability === null) {
    throw new RemoteDesktopShapeError(
      "Unexpected remote desktop availability shape.",
    );
  }
  return availability;
}
