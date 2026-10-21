// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for the remote-desktop proxy (issue #280).
 *
 * Role floors mirror `server/app/api/meshcentral.py`: availability is readonly,
 * a launch is operator. Records are re-parsed through the remote-desktop
 * allowlist; a launch's one-time `login_url` is the only secret that may pass.
 */

import {
  authorizeSession,
  isSameOriginRequest,
  json,
  upstreamError,
  type GetSession,
} from "./bff-route-core.ts";
import {
  meshLaunchFromUnknown,
  remoteDesktopAvailabilityFromUnknown,
  remoteDesktopLaunchErrorMessage,
} from "./remote-desktop-core.ts";

type EndpointCall = (sessionToken: string, endpointId: string) => Promise<unknown>;

const AVAILABILITY_UNAVAILABLE = "Remote desktop availability is unavailable.";
const passthroughLaunchStatuses = new Set([401, 404, 409, 429, 503]);

export async function handleRemoteDesktopAvailability(
  _request: Request,
  endpointId: string,
  deps: { getSession: GetSession; getRemoteDesktopAvailability: EndpointCall },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: "Sign in to view remote desktop availability.",
    forbidden: "Your role cannot view remote desktop availability.",
  });
  if (auth instanceof Response) return auth;
  try {
    const availability = remoteDesktopAvailabilityFromUnknown(
      await deps.getRemoteDesktopAvailability(auth.sessionToken, endpointId),
    );
    return availability ? json({ availability }) : json({ error: AVAILABILITY_UNAVAILABLE }, 502);
  } catch (error) {
    const status = upstreamError(error)?.status;
    return json({ error: AVAILABILITY_UNAVAILABLE }, status === 401 || status === 404 ? status : 502);
  }
}

export async function handleLaunchRemoteDesktop(
  request: Request,
  endpointId: string,
  deps: { getSession: GetSession; launchRemoteDesktop: EndpointCall },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Remote desktop request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: "Sign in to launch a remote desktop session.",
    forbidden: "Your role cannot launch remote desktop sessions.",
  });
  if (auth instanceof Response) return auth;
  try {
    const launch = meshLaunchFromUnknown(await deps.launchRemoteDesktop(auth.sessionToken, endpointId));
    return launch
      ? json({ launch }, 201)
      : json({ error: "The remote desktop session could not be launched. Try again." }, 502);
  } catch (error) {
    const upstream = upstreamError(error);
    if (!upstream) {
      return json({ error: "The remote desktop session could not be launched. Try again." }, 502);
    }
    const status = passthroughLaunchStatuses.has(upstream.status) ? upstream.status : 403;
    return json({ error: remoteDesktopLaunchErrorMessage(upstream.code, upstream.status) }, status);
  }
}
