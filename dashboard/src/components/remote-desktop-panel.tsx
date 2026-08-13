// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { LoaderCircle, MonitorUp, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import {
  describeRemoteDesktopAvailability,
  meshLaunchFromUnknown,
  remoteDesktopAvailabilityFromUnknown,
  type MeshLaunchData,
} from "@/lib/remote-desktop-core";

const UNAVAILABLE = {
  canLaunch: false,
  message: "Remote desktop is unavailable for this endpoint right now.",
};

/**
 * Launches an authorized, audited MeshCentral remote-desktop session. MeshCentral
 * is a separate trust boundary: NodeLink mints a short-lived, single-device login
 * URL which this panel opens in a new tab. The URL is used immediately and never
 * retained. Availability is fetched fail-closed from the server on mount and is
 * re-checked after each launch (rate limits, mapping drift).
 */
export function RemoteDesktopPanel({ endpointId }: { endpointId: string }) {
  const [availability, setAvailability] = useState<
    { canLaunch: boolean; message: string } | null
  >(null);
  const [busy, setBusy] = useState(false);
  const [launch, setLaunch] = useState<MeshLaunchData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(
          `/api/endpoints/${encodeURIComponent(endpointId)}/remote-desktop/availability`,
          { cache: "no-store" },
        );
        const raw: unknown = await response.json();
        if (cancelled) return;
        const parsed = response.ok
          ? remoteDesktopAvailabilityFromUnknown(
              (raw as { availability?: unknown }).availability,
            )
          : null;
        setAvailability(parsed ? describeRemoteDesktopAvailability(parsed) : UNAVAILABLE);
      } catch {
        if (!cancelled) setAvailability(UNAVAILABLE);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [endpointId, refreshTick]);

  const startLaunch = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/endpoints/${encodeURIComponent(endpointId)}/remote-desktop/launches`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          cache: "no-store",
        },
      );
      const raw: unknown = await response.json();
      if (!response.ok) {
        setError(
          (raw as { error?: string }).error ??
            "The remote desktop session could not be launched.",
        );
        return;
      }
      const parsed = meshLaunchFromUnknown((raw as { launch?: unknown }).launch);
      if (parsed === null || !parsed.login_url) {
        setError("The remote desktop session could not be launched.");
        return;
      }
      setLaunch(parsed);
      // Open the single-use MeshCentral login URL immediately; it is never stored.
      window.open(parsed.login_url, "_blank", "noopener,noreferrer");
    } catch {
      setError("The remote desktop session could not be launched. Try again.");
    } finally {
      setBusy(false);
      // Re-check availability for the next launch (rate limit, mapping drift).
      setRefreshTick((tick) => tick + 1);
    }
  }, [endpointId]);

  return (
    <section className="shell-panel" aria-labelledby="remote-desktop-title">
      <header>
        <div>
          <span className="eyebrow">
            <MonitorUp size={13} /> Remote access
          </span>
          <h2 id="remote-desktop-title">Remote desktop</h2>
          <p>
            Launches a MeshCentral session in a separate tab. MeshCentral is a
            separate trust boundary with its own logs; NodeLink authorizes and
            audits the launch.
          </p>
        </div>
        <div className="shell-actions">
          <button
            type="button"
            disabled={!availability?.canLaunch || busy}
            onClick={startLaunch}
          >
            {busy ? (
              <LoaderCircle className="spin" size={15} />
            ) : (
              <MonitorUp size={15} />
            )}{" "}
            Launch remote desktop
          </button>
        </div>
      </header>
      {availability && !availability.canLaunch ? (
        <div className="shell-unavailable">
          <ShieldAlert size={14} /> {availability.message}
        </div>
      ) : null}
      {launch && launch.login_expires_at ? (
        <footer>
          <span>
            Session opened in a new tab. The access link expires at{" "}
            {new Date(launch.login_expires_at).toLocaleTimeString()}.
          </span>
        </footer>
      ) : null}
      {error ? (
        <p className="shell-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
