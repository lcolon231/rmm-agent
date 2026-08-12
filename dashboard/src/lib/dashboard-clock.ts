// SPDX-License-Identifier: AGPL-3.0-only

"use client";

/** Shared clock access for time-sensitive views (issue #211).
 *
 * Maintenance-window coverage depends on "now", which a component must not read
 * while rendering: the server and the browser would disagree and hydration would
 * mismatch. Views instead subscribe to this coarse shared clock through
 * `useSyncExternalStore`, which hands them the server's instant during hydration
 * and the browser's from then on.
 *
 * `readClock` is the deliberate exception and is only ever called from an event
 * handler, where the exact instant of the operator's action is the whole point.
 */

const CLOCK_INTERVAL_MS = 30_000;

const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;
let snapshot = Date.now();
let resolvedZone: string | null = null;

function tick(): void {
  snapshot = Date.now();
  for (const listener of listeners) listener();
}

export function subscribeToClock(listener: () => void): () => void {
  listeners.add(listener);
  if (timer === null) {
    snapshot = Date.now();
    timer = setInterval(tick, CLOCK_INTERVAL_MS);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };
}

/** Stable between ticks, as `useSyncExternalStore` requires. */
export function clockSnapshot(): number {
  return snapshot;
}

/** The instant an operator acted. Never call this during render. */
export function readClock(): number {
  return Date.now();
}

/** The zone cannot change while the tab is open, so there is nothing to watch. */
const noopUnsubscribe = () => {};
export function subscribeToTimeZone(): () => void {
  return noopUnsubscribe;
}

export function browserTimeZone(): string {
  if (resolvedZone === null) {
    try {
      resolvedZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
    } catch {
      resolvedZone = "UTC";
    }
  }
  return resolvedZone;
}

/** The server has no operator zone to offer, so it renders UTC. */
export function serverTimeZone(): string {
  return "UTC";
}
