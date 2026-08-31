// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { useSyncExternalStore } from "react";

/**
 * Whether this browser can perform WebAuthn ceremonies (issue #67).
 *
 * Read through `useSyncExternalStore` rather than an effect that calls
 * `setState`: the answer is a property of an external system (the browser), not
 * derived React state, and reading it in an effect would trigger a cascading
 * re-render on every mount.
 *
 * The server snapshot is optimistic. During SSR there is no `window` to ask, and
 * rendering the controls enabled avoids a flash of "unsupported" for the
 * overwhelming majority of browsers that do support it; the client snapshot
 * corrects it on hydration. Nothing security-relevant rests on the value — it
 * only decides whether a button is disabled, and the server refuses any
 * ceremony that does not verify regardless.
 */

// The capability cannot change for the lifetime of the page, so there is
// nothing to subscribe to.
const subscribe = () => () => {};

export function useWebAuthnSupport(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => typeof window !== "undefined" && Boolean(window.PublicKeyCredential),
    () => true,
  );
}
