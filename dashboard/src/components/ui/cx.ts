// SPDX-License-Identifier: AGPL-3.0-only

/** Join class names, dropping falsy entries. */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/** Shared 2px focus ring, offset 2px, on every interactive element. */
export const focusRing = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--focus)";
