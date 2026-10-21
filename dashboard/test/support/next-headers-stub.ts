// SPDX-License-Identifier: AGPL-3.0-only
// Stand-in for `next/headers` under `npm test` (see module-hooks.mjs). Only the
// read side of `cookies()` is modelled: no wrapper under test writes cookies
// through it, and an accidental write should fail loudly rather than pass.
let jar = new Map<string, string>();

export function setRequestCookies(values: Record<string, string>): void {
  jar = new Map(Object.entries(values));
}

export async function cookies() {
  return {
    get: (name: string) => (jar.has(name) ? { name, value: jar.get(name)! } : undefined),
  };
}
