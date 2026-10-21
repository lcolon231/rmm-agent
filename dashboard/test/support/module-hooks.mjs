// SPDX-License-Identifier: AGPL-3.0-only
// Preloaded with `--import` by `npm test` (issue #281) so the server-only
// wrappers in `src/lib` can be imported by plain Node:
//   - `@/…` resolves against `src/` the way the tsconfig `paths` entry does;
//   - `server-only` becomes an empty module (its real guard throws outside RSC);
//   - `next/headers` becomes `next-headers-stub.ts`, whose cookie jar a test
//     fills with `setRequestCookies`;
//   - `next/server` resolves to the CommonJS entry Next ships as `server.js`.
// Pure `*-core.ts` modules use relative imports and never reach these hooks.
import { existsSync } from "node:fs";
import { registerHooks } from "node:module";

const srcRoot = new URL("../../src/", import.meta.url);
const headersStub = new URL("./next-headers-stub.ts", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") {
      return { url: "data:text/javascript,", shortCircuit: true };
    }
    if (specifier === "next/headers") {
      return { url: headersStub, shortCircuit: true };
    }
    if (specifier === "next/server") {
      return nextResolve("next/server.js", context);
    }
    if (specifier.startsWith("@/")) {
      const base = new URL(specifier.slice(2), srcRoot);
      for (const extension of [".ts", ".tsx"]) {
        const candidate = new URL(`${base.href}${extension}`);
        if (existsSync(candidate)) {
          return { url: candidate.href, shortCircuit: true };
        }
      }
    }
    return nextResolve(specifier, context);
  },
});
