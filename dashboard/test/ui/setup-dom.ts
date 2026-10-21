// SPDX-License-Identifier: AGPL-3.0-only
// Preloaded with `--import` before any component test so react-dom sees a DOM
// when it first evaluates (it decides `canUseDOM` at module load).
import { registerHooks } from "node:module";
import { afterEach } from "node:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";

GlobalRegistrator.register({ url: "http://localhost/" });
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// CSS modules resolve to their class names; plain stylesheets to nothing.
registerHooks({
  load(url, context, nextLoad) {
    if (!url.endsWith(".css")) return nextLoad(url, context);
    return {
      format: "module",
      shortCircuit: true,
      source: "export default new Proxy({}, { get: (_target, key) => String(key) });",
    };
  },
});

// Imported after registration so Testing Library binds to the happy-dom globals.
const { cleanup } = await import("@testing-library/react");
afterEach(() => cleanup());
