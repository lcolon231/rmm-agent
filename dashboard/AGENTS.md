<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

# Tests

`npm test` runs two tiers with the built-in `node --test` runner (no Jest, no Vitest). CI runs it in the `dashboard (Next.js)` job.

- **Core tier** (`test/*.test.ts`): pure `src/lib/*-core.ts` logic under `--experimental-strip-types`. List new files explicitly in the `test` script.
- **Component and page tier** (`npm run test:ui`, `test/ui/**/*.test.tsx`): renders real components with `@testing-library/react` on a `happy-dom` DOM.
  - `tsx` is the loader because strip-types cannot parse JSX or resolve the `@/` alias.
  - `test/ui/setup-dom.ts` is preloaded with `--import`. It registers DOM globals before react-dom loads, stubs `.css` imports, and runs `cleanup()` after each test.
  - Stub the network with `t.mock.method(globalThis, "fetch", ...)` and assert on the request each control sends. Never call a live API.
  - Components that call `useRouter()` need an `AppRouterContext.Provider` (see `command-dispatch-form.test.tsx`).
  - Server pages are async functions. Swap their `server-only` loaders and `next/navigation` with `mock.module(...)` (`--experimental-test-module-mocks`), `await` the page, then render the element it returns (see `endpoint-page.test.tsx`).
  - Query by role and label, as an operator would. Each test should pin a security or behavior guarantee: what is hidden, what is refused, what never reaches a URL, what is rendered as text.
- Playwright is out of scope for unit work. The browser-level check stays the CI page-load smoke test.
