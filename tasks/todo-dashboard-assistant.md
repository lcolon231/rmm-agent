# Dashboard assistant checklist

- [x] Inspect checkout and guidance; verify migration head 0037.
- [x] Write separate feature specification and plan.
- [x] Add schemas, settings, encrypted tables and migration.
- [x] Implement permission rechecks, bounded service, history, cancel and audit.
- [x] Implement all read-only tools and provider adapter.
- [x] Build dashboard session proxy and accessible investigation UI.
- [x] Verify authorization, redaction, injection, failure and bounds with fake provider.
- [x] Run backend and dashboard verification; document pilot configuration and limits.

Verification on 2026-09-07:

- Full backend rerun: 627 passed, 8 skipped. Two existing Windows-sensitive
  chronological-order tests now use explicit, distinct fixture timestamps.
- Final focused assistant/retention/redaction rerun after missing-data and quota
  refinements: 89 passed (31 assistant tests).
- Dashboard: 223 tests passed; typecheck and production build passed; lint passed
  with two pre-existing warnings in `shell-session-panel.tsx`.
- Production Next.js + FastAPI HTTP smoke with disposable data and fake provider:
  login/session, assistant server rendering, offline question, device links and
  last-seen timestamps, private history and CSRF rejection passed.
- Migration graph: 0038 is the sole head. Fresh/forward migration checks and
  0038 downgrade/upgrade with table/foreign-key assertions passed.
- No provider credential detected; no real-provider smoke test performed.
- Browser surface unavailable; interactive visual verification not performed.
- PostgreSQL multi-worker contention remains a pilot-environment check.
- Temporary smoke processes stopped; no deployment, merge, secret provisioning,
  or changes to the existing untracked work.
