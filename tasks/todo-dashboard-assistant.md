# Dashboard assistant checklist

- [x] Inspect checkout and guidance; verify migration head 0037.
- [x] Write separate feature specification and plan.
- [x] Add schemas, settings, encrypted tables and migration.
- [x] Implement permission rechecks, bounded service, history, cancel and audit.
- [x] Implement all read-only tools and provider adapter.
- [x] Build dashboard session proxy and accessible investigation UI.
- [x] Verify authorization, redaction, injection, failure and bounds with fake provider.
- [x] Run backend and dashboard verification; document pilot configuration and limits.

Initial implementation verification on 2026-09-07 (before integration with main):

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

Integration with main on 2026-09-07:

- Resolved dashboard test-script and FastAPI router conflicts by retaining both
  the assistant and the incoming MFA, session-management and approval features.
- Renumbered the unreleased assistant migration to 0042 after main's 0041;
  Alembic reports one head. Updated rollout instructions and migration tests.
- Assistant/migration regression suite: 48 passed, 1 PostgreSQL-only test skipped.
  Checks include managed-session revocation during provider waits, upgrades and
  rollback preserving the existing session and approval tables.
- Full backend integration suite: 812 passed, 8 skipped. The two new managed-session
  revocation cases were verified in the separate regression run above.
- Dashboard: 298 tests passed; lint, typecheck and production build passed.
  Lint still reports the two existing shell-session-panel warnings.
