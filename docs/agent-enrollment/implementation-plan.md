# Agent enrollment implementation plan

This plan extends NodeLink's existing FastAPI, SQLAlchemy/Alembic, Next.js, Go
agent, JWT, and audit architecture. Migrations remain forward-only.

## 1. Repository analysis

- **Scope:** Identify components, trust boundaries, existing enrollment,
  deployment, models, tests, and unsupported assumptions.
- **Files/modules:** `docs/agent-enrollment/current-state-analysis.md`,
  `docs/ARCHITECTURE.md`, repository READMEs.
- **Dependencies:** None.
- **Acceptance criteria:** Analysis names the implemented enrollment flow,
  relevant files, security gaps, assumptions, and integration points.
- **Security considerations:** Do not infer tenant isolation or certificate
  identity where none exists.
- **Testing requirements:** Cross-check statements against source and tests.
- **Migration considerations:** None.
- **Rollback strategy:** Documentation-only revert.

## 2. Data model and migrations

- **Scope:** Add token lifecycle/assignment fields, agent enrollment metadata,
  operator/token audit references, and credential metadata.
- **Files/modules:** `server/app/models/models.py`,
  `server/alembic/versions/0011_agent_enrollment_management.py`,
  `server/alembic/versions/0012_repair_stamped_debug_schema.py`.
- **Dependencies:** Phase 1 decisions.
- **Acceptance criteria:** Existing rows receive safe defaults; plaintext
  tokens and credentials have no database column; indexes support list,
  status, and audit queries.
- **Security considerations:** Preserve audit events on revocation; use
  restrictive foreign-key deletion behavior; treat labels/metadata as
  untrusted data.
- **Testing requirements:** Fresh upgrade, upgrade from the integration
  baseline revision `0010`, repair of a legacy debug-created database that was
  incorrectly stamped, model round-trip, head revision, and forward-only
  rollback-policy test.
- **Migration considerations:** Backfill existing token names and created-by
  metadata as unknown; retain legacy nullable expiry only long enough to
  classify old rows.
- **Rollback strategy:** Restore a verified pre-migration backup or ship a
  forward corrective migration; Alembic downgrade remains intentionally
  disabled.

## 3. Token generation and validation service

- **Scope:** Centralize generation, hashing, status calculation, restriction
  checks, and atomic redemption.
- **Files/modules:** `server/app/core/enrollment.py`,
  `server/app/core/security.py`.
- **Dependencies:** Phase 2.
- **Acceptance criteria:** 32 random bytes minimum; SHA-256 storage only;
  required expiry; single-use default; status/expiry/use/restrictions checked
  atomically; safe generic failures.
- **Security considerations:** PostgreSQL row lock, SQLite conditional update,
  constant-shape external errors, no secret logging.
- **Testing requirements:** generation, hashing, expiry, revocation, use
  limits, restrictions, and concurrent redemption.
- **Migration considerations:** Legacy unexpired rows without expiry are
  classified as expired/unusable after a documented compatibility window or
  explicit administrator replacement.
- **Rollback strategy:** Keep old API path but do not restore unsafe
  non-atomic redemption.

## 4. Administrative API

- **Scope:** Create/list/detail/revoke tokens; paginated agent list/detail;
  dashboard summary; audit list.
- **Files/modules:** `server/app/api/management.py`,
  `server/app/schemas/schemas.py`, `server/app/api/deps.py`.
- **Dependencies:** Phases 2-3.
- **Acceptance criteria:** Plaintext appears only in create response; list and
  detail return a masked identifier; filtering/sorting/pagination are bounded;
  revocation is idempotent or returns a stable conflict; no hard delete.
- **Security considerations:** Backend role checks; organization ownership
  validation; no query parameters containing tokens; output allowlists.
- **Testing requirements:** admin/operator/viewer matrix, isolation boundary,
  validation, pagination, redaction, audit events.
- **Migration considerations:** None beyond Phase 2.
- **Rollback strategy:** Remove additive routes while retaining schema and
  audit history.

## 5. Agent enrollment API

- **Scope:** Preserve `/api/v1/enroll`, add `/api/v1/agents/enroll`, validate
  expanded metadata, atomically redeem, create agent, audit success/failure.
- **Files/modules:** `server/app/api/agents.py`,
  `server/app/core/enrollment.py`, schemas.
- **Dependencies:** Phases 2-3.
- **Acceptance criteria:** Both paths use identical secure logic; hostname and
  name restrictions are enforced; token is consumed exactly once; response
  contains only agent-operational data.
- **Security considerations:** Dedicated rate limit; source IP without trusted
  proxy spoofing; no secret or request-body audit fields; HTTPS required by
  production configuration.
- **Testing requirements:** valid/invalid/expired/revoked/concurrent,
  restrictions, rate limit, redacted failure audit.
- **Migration considerations:** Additive request/response fields only.
- **Rollback strategy:** Retain legacy path; disable the alias if necessary
  without weakening validation.

## 6. Agent credential issuance

- **Scope:** Continue per-agent random bearer credentials, add fingerprint and
  issuance/expiry metadata, renewal endpoint, and revocation enforcement.
- **Files/modules:** security/enrollment service, agent API, models, schemas.
- **Dependencies:** Phases 2 and 5.
- **Acceptance criteria:** Unique credential per enrollment; hash only at rest;
  plaintext returned only on issuance/renewal; old credential is invalid after
  renewal; revoked agent cannot authenticate.
- **Security considerations:** Bearer credentials are an interim decision;
  private-key/certificate issuance remains preferred and tracked.
- **Testing requirements:** fingerprint, renewal rotation, old-token failure,
  revoked-agent behavior.
- **Migration considerations:** Existing credentials receive unknown issuance
  metadata and continue to work.
- **Rollback strategy:** Keep current bearer authentication and disable renewal
  route; never roll back to shared credentials.

## 7. Administrative website

- **Scope:** Live enrollment dashboard, token list/create/revoke, agent
  inventory/details/revoke, audit list, loading/empty/error states.
- **Files/modules:** `dashboard/src/app/enrollment/**`,
  `dashboard/src/components/enrollment/**`, `dashboard/src/lib/enrollment-*`,
  same-origin route handlers, existing global styles/navigation.
- **Dependencies:** Phase 4 APIs.
- **Acceptance criteria:** Authenticated and role-aware; one-time token modal;
  copy action; masked list; no browser persistence/history; responsive and
  keyboard accessible.
- **Security considerations:** Server Component reads; same-origin POSTs;
  HTTP-only session; no token in analytics/logs; no automatic mutation retry.
- **Testing requirements:** create, one-time display, copy, mask, revoke,
  unauthorized, loading, empty, and API-error tests.
- **Migration considerations:** None.
- **Rollback strategy:** Remove dashboard routes independently; API remains
  usable.

## 8. Agent CLI integration

- **Scope:** Add explicit `enroll` command with server URL and token input from
  environment, no-echo prompt, stdin, or restricted secret file; preserve
  config-file enrollment.
- **Files/modules:** `agent/cmd/agent/main.go`, agent config/client/service
  packages, README and installer guidance.
- **Dependencies:** Phase 5 compatibility route.
- **Acceptance criteria:** Noninteractive deployments do not require token in
  arguments; token is never logged; identity is persisted before success;
  clear retry/revocation errors.
- **Security considerations:** Reject remote HTTP servers outside explicitly
  documented development; avoid shell history; validate secret-file
  permissions where supported.
- **Testing requirements:** input precedence, redaction, config write
  permissions, enrollment success/error, Windows credential storage.
- **Migration considerations:** Existing config files remain valid.
- **Rollback strategy:** Existing `run -config` enrollment path remains.

## 9. Audit logging

- **Scope:** Record token creation/revocation, enrollment success/failure,
  credential renewal, agent revocation, and administrative views/actions.
- **Files/modules:** `server/app/core/audit.py`, enrollment and management APIs.
- **Dependencies:** Phases 3-6.
- **Acceptance criteria:** Events contain IDs and non-secret metadata, source
  context where safe, and remain in the action transaction.
- **Security considerations:** Never include token hashes, plaintext,
  credentials, public-key bodies, notes, or sensitive request bodies.
- **Testing requirements:** event existence, actor/source associations,
  redaction assertions, chain verification.
- **Migration considerations:** Add nullable structured references without
  rewriting historical chain content.
- **Rollback strategy:** Preserve emitted audit rows; remove only future event
  generation if a route is rolled back.

## 10. Security hardening

- **Scope:** Enrollment limiter, structured redaction, production validation,
  readiness, bounded errors, validation limits, CSRF posture documentation.
- **Files/modules:** rate-limit/config/logging modules, main application,
  deployment docs.
- **Dependencies:** All backend phases.
- **Acceptance criteria:** Stable 429 and Retry-After; `/readyz` checks DB;
  production refuses unsafe URLs/config; application logs omit secrets.
- **Security considerations:** Process-local rate limiting is explicitly not
  sufficient for HA; dashboard uses SameSite cookie plus JSON same-origin
  handlers and server-side authorization.
- **Testing requirements:** thresholds, readiness failure, config validation,
  redaction.
- **Migration considerations:** None.
- **Rollback strategy:** Configuration switches may disable metrics/readiness,
  but not authorization, atomic redemption, or redaction.

## 11. Automated testing

- **Scope:** Backend, migration, frontend core/component behavior, and Go agent
  tests required by the feature.
- **Files/modules:** `server/tests/test_enrollment_management.py`,
  dashboard tests, agent tests, CI workflows if needed.
- **Dependencies:** Implemented phases.
- **Acceptance criteria:** Required cases are covered or explicitly named as
  infrastructure-blocked; concurrent single-use test passes on PostgreSQL.
- **Security considerations:** Use placeholder secrets only; assert secrets
  never occur in serialized list/detail/audit/log output.
- **Testing requirements:** Formatting, lint, type check, unit/integration,
  migration, production build.
- **Migration considerations:** Test fresh and upgrade paths.
- **Rollback strategy:** Tests remain as regression specifications even if UI
  rollout is paused.

## 12. Documentation

- **Scope:** Administrator onboarding, agent installation, security model, API
  reference, operations, environment, deployment, backup/recovery, examples.
- **Files/modules:** `docs/agent-enrollment/`, component READMEs,
  `.env.example`.
- **Dependencies:** Final behavior from earlier phases.
- **Acceptance criteria:** No real secrets; commands favor environment,
  prompt, or secret files; limitations are explicit.
- **Security considerations:** Never normalize putting tokens on command lines
  or in config management logs.
- **Testing requirements:** Link/path review and command verification.
- **Migration considerations:** Include exact `alembic upgrade head` and backup
  prerequisites.
- **Rollback strategy:** Keep security and rollback documentation even if
  deployment is deferred.

## 13. Deployment and rollback

- **Scope:** Backup, migrate, configure, deploy API/dashboard/agent, validate,
  monitor, and recover.
- **Files/modules:** deployment checklist and existing readiness/TLS/backup
  runbooks.
- **Dependencies:** All phases.
- **Acceptance criteria:** Staged order is documented; old agents retain
  protocol compatibility; database backup is verified; smoke enrollment uses
  a short-lived placeholder token.
- **Security considerations:** HTTPS, strong secrets, protected signing keys,
  shared limiter requirement for multi-worker, audit-anchor publication.
- **Testing requirements:** Production config check, migration rehearsal,
  health/readiness, dashboard build, one-time test enrollment, revocation.
- **Migration considerations:** Deploy schema before code; forward-fix or
  restore rather than downgrade.
- **Rollback strategy:** Stop new enrollment, restore the verified database
  backup when schema rollback is unavoidable, redeploy prior API/dashboard,
  revoke any credentials issued during the abandoned window, and preserve
  audit evidence.
