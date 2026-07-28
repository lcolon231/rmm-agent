# Agent enrollment release notes for v0.1.2

Status: **code candidate; not approved for tagging or production deployment**

The immutable release manifest, verified deployment backup, PostgreSQL upgrade
rehearsal, canary result, and rollback evidence are tracked by
[GitHub issue #127](https://github.com/lcolon231/rmm-agent/issues/127). Do not
create or tag `release-notes/v0.1.2.json` with placeholder evidence.

## Scope delivered

- Temporary enrollment tokens generated from at least 256 bits of entropy.
- Hash-only token storage, one-time plaintext display, mandatory expiry, and
  single-use defaults.
- Token assignment metadata, restrictions, pagination, filtering, sorting,
  status, revocation, and audit history.
- Transactional token redemption with PostgreSQL row locking and an atomic
  SQLite test fallback.
- Agent inventory/details, heartbeat visibility, credential fingerprints, and
  agent revocation.
- Authenticated enrollment dashboard with one-time copy, masked token values,
  accessible states, confirmation dialogs, and server-enforced role checks.
- Go `enroll` command with hidden interactive input, environment variable,
  restricted secret file, and standard-input methods.
- Structured secret-redacting logs, enrollment rate limiting, readiness,
  liveness, and Prometheus-format enrollment/agent counters.
- Next.js and its matching lint configuration updated from 16.2.10 to 16.2.12
  to remove the direct patched framework advisories.
- Forward-only enrollment migrations `0011` and `0012`, including repair of
  legacy debug-created SQLite schemas that were incorrectly stamped.
- Administrator, installer, API, security, operations, analysis, decision, and
  implementation documentation.

## Compatibility and upgrade order

The compatibility API `POST /api/v1/enroll` remains available. The
resource-oriented alias is `POST /api/v1/agents/enroll`. Existing per-agent
bearer authentication remains the runtime identity model.

The integration baseline is Alembic `0010`; v0.1.2 enrollment code requires
head `0012`. Migrations are forward-only.

1. Stop enrollment and command rollout automation.
2. Verify and retain an encrypted database backup and its immutable manifest.
3. Set the server Python environment to Python 3.12 and install the project
   requirements.
4. Run `python -m alembic current`, then `python -m alembic upgrade head`.
5. Confirm `python -m alembic current` reports `0012`.
6. Deploy the server and dashboard together.
7. Verify `/healthz`, `/readyz`, production configuration validation, login,
   and enrollment dashboard access.
8. Enroll one owned Windows canary with a single-use, short-lived token.
9. Verify heartbeat, token use count, audit events, metrics, and revocation
   before expanding the rollout.

Do not downgrade the database in place. Prefer a forward fix. Restore the
verified pre-upgrade backup only through the approved rollback decision path,
with the data-loss boundary understood and post-backup tokens/credentials
revoked as required.

## Known limitations and release issues

| Issue | Impact |
|---|---|
| [#127](https://github.com/lcolon231/rmm-agent/issues/127) | Tag is blocked until immutable release/backup/canary/rollback evidence exists. |
| [#128](https://github.com/lcolon231/rmm-agent/issues/128) | The patched Next.js version still resolves PostCSS/Sharp versions reported by the production dependency audit; resolve or formally time-bound the exception before tagging. |
| [#24](https://github.com/lcolon231/rmm-agent/issues/24) | Windows agent and installer are not Authenticode signed. |
| [#125](https://github.com/lcolon231/rmm-agent/issues/125) | Per-agent bearer credentials do not expire or rotate automatically. |
| [#126](https://github.com/lcolon231/rmm-agent/issues/126) | An empty deployment must bootstrap its first client/site outside the enrollment area. |
| [#66](https://github.com/lcolon231/rmm-agent/issues/66) | Roles are global; clients/sites are not authorization tenants. |
| [#84](https://github.com/lcolon231/rmm-agent/issues/84) | Enrollment limits and in-memory counters are process-local, so HA/multi-worker guarantees are not claimed. |

Additional residual risks and decisions are recorded in
[`open-issues.md`](open-issues.md) and [`decisions.md`](decisions.md).

## Verification completed during development

- Server enrollment, authorization, audit, migration, redaction, rate-limit,
  revocation, and renewal-foundation tests.
- Dashboard lint, TypeScript type checking, unit tests, and production build.
- Full Go tests, `go vet`, and agent build.
- Manual Windows flow: administrator login, token creation, hidden-input
  enrollment, protected identity persistence, heartbeat display, credential
  fingerprint display, and chain-of-custody audit view.

The final release gate must rerun these checks from the rebased commit and add
the PostgreSQL/production-like evidence in #127.

## Completed page descriptions

- **Enrollment dashboard:** agent/token totals, active/offline/revoked states,
  recent enrollments, and recent failures.
- **Enrollment tokens:** searchable, filterable, sortable, paginated inventory
  with status, assignments, use counts, expiry, creator, and revoke action.
- **Create token:** validated assignment/restriction form followed by a
  one-time plaintext panel, copy action, and safe installation command.
- **Agent inventory:** searchable agent identity, organization/site metadata,
  platform/version, heartbeat, enrollment date, and trust state.
- **Agent details:** metadata, heartbeat, credential fingerprint, enrollment
  chain of custody, audit events, and confirmed revoke action.
- **Audit log:** filterable enrollment/token/agent events with redacted failure
  metadata.

## Placeholder enrollment workflow

1. Sign in as an authorized administrator.
2. Create a token named `Tampa canary`, assign it to the placeholder
   organization/site, set a short expiry, and keep `max_uses` at `1`.
3. Copy the one-time value into a secret manager or the
   `AGENT_ENROLLMENT_TOKEN` environment variable.
4. On the owned canary endpoint run:

   ```powershell
   $env:AGENT_ENROLLMENT_TOKEN = '<TEMPORARY-TOKEN>'
   .\rmm-agent.exe enroll `
     --server 'https://management.example.invalid' `
     --token-env 'AGENT_ENROLLMENT_TOKEN' `
     --name 'canary-01'
   Remove-Item Env:AGENT_ENROLLMENT_TOKEN
   ```

5. Start the agent/service and verify its heartbeat and audit event.
6. Confirm a second redemption of the single-use token is rejected.
7. Revoke the canary agent and confirm subsequent authenticated requests are
   rejected without exposing internal details.

All values above are placeholders. Never place a real token in a URL, source
file, screenshot, log, analytics event, issue, or shell command argument.
