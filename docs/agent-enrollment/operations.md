# Enrollment operations and deployment

## Environment variables

Existing server variables remain required. Enrollment adds:

| Variable | Default | Purpose |
|---|---:|---|
| `ENROLLMENT_RATE_LIMIT_ATTEMPTS` | `10` | Attempts per source window |
| `ENROLLMENT_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding-window seconds |
| `ENROLLMENT_TOKEN_DEFAULT_EXPIRY_HOURS` | `24` | API default expiry |
| `ENROLLMENT_TOKEN_MAX_EXPIRY_DAYS` | `30` | Administrator cap |
| `ENROLLMENT_TOKEN_MAX_USES` | `100` | Reusable-token cap |

Also configure `ENVIRONMENT`, `DEBUG`, `DATABASE_URL`, `SECRET_KEY`,
`PUBLIC_BASE_URL`, command signing key/keyring, heartbeat policy, and optional
trusted proxy settings. The dashboard continues to require the server-only
`NODELINK_API_BASE_URL`; never create a `NEXT_PUBLIC_` copy.

Production validation rejects nonpositive enrollment policy and limit values,
debug mode, weak/default secrets, missing signing material, and non-HTTPS public
URLs.

## Database migration

From `server/`:

```bash
python -m alembic current
python -m alembic upgrade head
```

Revision `0011` adds token metadata, agent enrollment/credential metadata, and
audit query references. Existing tokens retain `expires_at = NULL`; the new
service treats them as expired rather than preserving indefinite enrollment
access. Revision `0012` repairs legacy debug-created SQLite schemas that were
stamped without all enrollment columns. Replace old tokens intentionally.

Migrations are forward-only. Never run downgrade in production.

`alembic stamp` only writes a revision marker; it does not apply or validate
schema changes. Never infer a stamp revision from table presence or from a
successful later migration. Legacy debug-created databases require a
column/index comparison against the proposed revision or the forward repair in
revision `0012`.

## Deployment order

1. Stop token creation or announce a brief enrollment maintenance window.
2. Create and verify an encrypted PostgreSQL backup using the existing backup
   runbook.
3. Rehearse restore into an isolated database.
4. Deploy migrations `0011` and `0012`.
5. Deploy FastAPI.
6. Verify `/healthz`, `/readyz`, production configuration, and audit chain.
7. Deploy the dashboard.
8. Deploy the agent binary/installer only after API compatibility smoke tests.
9. Create a short-lived single-use test token with placeholder assignments.
10. Enroll a disposable endpoint, confirm heartbeat, revoke the agent, and
    verify audit/metrics without printing secrets.

Old agents retain `/api/v1/enroll` compatibility.

## Database backup and recovery

Follow `docs/BACKUP-RESTORE.md` and preserve:

- PostgreSQL database;
- command signing key/keyring;
- JWT secret rotation plan;
- Caddy/TLS configuration;
- external audit-anchor destination and receipts;
- release artifacts/configuration.

A database restore can roll agent/token trust state backward. After recovery:

1. compare the restored audit chain with external anchor receipts;
2. identify credentials/tokens issued after the backup;
3. revoke/re-enroll affected agents;
4. revoke every token whose state is uncertain;
5. rotate operator sessions and signing material when compromise is plausible.

## Monitoring

Poll:

- `/healthz` for liveness;
- `/readyz` for database readiness;
- `/metrics` for process counters and current agent-status gauges;
- `/api/v1/enrollment-dashboard` for state counts;
- `/api/v1/audit/publication-status` for anchor lag.

Alert on:

- sustained enrollment failures/rate limiting;
- unexpected reusable token creation;
- active tokens near maximum expiry;
- repeated agent revocation/renewal;
- readiness failures;
- external audit-anchor lag;
- sudden offline-agent increase.

Operation counters are process-local; agent-status gauges are read from the
database on scrape. Aggregate every worker at the collector (without summing
the duplicated gauges) or adopt a shared metrics backend before HA.

## Structured logging and redaction

Do not log or trace:

- request bodies for enrollment/token creation/renewal;
- Authorization headers or cookies;
- token plaintext/digests;
- agent bearer credentials/verifiers;
- private keys;
- administrator notes.

Safe fields include action, token/agent/organization IDs, status, restriction
presence booleans, source IP, duration, and stable non-secret failure category.
Configure proxy/access logs to exclude bodies and redact headers.

The application emits JSON request events containing only request ID, method,
path (without query), status, duration, and source IP. Its recursive redactor
replaces values under token, credential, authorization, cookie, password,
secret, and private-key field names as defense in depth.

## Deployment checklist

- [ ] PostgreSQL 14+ primary selected for enrollment writes.
- [ ] Encrypted backup and isolated restore verified.
- [ ] `python -m alembic upgrade head` reaches `0012`.
- [ ] Strong `SECRET_KEY` and protected command signing keys.
- [ ] `PUBLIC_BASE_URL` is the reachable HTTPS origin.
- [ ] uvicorn bound to loopback/private proxy-only interface.
- [ ] `TRUST_PROXY_HEADERS` matches the actual topology.
- [ ] Caddy/proxy excludes sensitive headers/bodies from logs.
- [ ] Enrollment expiry/use/rate policies reviewed.
- [ ] Single worker or shared-limiter limitation accepted.
- [ ] Dashboard server-only API origin configured.
- [ ] Admin/operator/viewer accounts verified.
- [ ] `/healthz`, `/readyz`, and metrics monitored.
- [ ] External audit-anchor publication configured.
- [ ] Test enrollment and revocation evidence reviewed.
- [ ] Installer/binary verification policy documented.

## Rollback checklist

Application rollback may be possible while keeping additive schema `0012`,
but only when the tag-specific compatibility record explicitly permits it.

- [ ] Disable new token creation/enrollment at the proxy if behavior is unsafe.
- [ ] Redeploy the previous dashboard.
- [ ] Redeploy the previous API only after confirming it tolerates additive
  nullable/defaulted columns.
- [ ] Do not downgrade Alembic.
- [ ] Revoke tokens/credentials issued during the failed deployment when their
  delivery state is uncertain.
- [ ] Verify audit chain and publish an external anchor.
- [ ] If database restoration is unavoidable, stop writes, restore the verified
  pre-deployment backup, then execute the post-restore trust reconciliation.
- [ ] Record rollback reason, window, affected identities, and final validation.

## Local development

Backend:

```powershell
cd server
py -3.12 -m venv .venv
& .\.venv\Scripts\Activate.ps1
python --version  # must report Python 3.12.x
python -m pip install -r requirements.txt
python -m alembic upgrade head
python -m uvicorn app.main:app --reload
```

Dashboard:

```bash
cd dashboard
npm ci
npm audit --omit=dev
npm run dev
```

Agent:

```bash
cd agent
go test ./...
go build ./cmd/agent
```

Use loopback URLs and placeholder secrets only. Never commit `.env`, token
values, generated identities, or private signing keys.

## Verification commands

```bash
# Backend
python -m pytest -q

# Dashboard
npm run lint
npm run typecheck
npm test
npm run build
npm run smoke:production

# Agent
go test ./...
```

On Windows CI, also run service lifecycle, DPAPI/ACL, installer, and signed
release verification jobs under an account able to inspect protected files.
