# NodeLink server

FastAPI backend for agent enrollment, heartbeat polling, signed command
dispatch, operator authentication, and tamper-evident audit records.

This is an early-stage system and is not production-ready. Backup/restore
tooling, production configuration enforcement, agent revocation, bounded
command results, and enrollment management are implemented; tenant isolation,
Authenticode signing, release-specific production evidence, and later-milestone
controls remain incomplete. See
[deployment readiness](../docs/DEPLOYMENT-READINESS.md).

## Requirements

- CPython 3.12 (the locked native dependencies and CI target this version;
  Python 3.14 is not supported)
- PostgreSQL 14+ for the intended deployment database
- SQLite with `aiosqlite` for local tests/development

## Setup

Windows PowerShell:

```powershell
cd server
py -3.12 -m venv .venv
& .\.venv\Scripts\Activate.ps1
python --version  # must report Python 3.12.x
python -m pip install -r requirements.txt

python scripts/gen_command_keys.py
Copy-Item .env.example .env  # replace every placeholder
python scripts/create_admin.py admin@example.com --role admin
python -m uvicorn app.main:app --reload
```

Unix:

```bash
cd server
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/gen_command_keys.py
cp .env.example .env
python scripts/create_admin.py admin@example.com --role admin
python -m uvicorn app.main:app --reload
```

Interactive API documentation is at `/docs`; health is at `/healthz`.
Signed monitoring-webhook setup, receiver verification, limits, and recovery
are documented in [`SIGNED-WEBHOOKS.md`](../docs/SIGNED-WEBHOOKS.md).

With `DEBUG=true`, the application creates missing tables on startup for local
convenience. With `DEBUG=false`, startup requires the database's Alembic
revision to exactly match this server build and fails before serving traffic if
the database is unversioned, behind, or ahead.

For a fresh database, run from `server/`:

```bash
python -m alembic upgrade head
uvicorn app.main:app
```

Alembic reads `DATABASE_URL` (or the higher-priority
`ALEMBIC_DATABASE_URL`). Existing databases created by the old debug
`create_all` path need a backup and schema review against revision `0001`
before `python -m alembic stamp 0001` followed by
`python -m alembic upgrade head`. Stamping does not validate
the schema. Migrations are forward-only: recover with a tested backup or a
forward fix, not `alembic downgrade`. See
[deployment readiness](../docs/DEPLOYMENT-READINESS.md#database-and-recovery).

### Supabase database URL on Render

For the Render Blueprint, set `DATABASE_URL` to the PostgreSQL **Session
pooler** connection string shown by Supabase's **Connect** dialog. It has this
shape:

```text
postgresql://postgres.<project-ref>:<password>@aws-<region>.pooler.supabase.com:5432/postgres
```

Do not use the Supabase project/API URL
(`https://<project-ref>.supabase.co`); it is an HTTP endpoint, not a PostgreSQL
connection string. NodeLink accepts Supabase's `postgres://` and
`postgresql://` forms and selects the required `asyncpg` SQLAlchemy driver
without logging the URL. Password characters that are reserved in URLs must
remain percent-encoded. Keep this value only in Render's secret environment
configuration.

## Current behavior

### Enrollment and heartbeat polling

An authorized operator creates a required-expiry, limited-use enrollment token
assigned to a client/site and optional endpoint restrictions. The plaintext is
returned only by the creation response; list/detail APIs expose a masked
prefix. Redemption is transactionally use-limited and creates a unique agent
credential, whose verifier is stored as a hash. Both `/api/v1/agents/enroll`
and the legacy `/api/v1/enroll` use the same validation service.

The enrolled agent posts telemetry to `/api/v1/heartbeat`; the response carries
queued commands. This is polling, not WebSocket or streaming transport.

Completed outcomes use at-least-once delivery over a command-ID idempotency
boundary. The agent heartbeat advertises protected outbox entries so the server
can expose `result_pending` separately from terminal `succeeded`/`failed`.
Exact duplicate result submissions return success without changing receipt
timestamps or duplicating audit events; conflicting duplicates fail with 409.
Commands whose dispatch lease expires are re-delivered to repair a lost
heartbeat response or stop-before-start, while the agent's durable reservation
prevents duplicate execution. `agent_completed_at` records endpoint completion
separately from the server's `completed_at` acknowledgement time.

### Signed commands

The server signs the negotiated `command-v3` canonical JSON containing
`envelope_version`, `schema_version`, `command_id`, `agent_id`, `kind`,
`payload`, canonical UTC `issued_at`, `expires_at`, a unique nonce, and
`signing_key_id`. Agents
advertise supported versions during enrollment and every heartbeat; dispatch
returns `409` until a compatible envelope is advertised. The agent verifies the
complete signed time window, key ID, and refuses replayed IDs, nonces, unknown,
or retired keys. Configure staged activation/overlap/retirement with
`COMMAND_SIGNING_KEYRING_PATH`. See the
[architecture](../docs/ARCHITECTURE.md#6-signed-command-envelope).

`GET /api/v1/signing-keys` exposes only redacted key IDs and lifecycle states so
operators can verify activation and overlap without exposing private material.

### Operator access

Management routes require operator JWT authentication. Global roles are
`readonly`, `operator`, and `admin`. Login failures are throttled per process,
and a token-generation counter supports logout-everywhere. `operator` and
`admin` may dispatch the typed `collect_inventory` operation, but arbitrary
`powershell`/`shell` execution is default-deny and needs a separate admin-granted
global, site, or agent scope. Admin has no implicit bypass. Grant/revoke reasons
and each allowed/denied decision are audited without scripts; see
[`SCRIPT-AUTHORIZATION.md`](../docs/SCRIPT-AUTHORIZATION.md). The Next.js
dashboard provides browser authentication and enrollment management; MFA,
federation, and tenant-scoped roles remain incomplete.

Administrators can create operators, change their global role, disable/re-enable
their identity, grant/revoke script permission, and revoke sessions. Creation,
role, status, permission, and revocation mutations are audited. Role and status
changes invalidate sessions; a transition to `readonly` clears script
permission, and the final active administrator cannot be demoted or disabled.
Operator deletion, password reset/change, forced initial-password rotation, and
list pagination are not implemented.

Technicians and administrators can create the first client and site used by
enrollment. Names are trimmed and normalized for uniqueness: clients are unique
deployment-wide, while sites are unique within their client. Creation is
audited without retaining plaintext names in audit detail.

### Audit records

Meaningful actions append redacted, schema-validated, monotonically sequenced,
hash-chained `AuditEvent` rows. The server can verify the local chain,
create/verify Merkle anchors over a prefix, and optionally publish anchors to
configured immutable storage with retained receipts.

## API surface

Agent-facing:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/enroll` | Enroll using a site token |
| POST | `/api/v1/agents/enroll` | Resource-oriented enrollment alias |
| POST | `/api/v1/agents/credentials/renew` | Rotate current agent credential |
| POST | `/api/v1/heartbeat` | Store telemetry, advertise pending results, and poll commands |
| POST | `/api/v1/commands/{id}/result` | Idempotently acknowledge a durable command result |

Operator/authentication:

| Method | Path | Minimum access |
|---|---|---|
| POST | `/api/v1/auth/login` | Public |
| GET | `/api/v1/auth/me` | Readonly |
| POST | `/api/v1/auth/operators` | Admin |
| GET | `/api/v1/auth/operators` | Admin |
| PUT | `/api/v1/auth/operators/{id}/role` | Admin |
| PUT | `/api/v1/auth/operators/{id}/disabled` | Admin |
| PUT | `/api/v1/auth/operators/{id}/script-permission` | Admin |
| POST | `/api/v1/auth/operators/{id}/script-permission/revoke` | Admin |
| POST | `/api/v1/auth/revoke-tokens` | Readonly |
| POST | `/api/v1/auth/operators/{id}/revoke-tokens` | Admin |
| POST/GET | `/api/v1/clients` | Operator / Readonly |
| POST | `/api/v1/sites` | Operator |
| POST | `/api/v1/enrollment-tokens` | Operator |
| GET | `/api/v1/enrollment-tokens`, `/api/v1/enrollment-tokens/{id}` | Readonly |
| POST | `/api/v1/enrollment-tokens/{id}/revoke` | Operator |
| GET | `/api/v1/enrollment-dashboard`, `/api/v1/audit/events` | Readonly |
| GET | `/api/v1/agents`, `/api/v1/agents/{id}` | Readonly |
| POST/GET | `/api/v1/agents/{id}/commands` | Operator / Readonly |
| GET | `/api/v1/audit/verify` | Readonly |
| POST/GET | `/api/v1/audit/anchors` | Operator / Readonly |
| GET | `/api/v1/audit/anchors/{id}/verify` | Readonly |

Liveness is `/healthz`, database readiness is `/readyz`, and `/metrics`
contains process-local enrollment operation counters without IDs or secrets.
See [`docs/agent-enrollment/api-reference.md`](../docs/agent-enrollment/api-reference.md).

## Tests

```bash
pip install pytest pytest-asyncio httpx aiosqlite
pytest -q
```

The server suite covers authentication/roles, operator creation and state
transitions, last-active-admin safety, client/site first-run provisioning and
duplicates, login throttling, operator-token revocation, enrollment, heartbeat,
command lifecycle, Python command signing, shared command vectors, Alembic
upgrades/revision checks, audit-chain tamper detection, and local Merkle
anchors. CI also migrates a fresh PostgreSQL 16 database.
Go-side verification and replay tests live under `agent/` and run on Linux and
Windows; Windows service and installer lifecycle automation remains open.
