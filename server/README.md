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

There is no self-service password reset. An operator who is locked out is
recovered out-of-band by someone with database access:

```bash
python scripts/reset_password.py admin@example.com            # prompts, hidden
python scripts/reset_password.py admin@example.com --clear-mfa  # lost the key too
```

The reset bumps the token generation and closes every live session for the
account, and is recorded on the audit chain as `operator.password_reset`.

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

### Script library and typed parameters

The library is a custody register for reusable PowerShell and POSIX-shell
source. It stores and reviews scripts; it does not schedule or execute them, and
it does not change an operator's separate script-execution scope. Versions are
append-only: content, metadata, and parameter definitions are fixed when the
version is created, and each version takes exactly one final `approved` or
`rejected` review. Deprecation is terminal and admin-only.

Each version carries up to 32 ordered, immutable parameter definitions of kind
`string`, `number`, `boolean`, `choice`, or `secret`. Changing a definition
requires a new version and a new review. Defaults are validated against their
own bounds at definition time, a defaulted parameter cannot also be required,
and `secret` parameters may never declare a default.

`POST /api/v1/script-library/{id}/versions/{version}/parameter-value-sets`
resolves per-run values for an **approved, non-deprecated exact version**.
Explicit values win, then defaults apply, then missing required keys fail.
Values are type-checked without coercion and bounded to 32 keys and 32,768
canonical UTF-8 bytes. The resolved document is stored as a single AES-256-GCM
ciphertext bound by authenticated data to its script-version and value-set IDs;
the response and audit record expose only safe metadata — provided/defaulted/
secret key **names**, a keyed HMAC-SHA256 fingerprint, creator, request ID, and
expiry. No endpoint decrypts or returns values, and plaintext never reaches an
audit row, a log line, or the browser.

`request_id` is the idempotency boundary per version: the same ID with the same
values returns the original set, and the same ID with different values returns
`409`. Sets expire (24 hours by default) and an expired set reports state
`expired` on retry rather than receiving a fresh lifetime.

Set `SCRIPT_PARAMETER_ENCRYPTION_KEY` to a **urlsafe-base64 32-byte** key,
generated separately from `WEBHOOK_SECRET_ENCRYPTION_KEY` and kept stable while
any prepared set can still be consumed:

```bash
python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Preparation fails closed with `503` and code `parameter_encryption_unavailable`
when that key is absent or malformed; nothing is persisted and no audit event
claims success. `SCRIPT_PARAMETER_VALUE_TTL_SECONDS`,
`SCRIPT_PARAMETER_MAX_VALUES_BYTES`, and
`SCRIPT_PARAMETER_MAX_SETS_PER_VERSION` bound lifetime and volume.

Prepared values are not yet dispatched to any agent. The signed `command-v3`
envelope is unchanged, and issue #49 must negotiate a parameter-aware dispatch
contract before values are consumed. See
[`SCRIPT-LIBRARY.md`](../docs/SCRIPT-LIBRARY.md).

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
| POST/GET | `/api/v1/script-library` | Operator / Readonly |
| GET | `/api/v1/script-library/{id}`, `/api/v1/script-library/{id}/versions/{version}` | Readonly |
| POST | `/api/v1/script-library/{id}/versions` | Operator |
| POST | `/api/v1/script-library/{id}/versions/{version}/parameter-value-sets` | Operator |
| POST | `/api/v1/script-library/{id}/versions/{version}/review` | Admin |
| POST | `/api/v1/script-library/{id}/deprecate` | Admin |
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
anchors. Script-library coverage in `tests/test_script_library.py` and
`tests/test_script_parameters.py` adds immutability, role gating, typed
validation, cross-platform quoting, AEAD binding, idempotency/conflict,
expired-state, and fail-closed missing-key behavior. CI also migrates a fresh
PostgreSQL 16 database.
Go-side verification and replay tests live under `agent/` and run on Linux and
Windows; Windows service and installer lifecycle automation remains open.
