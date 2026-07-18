# NodeLink server

FastAPI backend for agent enrollment, heartbeat polling, signed command
dispatch, operator authentication, and tamper-evident audit records.

This is an early-stage scaffold. It is not production-ready: backup/restore,
production TLS enforcement, agent revocation, bounded command
results, tenant isolation, and several other Milestone 0 controls are not yet
implemented. See [deployment readiness](../docs/DEPLOYMENT-READINESS.md).

## Requirements

- Python 3.12 recommended
- PostgreSQL 14+ for the intended deployment database
- SQLite with `aiosqlite` for local tests/development

## Setup

```bash
cd server
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -r requirements.txt

python scripts/gen_command_keys.py
copy .env.example .env  # use cp on Unix; replace every placeholder
python scripts/create_admin.py admin@example.com --role admin
uvicorn app.main:app --reload
```

Interactive API documentation is at `/docs`; health is at `/healthz`.

With `DEBUG=true`, the application creates missing tables on startup for local
convenience. With `DEBUG=false`, startup requires the database's Alembic
revision to exactly match this server build and fails before serving traffic if
the database is unversioned, behind, or ahead.

For a fresh database, run from `server/`:

```bash
alembic upgrade head
uvicorn app.main:app
```

Alembic reads `DATABASE_URL` (or the higher-priority
`ALEMBIC_DATABASE_URL`). Existing databases created by the old debug
`create_all` path need a backup and schema review against revision `0001`
before `alembic stamp 0001 && alembic upgrade head`. Stamping does not validate
the schema. Migrations are forward-only: recover with a tested backup or a
forward fix, not `alembic downgrade`. See
[deployment readiness](../docs/DEPLOYMENT-READINESS.md#database-and-recovery).

## Current behavior

### Enrollment and heartbeat polling

An operator creates a client, site, and limited-use enrollment token. The agent
uses that token once and receives an agent ID, plaintext agent bearer token,
heartbeat interval, and the current Ed25519 public key. The server stores token
hashes, not plaintext tokens.

The enrolled agent posts telemetry to `/api/v1/heartbeat`; the response carries
queued commands. This is polling, not WebSocket or streaming transport.

### Signed commands

The server signs the negotiated `command-v1` canonical JSON containing
`envelope_version`, `command_id`, `agent_id`, `kind`, and `payload`. Agents
advertise supported versions during enrollment and every heartbeat; dispatch
returns `409` until `command-v1` is advertised. `expires_at` is delivered and
enforced by server and agent, but is not covered by the current signature.
There is no nonce, signing-key ID, or key rotation. See the
[architecture](../docs/ARCHITECTURE.md#6-signed-command-envelope).

### Operator access

Management routes require operator JWT authentication. Global roles are
`readonly`, `operator`, and `admin`. Login failures are throttled per process,
and a token-generation counter supports logout-everywhere. There is no browser
authentication UI, MFA, federation, tenant-scoped role, or full operator
administration API yet.

### Audit records

Meaningful actions append hash-chained `AuditEvent` rows. The server can verify
the local chain and create/verify Merkle anchors over a prefix. It does not
assign monotonic audit sequence numbers or publish anchors outside the database.

## API surface

Agent-facing:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/enroll` | Enroll using a site token |
| POST | `/api/v1/heartbeat` | Store telemetry and poll commands |
| POST | `/api/v1/commands/{id}/result` | Submit buffered command result |

Operator/authentication:

| Method | Path | Minimum access |
|---|---|---|
| POST | `/api/v1/auth/login` | Public |
| GET | `/api/v1/auth/me` | Readonly |
| POST | `/api/v1/auth/operators` | Admin |
| POST | `/api/v1/auth/revoke-tokens` | Readonly |
| POST | `/api/v1/auth/operators/{id}/revoke-tokens` | Admin |
| POST/GET | `/api/v1/clients` | Operator / Readonly |
| POST | `/api/v1/sites` | Operator |
| POST | `/api/v1/enrollment-tokens` | Operator |
| GET | `/api/v1/agents`, `/api/v1/agents/{id}` | Readonly |
| POST/GET | `/api/v1/agents/{id}/commands` | Operator / Readonly |
| GET | `/api/v1/audit/verify` | Readonly |
| POST/GET | `/api/v1/audit/anchors` | Operator / Readonly |
| GET | `/api/v1/audit/anchors/{id}/verify` | Readonly |

## Tests

```bash
pip install pytest pytest-asyncio httpx aiosqlite
pytest -q
```

The server suite covers authentication/roles, login throttling, operator-token
revocation, enrollment, heartbeat, command lifecycle, Python command signing,
shared command vectors, Alembic upgrades/revision checks, audit-chain tamper
detection, and local Merkle anchors. CI also migrates a fresh PostgreSQL 16
database.
Go-side verification and replay tests live under `agent/` and run on Linux and
Windows; Windows service and installer lifecycle automation remains open.
