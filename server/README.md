# NodeLink RMM — Server

FastAPI backend: agent enrollment, heartbeat/telemetry, signed command dispatch,
and a tamper-evident audit log.

## Requirements

- Python 3.11+
- PostgreSQL 14+ (SQLite works for local dev/tests)

## Setup

```bash
cd server
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. Generate the Ed25519 command-signing keypair (private key stays secret)
python scripts/gen_command_keys.py

# 2. Configure environment
cp .env.example .env
#    - set DATABASE_URL to your Postgres instance
#    - set SECRET_KEY:  python -c "import secrets; print(secrets.token_urlsafe(48))"

# 3. Run
uvicorn app.main:app --reload
```

Interactive API docs: http://localhost:8000/docs — health check: `/healthz`.

With `DEBUG=true`, tables are auto-created on startup for convenience. For
production, use Alembic migrations instead (scaffold under `alembic/`).

## How the pieces fit

**Enrollment.** An operator creates a Client → Site → EnrollmentToken. The
token's plaintext is shown once and handed to the agent installer. The agent
calls `POST /api/v1/enroll` with it and receives a long-lived bearer token
(stored server-side only as a SHA-256 hash) plus the command-signing **public
key**.

**Heartbeat + command poll.** The agent calls `POST /api/v1/heartbeat` every
`HEARTBEAT_INTERVAL_SECONDS` with CPU/RAM/disk/uptime. The response carries any
queued commands (a simple poll model; a WebSocket channel can replace this
later without changing the contract).

**Signed commands.** When an operator dispatches a command, the server signs a
canonical representation of it with its Ed25519 private key. The agent verifies
that signature against the public key it got at enrollment and refuses anything
that doesn't check out. This is what lets the audit log claim that a recorded
command genuinely came from the server.

**Tamper-evident audit log.** Every meaningful action appends a hash-chained
`AuditEvent`: each row commits to the previous one, so altering or deleting any
event breaks the chain from that point on. `GET /api/v1/audit/verify` walks the
chain and reports the first broken link. The `event_hash` values are the natural
unit to batch and anchor to an external verification layer later.

## Endpoints

Agent-facing (`app/api/agents.py`):

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/enroll` | Claim an agent identity with an enrollment token |
| POST | `/api/v1/heartbeat` | Submit telemetry, receive queued commands |
| POST | `/api/v1/commands/{id}/result` | Report a command's outcome |

Operator-facing (`app/api/management.py`):

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/clients` · `/sites` · `/enrollment-tokens` | Provisioning |
| GET  | `/api/v1/agents` · `/agents/{id}` | List / inspect endpoints |
| POST | `/api/v1/agents/{id}/commands` | Dispatch a signed command |
| GET  | `/api/v1/agents/{id}/commands` | Command history |
| GET  | `/api/v1/audit/verify` | Verify the audit hash chain |

> **Security note:** operator endpoints are unauthenticated in Phase 1 to keep
> the scaffold runnable. Gate them behind operator auth before any real use —
> `app.core.security.create_access_token` is already in place for this.

## Tests

```bash
pip install pytest pytest-asyncio httpx aiosqlite
pytest -q
```

The suite runs in-process against ephemeral SQLite and covers enrollment,
heartbeat, signed command dispatch/pickup, agent-side signature verification,
and audit-chain tamper detection.
