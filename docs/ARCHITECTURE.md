# NodeLink RMM — Architecture & Roadmap

This document is the single source of truth for what NodeLink RMM is, how it's
built, and where it's going. It reflects the code as it actually exists (not the
aspirational bits in some of the older READMEs — see "Known drift" at the end).

If you're an AI coding agent or a new contributor: **read this first.** Then, for
anything security-related, read `docs/threat-model.md`, which is the most
accurate security doc in the repo.

---

## 1. What this is

A self-hosted Remote Monitoring & Management (RMM) platform for an MSP
(NodeLink) serving small businesses and medical offices — an open alternative to
commercial RMMs like Atera, NinjaOne, and Tactical RMM.

Two design priorities distinguish it:

1. **Outbound-only agent connectivity.** Agents dial the server; the server
   never dials agents. No inbound firewall changes at client sites — important
   for medical offices.
2. **Cryptographically verifiable, tamper-evident audit log.** Every meaningful
   action is recorded in an append-only hash chain, so the record of what was
   done (and by whom) can be shown to be un-altered. This matters for HIPAA
   clients.

It also serves as a portfolio project demonstrating full-stack plus security
engineering.

---

## 2. High-level architecture

Three parts live in one repository:

```
  Operator (human)                     Agent (machine, one per endpoint)
      | JWT auth                            | enrollment token, then bearer token
      v                                     v
  +---------------------------- server/ (FastAPI) ----------------------------+
  |  auth  |  agent-facing API  |  management API  |  audit log  |  offline   |
  |        |  (enroll/heartbeat)|  (dispatch etc.) |  hash chain |  sweeper   |
  +---------------------------------------------------------------------------+
      |
      v
  Database (PostgreSQL in prod, SQLite for dev/tests)
```

The transport today is **plain HTTP with polling**: the agent's heartbeat doubles
as the command poll (the heartbeat response carries any queued commands). There
is no WebSocket and no TLS termination in the scaffold yet — both are planned
(see Roadmap and Known drift).

| Component | Stack | Status |
|-----------|-------|--------|
| `server/` | FastAPI, SQLAlchemy 2 (async), Pydantic 2 | Working |
| `agent/`  | Go 1.22, stdlib-only except `golang.org/x/sys` (Windows service) | Working, incl. Gate 2 |
| `docs/`   | Markdown (this file + threat model) | — |
| Dashboard | Next.js | **Not started** (Phase 2) — referenced in root README but does not exist |

---

## 3. The server (`server/`)

FastAPI application, async SQLAlchemy, Pydantic v2. Runs on Python 3.12 for local
development. (The README says 3.11+, and the code only strictly needs 3.10+ for
its `X | None` unions, but **use 3.12** — newer Pythons like 3.14 lack prebuilt
wheels for `asyncpg`/`pydantic-core` and fail to install without a C/Rust
toolchain.)

### 3.1 Data model (`app/models/models.py`)

```
Client ──< Site ──< EnrollmentToken
                └──< Agent ──< Heartbeat
                          └──< Command
Operator   (standalone)
AuditEvent (standalone, append-only hash chain)
```

- **Client / Site** — the customer org and its locations.
- **EnrollmentToken** — one-time-ish token (configurable `max_uses`, expiry,
  revocable) used by an installer to enroll agents at a site. Only its SHA-256
  hash is stored; the plaintext is shown exactly once at creation.
- **Agent** — an enrolled endpoint. Holds `token_hash` (SHA-256 of its
  long-lived bearer token), host info, `status` (pending/online/offline),
  `last_seen_at`, and an `inventory` JSON snapshot.
- **Heartbeat** — one telemetry sample (CPU/mem/disk %, uptime, logged-in user).
- **Command** — `kind` (powershell/shell/collect_inventory), `payload` (JSON),
  base64 Ed25519 `signature`, `status`, captured `exit_code`/`stdout`/`stderr`,
  and timestamps including `expires_at`.
- **Operator** — a human user: `email` (unique), bcrypt `password_hash`, `role`
  (readonly/operator/admin), `disabled`.
- **AuditEvent** — append-only record with `prev_hash` + `event_hash` forming a
  hash chain, plus `ts_iso` (the exact string that was hashed, stored so
  verification never depends on DB datetime round-tripping).

### 3.2 API surface

All routes are mounted under `/api/v1` (plus an unauthenticated `/healthz`).

**Auth (`app/api/auth.py`)**

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/auth/login` | Email + password → JWT | Public |
| POST | `/auth/operators` | Create an operator | admin |
| GET  | `/auth/me` | Return the calling operator | readonly+ |

**Agent-facing (`app/api/agents.py`)**

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/enroll` | Claim identity via enrollment token; returns `agent_id`, one-time `agent_token`, heartbeat interval, and the Ed25519 **public key** | Enrollment token |
| POST | `/heartbeat` | Submit telemetry; response carries queued commands (this is also the command poll) | Agent bearer token |
| POST | `/commands/{id}/result` | Report exit code/stdout/stderr | Agent bearer token |

**Management / operator-facing (`app/api/management.py`)** — the whole router
requires at least `readonly`, so nothing here is anonymous.

| Method | Path | Purpose | Min role |
|--------|------|---------|----------|
| POST | `/clients` | Create client | operator |
| GET  | `/clients` | List clients | readonly |
| POST | `/sites` | Create site | operator |
| POST | `/enrollment-tokens` | Mint enrollment token (plaintext once) | operator |
| GET  | `/agents` | List agents | readonly |
| GET  | `/agents/{id}` | Inspect one agent | readonly |
| POST | `/agents/{id}/commands` | Queue + sign a command | operator |
| GET  | `/agents/{id}/commands` | Command history | readonly |
| GET  | `/audit/verify` | Walk the audit hash chain | readonly |

### 3.3 Background work

`app/core/tasks.py` runs an **offline sweeper**: agents that were `online` but
haven't been seen for `heartbeat_interval_seconds * offline_after_missed`
(default 60 × 3 = 180s) are flipped to `offline`, and an `agent.offline` audit
event is written.

---

## 4. The agent (`agent/`)

Go 1.22. A single static binary. Standard-library-only **except**
`golang.org/x/sys` (used solely for the Windows service integration). Linux/macOS
builds are pure stdlib.

### 4.1 Package layout (`agent/internal/`)

- **config** — install-time `Config` (`server_url`, `enrollment_token`,
  `heartbeat_seconds`) and the persisted `Identity` (`agent_id`, `agent_token`,
  `command_public_key` PEM, `server_url`), saved as `identity.json` (mode 0600)
  beside the config.
- **client** — HTTP client for the server API: `Enroll`, `Heartbeat`,
  `ReportResult`. 30s timeout; bearer auth on everything except enroll.
- **telemetry** — per-OS metrics: Linux via `/proc` + `statfs`; Windows via
  PowerShell CIM queries; other OSes return zeros so the agent still checks in.
- **executor** — runs verified commands with a 5-minute timeout. Windows:
  `powershell.exe` for powershell/collect_inventory, `cmd.exe /C` for shell.
  Unix: `/bin/sh -c`, or `pwsh` for powershell if on PATH.
- **verify** — Ed25519 command-signature verification (the security-critical
  path — see §5).
- **service** — the OS-independent runtime (enroll/check-in loop, backoff,
  rotating log) plus the Windows SCM integration.

### 4.2 The check-in loop

Entry point is `cmd/agent/main.go` → `service.NewAgent(...)` → `Agent.Run(ctx)`.
The loop (in `internal/service/runner.go`):

1. **`loadSession`** — load config (missing/bad config is fatal, no retry). Then
   `ensureEnrolled`: if `identity.json` exists, use it; otherwise enroll with the
   token from config (network errors here are retried with backoff), then save
   the identity 0600. Parse the command public key.
2. **`checkIn`** (every heartbeat interval) — collect telemetry, POST a
   heartbeat, and for each returned command call `processCommand`.
3. **`processCommand`** — verify the Ed25519 signature. On failure: **refuse**,
   log `REFUSING command ...`, and report a failure result **without executing**.
   On success: run it via the executor, then report the result.

On a failed heartbeat the loop backs off (exponential + jitter); on success it
resets and sleeps the interval.

> Note: the heartbeat interval always comes from the server's enroll response
> (`identity.HeartbeatSeconds`). The local `Config.HeartbeatSeconds` override is
> documented but not currently read.

### 4.3 Running as a Windows service (Gate 2)

The binary is both the CLI and the service. Subcommands (from
`cmd/agent/main.go`):

```
rmm-agent run       (default)   -config FILE (default config.json), -once
rmm-agent install               -config FILE   (copies config beside the binary)
rmm-agent uninstall             (idempotent)
rmm-agent start
rmm-agent stop
rmm-agent help
```

`rmm-agent -config config.json` still works because `run` is the default
subcommand. When launched by the Windows SCM, the binary detects that from the
environment and goes straight into service mode.

What the service integration provides (`internal/service/service_windows.go`,
`runner.go`, `backoff.go`, `rotatelog.go`):

- **Service identity:** `NodeLinkAgent` ("NodeLink RMM Agent"), auto-start at
  boot.
- **Crash recovery:** SCM restart after 5s / 15s / 60s, failure counter reset
  after 24h. If the runtime exits on a fatal error it returns non-zero so the SCM
  applies recovery.
- **Graceful shutdown:** on Stop/Shutdown, no new commands start; an in-flight
  command gets a 20s grace period, then is force-killed so no child process is
  orphaned.
- **Logging:** rotating file log at `%ProgramData%\NodeLink\logs\rmm-agent.log`
  (10 MB × 5 backups). Foreground runs still log to stdout.
- **Network resilience:** exponential backoff with jitter on unreachable server —
  a down server means "keep retrying quietly," not a crash or a tight loop.

On non-Windows, the service subcommands return "only supported on Windows."

---

## 5. Security model

This is the heart of the system. `docs/threat-model.md` has the full treatment;
this is the summary.

**Operator auth (authN).** `POST /auth/login` verifies email + bcrypt password
and returns an HS256 JWT (subject = operator id, 60-min default lifetime).
`get_current_operator` validates the token on every management request. Login is
hardened against account enumeration: unknown-email and wrong-password return an
identical 401, and a dummy hash verification runs on unknown emails to keep
timing constant.

**Authorization (authZ).** Three roles, ranked `readonly < operator < admin`.
`require_role(minimum)` builds a dependency that 403s if the caller's rank is too
low. AuthZ depends on authN — identity first, permission second. (401 = "who are
you"; 403 = "not allowed".)

**Agent identity.** A long-lived bearer token issued at enrollment; the server
stores only its SHA-256 hash (single SHA-256 is appropriate for a high-entropy
token, unlike a human password).

**Command authenticity (the critical path).** The server signs every command
with an Ed25519 private key. The agent verifies against the public key it
received at enrollment and **refuses any command that fails**. What's signed is
the canonical encoding of `{command_id, agent_id, kind, payload}`:

```python
# server: app/core/security.py
json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

The Go agent reproduces this exactly, including disabling Go's default HTML
escaping of `<`, `>`, `&` (Python doesn't escape those). **This cross-language
canonical encoding is the single most fragile seam in the system** — if the two
sides ever diverge by a byte, every signature fails. It is pinned by tests on
both sides (see §6); never change the encoding on one side without the other, and
never without versioning it.

Because `agent_id` is inside the signed document, a valid command for one agent
cannot be replayed against a different agent.

**Audit log.** Append-only, hash-chained: each event's `event_hash` is
`SHA-256` over `{prev_hash, ts, actor, action, agent_id, detail}`, so altering or
deleting any event breaks the chain from that point forward. Events:
`agent.enrolled`, `command.dispatched` (records the operator's email as actor),
`command.completed`, `agent.offline`. `GET /api/v1/audit/verify` walks the chain
and returns the first broken link, if any.

---

## 6. Tests

**Server** (`server/tests/`, pytest + httpx ASGI transport, ephemeral SQLite):

- `test_auth.py` — identical 401 for wrong-password vs unknown-email; login
  returns a token; management refuses unauthenticated callers; read-only can read
  but gets 403 on provisioning/dispatch; dispatch records the operator email in
  the audit event.
- `test_e2e.py` — full lifecycle (enroll → online → dispatch → pickup → verify →
  result → succeeded); tampered payload fails verification; audit chain verifies,
  then a direct DB edit makes it report broken.

**Agent** (Go):

- `internal/verify/verify_test.go` — the **cross-language signature test**: pins
  Go's canonical output against literal Python `json.dumps(...)` strings,
  including a case with `>` and `&`, an empty payload, and nested key sorting.
- `internal/service/backoff_test.go`, `rotatelog_test.go`, `runner_test.go` —
  backoff growth/cap/jitter, log rotation/retention, script extraction,
  fatal-config classification, and retry-until-cancelled network resilience.

Not covered by automated tests: the Windows-only SCM code itself (needs Windows),
and there is no CI workflow yet.

---

## 7. Running it locally

**Server:**

```bash
cd server
python -m venv .venv && .venv\Scripts\activate    # Windows; use source .venv/bin/activate on Unix
pip install -r requirements.txt
python scripts/gen_command_keys.py                 # writes the Ed25519 keypair
copy .env.example .env                             # set DATABASE_URL, SECRET_KEY
python scripts/create_admin.py admin@example.com --role admin   # bootstrap first operator
uvicorn app.main:app --reload                      # docs at /docs, health at /healthz
```

Use `DATABASE_URL=sqlite+aiosqlite:///./rmm.db` and `DEBUG=true` for local dev
(tables auto-create on startup). Tests:
`pip install pytest pytest-asyncio httpx aiosqlite && pytest -q`.

**Agent:**

```bash
cd agent
go build -o rmm-agent.exe ./cmd/agent          # or ./build.sh 0.1.0 for all targets
copy config.example.json config.json           # set server_url + enrollment_token
./rmm-agent -config config.json                # first run enrolls, writes identity.json
```

**Windows service** (elevated prompt, binary in its final location):

```
rmm-agent.exe install -config config.json
rmm-agent.exe start
rmm-agent.exe stop
rmm-agent.exe uninstall
```

---

## 8. Roadmap — three readiness gates (done strictly in order)

**Gate 1 — Works.** Enroll → heartbeat → signed dispatch → verified execution →
result reporting, proven on a dev machine. **Status: DONE and verified.**

**Gate 2 — Runs unattended.** Windows service install, auto-start, crash
recovery, rotating logs, backoff on network failure, graceful shutdown.
**Status: CODE COMPLETE; needs the real manual acceptance test** — install on
Windows, reboot and confirm the agent comes back online with nobody logged in;
kill the process and confirm SCM restarts it; stop the server and confirm the
agent retries quietly then reconnects. (The SCM code has no automated test by
nature.)

**Gate 3 — Safe to deploy off the dev box.** HTTPS enforced end-to-end;
**agent-side command TTL + replay/nonce protection** (the one genuinely open
security item — see below); least-privilege service account; repeatable
install/uninstall; code-signed binary; multi-day soak test. Above all of this
sits a **HIPAA compliance bar** for medical endpoints (documented change control,
rollback plan, security review of the command-execution surface). **Regulated
endpoints come last.**

Deployment progression: your own dev box → a spare machine/VM you own → a
friendly non-critical client who knows it's early → regulated endpoints.

### Open security gaps (see `docs/threat-model.md` for the live list)

- **Agent-side command TTL / replay protection.** Server-side TTL works
  (`expires_at`, and the heartbeat expires stale commands before delivery), but
  the agent never checks `expires_at` and there is no nonce. This is the most
  important open item. Note cross-*agent* replay is already prevented (agent_id
  is signed).
- **TLS.** Not implemented; the scaffold serves plain uvicorn. Terminate TLS
  (reverse proxy or the server) and switch agent configs to `https://` before any
  off-box use; consider cert pinning for high-assurance clients.
- **Token revocation + login rate-limiting.** JWTs are stateless, so a leaked
  token is valid until expiry. Consider short lifetimes + refresh tokens or a
  denylist, plus throttling on `/auth/login`.
- **External anchoring of the audit chain.** The local chain proves internal
  consistency; anchoring the periodic `event_hash` (e.g. a Merkle root) to an
  external append-only medium would make history un-rewritable even by a server
  operator.

---

## 9. Known drift (code vs. older docs)

These are places where existing docs or dependencies describe things that aren't
in the code. Fix opportunistically; listed here so nobody is misled.

- **`server/README.md` is dangerously stale on auth.** It says operator
  endpoints are "unauthenticated in Phase 1." They are **not** — full operator
  auth is implemented. Trust the code and `docs/threat-model.md`, not that note.
  The README's endpoint table also omits the three `/auth/*` routes.
- **Root README shows a `dashboard/` (Next.js) and "WebSocket".** Neither exists.
  The `websockets` dependency is unused; the transport is HTTP polling.
- **`alembic` is in `requirements.txt` but there is no `alembic/` scaffold**
  (a `main.py` comment references one). `python-multipart` also appears unused.
- **Inventory is half-wired.** The server accepts and stores `inventory`, and a
  `collect_inventory` command kind exists, but the agent always sends `nil`
  inventory and `collect_inventory` just runs a script like any other kind.
  Nothing populates `Agent.inventory` yet.
- **`CommandStatus.running`** is defined but never assigned.
- **"Remote PowerShell with streamed output"** (root README, Phase 1) is actually
  buffered stdout/stderr reported after completion — no streaming.
- **Naming:** the repo/module is `rmm-agent` / `github.com/lcolon231/rmm/agent`,
  while some doc layouts call the root `rmm/`.
- **Audit ordering** uses `ts` (timestamp), not a monotonic sequence number —
  two events in the same tick could in principle interleave ambiguously. Fine as
  built; worth knowing before documenting hard guarantees.

---

*Keep this document current. When you change the architecture, the API surface,
the security model, or a gate's status, update this file in the same commit.*
