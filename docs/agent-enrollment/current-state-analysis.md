# Agent enrollment current-state analysis

Last reviewed: 2026-07-27

## Scope and assumptions

This analysis describes the repository state before the enrollment-management
work in this change. `docs/ARCHITECTURE.md` remains the source of truth for the
whole product.

Terminology is adapted to NodeLink's existing model:

- `Client` is the closest existing equivalent to an organization.
- `Site` is a location under a client and is the current enrollment boundary.
- `Operator` is a human management user.
- `Agent` is an enrolled endpoint.
- Existing roles are retained: `admin` maps to Super Administrator,
  `operator` maps to the provisioning/Organization Administrator capability,
  and `readonly` maps to Viewer. These roles are currently global.

The repository contains no separate tenant identity or tenant membership
model. Clients and sites must not be described as security tenants until
tenant-scoped operator assignments and query enforcement exist.

## Existing architecture

```text
Browser -- same-origin HTTP-only session --> Next.js dashboard
                                             |
                                             | operator JWT (server-side only)
                                             v
Installer/agent -- outbound HTTPS --> FastAPI /api/v1 --> PostgreSQL
                        |                    |
                        |                    +-- SQLAlchemy / Alembic
                        |                    +-- hash-chained audit events
                        |                    +-- in-process background tasks
                        |
                        +-- Go agent / Windows service
```

### Frontend

`dashboard/` is a Next.js 16 App Router application using React 19 and
TypeScript. It has:

- a server-mediated login flow;
- an HTTP-only, `SameSite=Lax` operator-session cookie;
- server-only forwarding of the operator JWT to FastAPI;
- live client/site navigation, endpoint inventory, endpoint detail, and
  command pages;
- a responsive custom NodeLink visual system in `src/app/globals.css`;
- fixture-backed aggregate dashboard and audit panels.

There is no client-side bearer-token storage. Browser mutations use
same-origin route handlers, which is the correct integration point for
enrollment-token administration.

### Backend and API

`server/` is FastAPI with Pydantic v2 schemas, SQLAlchemy 2 async sessions, and
Alembic forward-only migrations. Public application APIs use the existing
`/api/v1` prefix.

The request-scoped database dependency commits after a successful handler and
rolls back on exceptions. Audit writes occur inside the same transaction as
the action they describe.

### Database

The intended production database is PostgreSQL 14 or newer. SQLite is used for
development and automated tests. The relevant existing entity chain is:

```text
Client -> Site -> EnrollmentToken
               -> Agent -> Heartbeat
                        -> Command
AuditEvent (agent ID and JSON detail, no relational tenant columns)
Operator (global role)
```

Alembic revision `0008` was the head when this work began. While the enrollment
implementation was in progress, `origin/main` advanced through revisions
`0009` (durable command-result delivery) and `0010` (scoped script-execution
permission). The enrollment change therefore integrates after `0010` as
revisions `0011` and `0012`. Production startup verifies the exact revision and
fails closed when the schema is behind or ahead.

### Authentication and authorization

Human operators authenticate with email/password. Passwords are bcrypt hashed.
Successful login returns a signed, expiring JWT containing the operator ID and
a token-generation claim. Incrementing the generation revokes all existing
sessions for that operator.

Management routes require a valid operator JWT at router level. Route-specific
dependencies enforce the ordered global roles:

1. `readonly`
2. `operator`
3. `admin`

The dashboard stores the JWT only in an HTTP-only cookie and revalidates the
operator with `/api/v1/auth/me`. The frontend does not act as the authorization
boundary.

Agents authenticate after enrollment with a high-entropy bearer credential.
Only its SHA-256 hash is stored. Revoked agent credentials return the same
unauthorized response as unknown credentials.

### Deployment

The application does not terminate TLS. The documented production topology
places Caddy in front of uvicorn, binds uvicorn to loopback, and uses PostgreSQL.
Production configuration validation rejects debug mode, weak/default secrets,
missing command-signing keys, and non-HTTPS public URLs. The dashboard and API
are deployed separately and communicate through a server-only API origin.

### Agent

`agent/` is a Go binary that supports foreground execution and Windows service
control. On first run it reads `server_url` and `enrollment_token` from a JSON
configuration file, enrolls, then persists a per-agent bearer credential and
command-verification keys.

On Windows the identity envelope is protected by user-scope DPAPI and a
SYSTEM/Administrators-only DACL. Other platforms use a mode `0600` file without
an OS key store. The runtime retries network failures with capped exponential
backoff and heartbeats after enrollment.

## Relevant files and services

| Area | Relevant files | Notes |
|---|---|---|
| ORM | `server/app/models/models.py` | Existing Client, Site, Operator, EnrollmentToken, Agent, AuditEvent |
| Validation | `server/app/schemas/schemas.py` | Pydantic request/response contracts |
| Enrollment API | `server/app/api/agents.py` | Existing `POST /api/v1/enroll` |
| Management API | `server/app/api/management.py` | Existing token creation and agent inventory/revocation |
| Auth/RBAC | `server/app/api/auth.py`, `server/app/api/deps.py` | JWT authentication and global role ordering |
| Secrets | `server/app/core/security.py` | `secrets.token_urlsafe(32)`, SHA-256 token hashing |
| Rate limiting | `server/app/core/ratelimit.py` | Login-only, process-local sliding window |
| Audit | `server/app/core/audit.py` | Transactional hash-chained events |
| Migrations | `server/alembic/versions/` | Forward-only revisions |
| Configuration | `server/app/core/config.py`, `server/.env.example` | Environment-backed settings |
| Application | `server/app/main.py` | Routers, lifespan, `/healthz` |
| Dashboard auth | `dashboard/src/lib/dashboard-session.ts` | Server-side session validation |
| Dashboard API | `dashboard/src/lib/nodelink-api.ts` | Server-only FastAPI client |
| Dashboard shell | `dashboard/src/components/dashboard-shell.tsx` | Existing visual/navigation conventions |
| Agent CLI | `agent/cmd/agent/main.go` | Run and Windows service commands |
| Agent HTTP | `agent/internal/client/client.go` | Existing enroll and heartbeat requests |
| Agent identity | `agent/internal/config/` | Protected identity envelope |
| Agent runtime | `agent/internal/service/runner.go` | Enroll, retry, heartbeat, revocation response |
| TLS | `deploy/Caddyfile`, `docs/DEPLOYMENT-TLS.md` | Reverse-proxy deployment |
| Installer | `installer/NodeLinkAgent.iss` | Windows GUI enrollment input |

## Existing agent registration flow

1. An operator creates a client and site.
2. An `operator` or `admin` calls `POST /api/v1/enrollment-tokens`.
3. The server generates 32 random bytes with `secrets.token_urlsafe`, stores
   the SHA-256 digest, and returns the plaintext once.
4. The token is currently copied into `config.json`.
5. The agent posts it to `POST /api/v1/enroll` with host metadata and supported
   command-envelope versions.
6. The server looks up the digest, checks a Python `is_usable` property, creates
   a new agent, increments the token use count, and records `agent.enrolled`.
7. The server returns a new per-agent bearer credential once plus the command
   verification key bundle.
8. The agent stores the identity and begins heartbeat polling.

The existing implementation already avoids permanent shared enrollment
secrets, uses at least 256 bits of entropy, stores only hashes, defaults to one
use, and returns agent-specific credentials.

## Security gaps

### Enrollment-token lifecycle

- Expiration is optional, so tokens can currently remain valid indefinitely.
- Token creation is not audited.
- There is no token list, detail, revoke, search, filter, sort, or pagination
  API.
- There is no created-by, revoked-by, last-used, description, notes,
  environment, hostname, agent-name, user, or labels metadata.
- Token status is implicit rather than a stable response field.
- Plaintext is returned once by API convention, but no dedicated UI enforces
  one-time viewing.

### Redemption atomicity and abuse resistance

- Redemption reads then increments without a row lock or conditional update.
  Concurrent requests can redeem a single-use token more than once.
- Enrollment has no dedicated rate limiter.
- Failed enrollment attempts are not audited.
- Restriction checks are not implemented.
- Error bodies from the agent client may include the server response; request
  bodies are not logged today, but there is no centralized redaction policy to
  prevent future regressions.

### Credentials

- The server issues long-lived bearer credentials with no expiry or renewal
  flow.
- Agent credentials do not have an explicit fingerprint column.
- The agent does not generate a public/private key pair for enrollment.
- Revocation is enforced server-side, but a revoked agent retains its protected
  local identity until an operator removes or replaces it.

### Authorization and tenancy

- Roles are global.
- Clients and sites are navigation categories, not authorization tenants.
- Operators have no client/organization membership.
- The existing `operator` role can provision across all clients.
- Audit events do not have first-class actor-user, client, token, or source-IP
  columns, limiting efficient scoped queries.

### Operations

- `/healthz` is a liveness response but there is no database readiness route.
- Enrollment/token/agent metrics are not exposed.
- Rate limits are process-local and multiply with worker count.
- The dashboard aggregate and audit panels are fixture-backed.
- Linux/macOS credential protection relies only on filesystem permissions.
- Windows installer artifacts are not Authenticode signed.

## Recommended integration points

1. Extend the existing `EnrollmentToken`, `Agent`, `Operator`, and `AuditEvent`
   tables with an additive Alembic migration. Do not create parallel user,
   organization, or audit systems.
2. Keep SHA-256 hashing for high-entropy tokens and add a non-secret token
   prefix for support/masking. Continue using `secrets.token_urlsafe(32)`.
3. Move enrollment validation into a focused service that performs a
   PostgreSQL row lock and all validation, use-count update, agent creation,
   and audit append in one transaction. Use a conditional atomic update on
   SQLite tests.
4. Preserve `/api/v1/enroll` for backward compatibility and add the requested
   `/api/v1/agents/enroll` alias with the expanded schema.
5. Add administrative endpoints to the existing management router and enforce
   roles in FastAPI dependencies/handlers.
6. Extend the process-local limiter for enrollment now; document a shared
   Redis-compatible limiter as required before multi-worker/high-availability
   deployment.
7. Add live dashboard routes under the existing authenticated App Router
   shell. Mutations go through same-origin route handlers and never place
   plaintext tokens in URLs, browser storage, analytics, or server logs.
8. Add a first-class Go `enroll` command that accepts an environment variable,
   restricted secret file, or no-echo prompt. Keep the existing configuration
   enrollment path for backward compatibility.
9. Keep bearer credentials for this increment because that is the implemented
   trust model; document agent-generated keys and server-signed certificates as
   the preferred follow-up design.

## Initial acceptance boundary

This implementation can safely complete token lifecycle management, atomic
redemption, restriction enforcement, audit visibility, dashboard management,
and safer agent token input within the current architecture.

Full cryptographic device identity, organization-scoped operator membership,
shared distributed rate limiting, HA enrollment, non-Windows keychain support,
and signed installers require infrastructure that the repository does not yet
contain. They are tracked explicitly in `open-issues.md` and must not be
represented as completed controls.
