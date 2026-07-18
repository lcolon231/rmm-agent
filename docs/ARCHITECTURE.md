# NodeLink architecture

This document is the source of truth for NodeLink's implemented architecture,
security boundaries, and planned evolution. Update it in the same pull request
as any change to protocols, data models, authorization, deployment topology, or
audit behavior. The [threat model](threat-model.md) remains the detailed security
analysis.

## 1. Product and support boundary

NodeLink is an early-stage, self-hosted endpoint-management platform designed
for regulated small businesses and MSPs. The primary support target is Windows.
Linux and macOS binaries can be built, but cross-platform product support is a
Milestone 4 goal.

The current repository is an API and agent scaffold, not a complete RMM. There
is no dashboard, patch engine, live remote shell, remote desktop, compliance
exporter, or tenant-scoped authorization. Production and regulated endpoint use
remain outside the supported boundary until the deployment-safety gates in
[DEPLOYMENT-READINESS.md](DEPLOYMENT-READINESS.md) are satisfied.

## 2. Current topology and transport

```text
Operator/API client                  Endpoint
        | JWT                           | enrollment token, then agent token
        v                               v
 +------------------------- FastAPI server --------------------------+
 | auth | management API | agent API | offline sweeper | audit APIs |
 +-------------------------------------------------------------------+
                              |
                              v
                  PostgreSQL (SQLite in tests/dev)
```

The endpoint initiates every connection. The current transport is HTTP request
and response polling:

1. An unenrolled agent calls `POST /api/v1/enroll`.
2. The enrolled agent calls `POST /api/v1/heartbeat` on its configured cadence.
3. The heartbeat response carries queued commands.
4. The agent executes accepted commands sequentially and posts the buffered
   result to `POST /api/v1/commands/{id}/result`.

There is no WebSocket, server-initiated endpoint connection, interactive
session, or streamed result channel. A future interactive transport may add
lower-latency delivery and streaming, but polling must remain a resilient
fallback and the signed command contract must be transport-independent.

The FastAPI application does not terminate or require TLS. The documented
off-box topology is:

```text
Agent/API client -- HTTPS --> Caddy :443 -- HTTP loopback --> uvicorn :8000
```

This topology is documented in [DEPLOYMENT-TLS.md](DEPLOYMENT-TLS.md) and
`deploy/Caddyfile`; production-policy enforcement is still planned.

## 3. Architectural planes

### 3.1 Trust plane

The trust plane decides who or what may act and whether an endpoint should
accept an action. It currently contains:

- Operator email/password authentication with bcrypt password hashes.
- HS256 JWTs with a per-operator generation counter for logout-everywhere.
- Global `readonly`, `operator`, and `admin` roles.
- Enrollment-token and agent-token issuance; only token hashes are stored on
  the server.
- A single deployment-wide Ed25519 command-signing keypair.
- Agent-side signature, delivered-expiry, and replay-ID checks.

Known gaps include agent revocation/quarantine, Windows DPAPI protection for
credentials, signing-key identifiers and rotation, a versioned command
envelope, MFA/federation, tenant-scoped authorization, and certificate pinning.

### 3.2 Operations plane

The operations plane delivers endpoint state and actions. It currently contains
enrollment, heartbeat telemetry, polling command pickup, three command kinds,
buffered result submission, command history, and offline status transitions.

The current command kinds are `powershell`, `shell`, and `collect_inventory`.
`collect_inventory` is only another script execution path; no built-in complete
inventory collector exists. Prefer typed endpoint operations as new behavior is
added. Arbitrary scripts remain powerful escape hatches and should receive
stronger policy and approval controls.

### 3.3 Product plane

The product plane will provide the technician and customer experience. It does
not exist in this repository today. Milestone 1 introduces the authenticated
Next.js dashboard, endpoint and audit views, inventory, monitoring, alerts,
notifications, script library, and recurring tasks. Later phases add patching,
remediation, evidence workflows, and ecosystem integrations.

## 4. Server

The server uses FastAPI, Pydantic 2, and async SQLAlchemy. PostgreSQL is the
intended deployment database; tests use SQLite. With `DEBUG=true`, startup calls
`Base.metadata.create_all`. Alembic is declared as a dependency but no migration
environment or revisions currently exist, so production schema evolution is
not supported.

### 4.1 Current data model

```text
Client --< Site --< EnrollmentToken
                 \--< Agent --< Heartbeat
                          \--< Command
Operator
AuditEvent
AuditAnchor
```

`Client` and `Site` are organizational records, not security tenants. An
authenticated operator can currently access records across every client and
site. Tenant identifiers are not carried through every row or authorization
decision.

`Agent.inventory` stores only a latest optional JSON value received in a
heartbeat. The agent always sends `nil`, and there are no normalized inventory
tables, history, provenance, or diffs.

### 4.2 API surface

All application routes except `/healthz` are under `/api/v1`.

| Method | Path | Current purpose | Authorization |
|---|---|---|---|
| POST | `/auth/login` | Exchange credentials for JWT | Public, throttled in-process |
| POST | `/auth/operators` | Create operator | Admin |
| GET | `/auth/me` | Current operator | Readonly+ |
| POST | `/auth/revoke-tokens` | Revoke caller sessions | Readonly+ |
| POST | `/auth/operators/{id}/revoke-tokens` | Revoke operator sessions | Admin |
| POST | `/enroll` | Enroll with site token | Enrollment token |
| POST | `/heartbeat` | Store telemetry and poll commands | Agent token |
| POST | `/commands/{id}/result` | Submit buffered result | Agent token |
| POST/GET | `/clients` | Create/list clients | Operator / Readonly |
| POST | `/sites` | Create site | Operator |
| POST | `/enrollment-tokens` | Create token | Operator |
| GET | `/agents`, `/agents/{id}` | List/get endpoint | Readonly |
| POST/GET | `/agents/{id}/commands` | Dispatch/list commands | Operator / Readonly |
| GET | `/audit/verify` | Verify hash chain | Readonly |
| POST/GET | `/audit/anchors` | Create/list local anchors | Operator / Readonly |
| GET | `/audit/anchors/{id}/verify` | Verify local anchor | Readonly |

There are no APIs yet for listing/revoking enrollment tokens, agent quarantine,
telemetry history, operator listing/editing, audit-event listing, monitoring,
alerts, scheduling, patching, or evidence export.

## 5. Agent

The Go agent shares one runtime between foreground mode and the Windows service.
Windows service support includes automatic start, SCM recovery actions, rotating
logs, network retry with jitter, and graceful cancellation of a running child
process. Windows-specific behavior has been manually exercised but is not
covered by Windows CI.

The current Windows telemetry collector shells out to PowerShell/CIM once per
heartbeat for CPU, memory, system drive, uptime, user, and OS version. It does
not collect complete hardware, installed software, Defender, BitLocker, Secure
Boot, TPM, or local administrator state.

After enrollment, `identity.json` contains the plaintext agent token, server URL,
and command public key. File mode `0600` is requested, but Windows credential
protection and explicit ACL validation are absent. `seen_commands.json` stores
executed IDs and expiry values for replay prevention.

The agent processes commands from a single heartbeat sequentially. This happens
to limit concurrency to one per runtime, but there is no explicit policy,
server-side admission control, queue limit, or testable per-agent concurrency
contract. Stdout and stderr are held in memory without size limits.

## 6. Signed command envelope

### 6.1 Implemented format

The server currently signs canonical JSON containing exactly:

```json
{
  "agent_id": "...",
  "command_id": "...",
  "kind": "powershell",
  "payload": {"script": "..."}
}
```

Canonicalization sorts object keys and removes insignificant whitespace. Go
disables HTML escaping to match Python. Both languages have tests for a small
set of canonical examples.

`expires_at` is delivered beside the signature and enforced by the agent, but
is not signed. There is no schema/envelope version, nonce field, issued-at time,
signing-key ID, rotation state, or repository-level shared test-vector artifact.
The persisted command ID acts as replay state but is not a distinct signed
nonce.

### 6.2 Planned versioned format

Milestone 0 will define a versioned contract under a future `contracts/`
directory. A command envelope is expected to bind at least `schema_version`,
`command_id`, `agent_id`, `kind`, typed payload, `issued_at`, `expires_at`,
`nonce`, and `signing_key_id` into the signature. Canonical test vectors must be
consumed by both server and agent tests. Compatibility and rejection behavior
must be explicit before a version is activated.

## 7. Audit architecture

`AuditEvent` rows contain canonical event content, the previous event hash, and
their own SHA-256 hash. `/audit/verify` detects changes or deletion relative to
the stored chain.

Current ordering is by timestamp (and, for Merkle coverage, timestamp plus UUID).
There is no monotonic sequence number, transactional serialization strategy, or
database constraint that prevents concurrent writers from selecting the same
previous hash. These limits prevent a strong total-order guarantee.

`AuditAnchor` stores a Merkle root over a prefix of event hashes. Local anchor
verification is implemented and tested, including detection of a consistent
chain rebuild. The root is not automatically sent to an external immutable
destination, so an attacker controlling the database can rewrite events and
anchors together. External publication, receipts, retry behavior, monitoring,
and independent verification are Milestone 0 requirements.

The audit system is tamper-evident by design; it is not yet immutable evidence
storage and does not currently provide a signed evidence bundle.

## 8. Tenant isolation roadmap

Today, `Client` and `Site` provide navigation scope only. Milestone 1 may use
them to organize the dashboard, but must not describe them as security tenants.
Milestone 3 introduces an explicit tenant boundary: tenant IDs on relevant
records, tenant-scoped queries, tenant-aware roles, isolation tests, per-tenant
retention, and administrative break-glass rules. Any schema transition needs a
migration and a documented strategy for existing rows.

## 9. Remote desktop boundary

NodeLink will not invent a proprietary remote desktop protocol. Milestone 2
plans a narrowly scoped MeshCentral integration. MeshCentral remains a separate
security and operational boundary with its own agent, sessions, permissions,
updates, logs, and failure modes. NodeLink must authorize and audit session
launches without treating MeshCentral's activity as automatically covered by
NodeLink's command signature or audit guarantees.

## 10. Repository evolution

The current top-level structure is `agent/`, `server/`, `installer/`, `deploy/`,
`docs/`, and `.github/`. Planned additions are:

```text
dashboard/   technician web application
contracts/   versioned schemas and canonical signature vectors
tools/       audit verification and operational utilities
```

Reorganization must be incremental. Repository moves are separate issues with
import/build/release compatibility criteria; working code must not be deleted or
moved merely to match an aspirational tree.

## 11. Known limitations and documentation corrections

- Polling is the only command transport; output is buffered, not streamed.
- Dashboard, complete inventory, monitoring alerts, scheduling, patching,
  remediation, remote shell, and remote desktop are not implemented.
- Production TLS is an operator-run topology, not enforced by application
  configuration.
- Command expiry is not cryptographically bound to the current signature.
- One deployment-wide signing key has no identifier or rotation mechanism.
- Agent credentials are plaintext in endpoint JSON files and cannot be revoked.
- Output and queues have no explicit resource limits.
- Database migrations and automated backup/restore are absent.
- Audit anchors remain inside the same trust boundary as the audit database.
- Roles are global; clients/sites are not authorization tenants.
- The login limiter is process-local and weakens with multiple workers.
- `CommandStatus.running` exists but is never assigned.
- `websockets`, `python-multipart`, and Alembic are declared dependencies without
  corresponding implemented product behavior or migration scaffolding.
- Release binaries are checksummed but unsigned and have no SBOM or provenance
  attestation.

## 12. Change discipline

Security-sensitive behavior requires unit and integration tests across every
affected boundary. Windows service, installer, signing, and credential changes
also require Windows tests. Keep this document, the threat model, deployment
readiness, and relevant runbooks synchronized with code in the same pull
request.
