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
- A negotiated `command-v3` envelope with shared Python/Go canonical vectors,
  version downgrade rejection, and agent-side signature, signed time-window,
  command-ID, and nonce replay checks.

Agent trust state is explicit and separate from online status: `active`,
`quarantined` (authenticates, but receives no commands, may not submit
results, and has no telemetry/inventory recorded), and `revoked` (credentials
fail authentication with the same response as an unknown token; terminal —
the endpoint must re-enroll as a new identity). Quarantine/restore require the
operator role; revocation requires admin. Every transition demands a reason
and is audited, and revocation expires the agent's outstanding queued and
dispatched commands.

Signing-key rotation is an operator-run workflow (`scripts/rotate_command_key.py`
with the `docs/KEY-ROTATION.md` runbook): staged active/overlap/retired
transitions, a compromise fast path, and rollback, each written atomically to
the registry and appended to a rotation journal. Known gaps include
MFA/federation, tenant-scoped authorization, and certificate pinning.

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

The server uses FastAPI, Pydantic 2, async SQLAlchemy, and Alembic. PostgreSQL is
the intended deployment database; most tests use SQLite and CI also migrates a
fresh PostgreSQL 16 database. With `DEBUG=true`, startup calls
`Base.metadata.create_all` for developer convenience. With `DEBUG=false`, the
server compares the database's Alembic revision with its expected head and
fails before serving traffic on an unversioned, older, or newer schema.

Revision `0001` captures the pre-versioning schema. Revision `0002` adds agent
envelope capabilities and persisted command envelope versions. Revision `0003`
adds signed-command schema/timestamp/nonce columns and a per-agent nonce
uniqueness index. Existing queued legacy commands are marked expired because
their signatures do not cover the v2 contract. Migrations are forward-only; an
existing debug-created database may be stamped `0001` only after backup and
manual schema verification.

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
| POST | `/agents/{id}/quarantine` | Suspend agent trust (reversible) | Operator |
| POST | `/agents/{id}/restore` | Return quarantined agent to active | Operator |
| POST | `/agents/{id}/revoke` | Permanently revoke agent credentials | Admin |
| GET | `/signing-keys` | View redacted active/overlap/retired key state | Readonly |
| POST/GET | `/agents/{id}/commands` | Dispatch/list commands | Operator / Readonly |
| GET | `/audit/verify` | Verify hash chain | Readonly |
| POST/GET | `/audit/anchors` | Create/list local anchors | Operator / Readonly |
| GET | `/audit/anchors/{id}/verify` | Verify local anchor | Readonly |
| GET | `/audit/anchors/{id}/receipt` | External publication receipt + tamper check | Readonly |
| GET | `/audit/publication-status` | External anchor publication lag/health | Readonly |

There are no APIs yet for listing/revoking enrollment tokens,
telemetry history, operator listing/editing, audit-event listing, monitoring,
alerts, scheduling, patching, or evidence export.

## 5. Agent

The Go agent shares one runtime between foreground mode and the Windows service.
Windows service support includes automatic start, SCM recovery actions, rotating
logs, network retry with jitter, and graceful cancellation of a running child
process. Go build and unit tests run on Windows CI, but Windows service and
installer lifecycle behavior is exercised in Windows CI: a lifecycle script drives install/start/stop/restart/refuse-double-install/uninstall against the SCM, and a silent installer install+uninstall smoke test builds and runs the Inno Setup package.

The current Windows telemetry collector shells out to PowerShell/CIM once per
heartbeat for CPU, memory, system drive, uptime, user, and OS version. It does
not collect complete hardware, installed software, Defender, BitLocker, Secure
Boot, TPM, or local administrator state.

After enrollment, `identity.json` holds the agent token, server URL, and command
public keys inside a versioned envelope that declares its protection scheme. On
Windows the payload is DPAPI-encrypted in user scope under the account that
enrolled (LocalSystem for the installed service) and the file's DACL is replaced
with a protected SYSTEM+Administrators-only ACL; on other platforms the payload
is stored with protection `none` and mode `0600`. A legacy plaintext
`identity.json` is migrated to the envelope form on first load via an atomic
replace; if protection or migration fails, the agent refuses to run rather than
falling back to plaintext, and a scheme mismatch (e.g. a blob enrolled under a
different account) fails closed with a delete-and-re-enroll instruction.
`seen_commands.json` stores
executed command IDs and accepted signed nonces with expiry values for replay
prevention; both entries are reserved atomically before execution.

Command concurrency and admission are explicit and configurable. The agent's
contract is one command at a time per runtime: a heartbeat's batch is executed
strictly in delivery order and the next beat is not issued until the batch
drains. The server enforces two bounds: admission control refuses dispatch
(HTTP 429, `agent_command_queue_full`) once an agent has
`max_outstanding_commands_per_agent` non-terminal commands, and each heartbeat
hands out at most `max_commands_per_heartbeat` queued commands oldest-first, so
a backlog drains over several beats instead of flooding one. Terminal commands
(succeeded/failed/expired) free admission slots.

Command output capture is bounded: stdout and stderr are each captured up to
256 KiB, with a 384 KiB combined cap. Bytes beyond a cap are counted but never
buffered, so a runaway command cannot exhaust agent memory. When the combined
cap binds, stderr is preserved and stdout trimmed to the remaining budget — a
deterministic rule chosen because diagnostics matter most. Truncation is
UTF-8-safe (no split runes) and reported as structured metadata
(`stdout_truncated`, `stderr_truncated`, and the original byte totals) that
the server persists, exposes on command records, and writes into the
`command.completed` audit detail. NULL metadata means a pre-limits result:
unknown, not complete. The server refuses results beyond the caps (they cannot
have come from a compliant agent) and refuses dispatch payloads over 64 KiB.

## 6. Signed command envelope

### 6.1 Implemented `command-v3` format

The server currently signs canonical JSON containing exactly:

```json
{
  "agent_id": "...",
  "command_id": "...",
  "envelope_version": "command-v3",
  "schema_version": 1,
  "issued_at": "2026-07-18T12:00:00Z",
  "expires_at": "2026-07-18T12:05:00Z",
  "nonce": "...",
  "signing_key_id": "key-2026-a",
  "kind": "powershell",
  "payload": {"script": "..."}
}
```

Canonicalization emits UTF-8 JSON, recursively sorts object keys, removes
insignificant whitespace, and does not HTML-escape. Payload values are limited
to objects, arrays, strings, booleans, null, and signed 64-bit integers; floats
are rejected to avoid cross-runtime formatting ambiguity. Payload nesting is
limited to 16 levels, the API payload to 60 KiB, and the full canonical envelope
to 64 KiB. Both runtimes consume the positive and negative vectors in
`contracts/command-v3.schema.json`. The signed time window is canonical UTC,
expires within 24 hours, and rejects timestamps more than two minutes in the
future.

Agents advertise supported versions during enrollment and every heartbeat.
Enrollment returns the selected version and fails with `409` when there is no
overlap. Command dispatch also returns `409` until the target has advertised
`command-v3`. Missing, unknown, and `legacy-unversioned` commands fail closed in
the agent before signature verification. Capability changes are audited without
secrets. Successful dispatch audit rows record the envelope version, payload
key names, and a SHA-256 envelope digest, not potentially sensitive payload
values. This deliberately prevents an implicit legacy fallback.

The signature binds the schema version, issued-at, expiry, nonce, and
`signing_key_id`. The agent persists both command IDs and nonces, replaces its
trusted public-key bundle on heartbeat, and refuses execution if replay state
cannot be durably written or the key is unknown/retired. The external registry
supports one active key, any number of overlap keys, and retired keys that are
never sent to agents.

### 6.2 Signing-key lifecycle and rollback

The JSON registry named by `COMMAND_SIGNING_KEYRING_PATH` records the active key
ID and each key's `active`, `overlap`, or `retired` state. Private material stays
outside the database; overlap entries may provide public material only. Changing
the registry is an operator action that must be reviewed, backed up, and paired
with an audit record. On compromise, activate a new key, retain the old key only
for the documented overlap window, then mark it retired. Rollback restores the
previous registry atomically and never reactivates an unknown key.

## 7. Audit architecture

`AuditEvent` rows contain canonical event content, the previous event hash, and
their own SHA-256 hash. `/audit/verify` detects changes or deletion relative to
the stored chain.

Ordering is explicit: every event carries a strictly monotonic `seq`
(1, 2, 3, … with no gaps) assigned inside a serialized append — a
transaction-scoped PostgreSQL advisory lock serializes concurrent writers, and
a unique constraint on `seq` turns any lost race into a failed transaction
rather than a silently forked chain. For events appended after migration 0007,
`seq` is bound into `event_hash` (`hash_schema=2`), so renumbering an event
breaks its own hash. Pre-existing events were backfilled 1..N in their
historical `(ts, id)` order and marked `hash_schema=1` — their hashes honestly
do not cover a sequence that did not exist when they were written, and a
schema-1 event appearing after the cutover fails verification. `/audit/verify`
walks `seq` order and detects gaps, duplicates, reordering, and edits.

`AuditAnchor` stores a Merkle root over a prefix of event hashes. Local anchor
verification is implemented and tested, including detection of a consistent
chain rebuild. A scheduled publisher (`app/core/anchor_publish.py`) carries
each anchor's root to an external immutable destination — an S3-compatible
bucket with Object Lock, or an append-only WORM filesystem — recording an
`AnchorPublication` row with the destination URI, the backend's receipt, and a
`receipt_sha256` tamper check. Publication is idempotent (content-addressed
keys), retried on outage, and lag past a threshold alerts through
`GET /audit/publication-status`. `scripts/verify_anchor_receipt.py` recomputes
the root from read-only event hashes and the downloaded artifact, so a verifier
needs no write access to (or trust in) the database. Publication is opt-in and
logs a loud warning in production when unconfigured. Anchor-publication events
are deliberately kept out of the hash chain so publishing does not itself force
perpetual re-anchoring. See `docs/AUDIT-ANCHORING.md`.

The audit system is tamper-evident and, once an external anchor destination is
configured, externally verifiable against immutable storage. It does not yet
provide a signed, exportable evidence bundle (a Milestone 3 compliance
deliverable).

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
dashboard/   technician web application (planned)
contracts/   versioned schemas and canonical signature vectors (implemented)
tools/       audit verification and operational utilities (planned)
```

Reorganization must be incremental. Repository moves are separate issues with
import/build/release compatibility criteria; working code must not be deleted or
moved merely to match an aspirational tree.

## 11. Known limitations and documentation corrections

- Polling is the only command transport; output is buffered, not streamed.
- Dashboard, complete inventory, monitoring alerts, scheduling, patching,
  remediation, remote shell, and remote desktop are not implemented.
- TLS termination itself remains an operator-run topology, but production
  mode (ENVIRONMENT=production) now fails startup on debug mode, placeholder
  or short secrets, missing signing keys, and a missing/non-HTTPS/loopback
  PUBLIC_BASE_URL. X-Forwarded-For is ignored unless TRUST_PROXY_HEADERS is
  explicitly enabled for a proxy-only topology.
- Command expiry is not cryptographically bound to the current signature.
- One deployment-wide signing key has no identifier or rotation mechanism.
- Agent credentials are DPAPI-protected only on Windows; other platforms rely
  on file permissions. Revocation is server-side only — a revoked agent keeps
  its local identity file until uninstalled or re-enrolled.
- Stdout/stderr and dispatch payloads are bounded; per-agent outstanding-command
  admission and per-heartbeat FIFO batch limits are configurable and enforced.
- Backup/restore automation ships in `deploy/backup/` (encrypted streaming
  pg_dump with manifests, isolated restore, application-level validation via
  `scripts/verify_restore.py`) and is rehearsed in CI; production scheduling,
  retention monitoring, and the release rollback drill remain operator
  evidence. Schema
  migrations and exact startup revision checks are implemented.
- Audit anchors remain inside the same trust boundary as the audit database.
- Roles are global; clients/sites are not authorization tenants.
- The login limiter is process-local and weakens with multiple workers.
- `CommandStatus.running` exists but is never assigned.
- `websockets` and `python-multipart` are declared dependencies without
  corresponding implemented product behavior.
- Release binaries are checksummed but unsigned and have no SBOM or provenance
  attestation.

## 12. Change discipline

Security-sensitive behavior requires unit and integration tests across every
affected boundary. Windows service, installer, signing, and credential changes
also require Windows tests. Keep this document, the threat model, deployment
readiness, and relevant runbooks synchronized with code in the same pull
request.
