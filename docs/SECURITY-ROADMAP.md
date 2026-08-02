# Security roadmap

This document sequences security work without overstating the current system.
The [threat model](threat-model.md) describes existing boundaries; this roadmap
defines the controls and evidence required to strengthen them.

## Current security baseline

Implemented controls include operator password authentication, global RBAC,
JWT generation revocation, in-process login throttling, hashed server-side agent
tokens, outbound-only polling, negotiated `command-v3` Ed25519 verification
with shared cross-language vectors and downgrade rejection, signed schema/time
window/nonce checks, Windows command timeouts, a hash-chained audit log, and
local Merkle anchor verification.

The system is not approved for production or regulated endpoints. Key gaps are
listed below and tracked as separate GitHub issues.

## Milestone 0 — close pilot-blocking trust gaps

### Version and bind the command envelope

`command-v3` defines and signs envelope version, schema version, agent ID,
command ID, operation, bounded payload, canonical issued-at/expiry, and nonce.
Python and Go consume the same canonical test vectors; missing, unknown,
malformed, expired, and downgraded envelopes fail closed. Both command IDs and
nonces are durably reserved before execution.

Key IDs and active/overlap/retired registry states are implemented for v3, and
staged rotation, compromise response, and rollback are operator-run via
`scripts/rotate_command_key.py` with the `docs/KEY-ROTATION.md` runbook and a
rehearsed test suite. Registry mutations are atomic and journaled.

The implemented rollout is fail closed, not dual issue: agents report supported
versions, new servers reject incompatible enrollment/dispatch, new agents
reject old unversioned commands, and migration expires queued legacy commands.
There is no implicit legacy fallback.

### Operate signing-key lifecycle

The external key registry stores an active key ID, overlap keys, and retired
keys. Every v3 command records the key ID in its signed envelope and audit
detail; agents replace their public-key bundle on heartbeat and fail closed on
unknown/retired keys. Private keys remain outside the database. Add an
operator-facing rotation workflow (`scripts/rotate_command_key.py`) with
staged activation/retirement, compromise fast path, and rollback; the runbook
is `docs/KEY-ROTATION.md` and the procedures are rehearsed in
`tests/test_key_rotation.py`.

### Revoke and quarantine agents

Implemented. Agents carry an explicit trust state (`active`, `quarantined`,
`revoked`) independent of online status. Revoked credentials fail
authentication with the same response as unknown tokens and outstanding
queued/dispatched work is expired; quarantined agents receive only a minimal
heartbeat ack (no commands, no signing keys, no recorded telemetry/inventory)
and may not submit results. Quarantine/restore require the operator role,
revocation requires admin, every transition records a mandatory reason, and
all transitions and refusals are audited and covered by integration tests.
Revocation is terminal; recovery is re-enrollment under a new identity.

### Protect endpoint credentials

Implemented on Windows. The persisted identity is wrapped in a versioned
envelope whose payload is DPAPI-encrypted in user scope under the enrolling
account (LocalSystem for the installed service), with the file's DACL replaced
by a protected SYSTEM+Administrators-only ACL. Legacy plaintext `identity.json`
files migrate to the envelope atomically on first load; protection or
migration failure refuses to run — there is no silent plaintext fallback, and
a scheme mismatch fails closed with a delete-and-re-enroll instruction. The
uninstaller removes `identity.json`. Non-Windows platforms remain
`0600`-permission plaintext by declared scheme (`none`). Remaining work:
least-privilege service account and installer lifecycle CI (issue #23).

### Enforce transport policy

Implemented for configuration validation: `ENVIRONMENT=production` fails
startup on debug mode, placeholder or short secrets, missing signing keys, and
a missing/non-HTTPS/loopback public URL, listing every violation at once.
Proxy trust is explicit opt-in (`TRUST_PROXY_HEADERS`), spoofed forwarding
headers are ignored by default, and only the rightmost proxy-appended entry is
used when trusted. Optional high-assurance pinning is implemented in the agent:
strict `sha256/<base64>` leaf-SPKI pins, current+next overlap, constant-time
matching after normal PKI validation, fail-closed configuration/mismatch tests,
and expired/stale recovery procedures (`docs/CERTIFICATE-PINNING.md`).
Certificate lifecycle monitoring remains deployment evidence; pinning does not
replace it or normal PKI validation.

### Bound execution resources

Limit stdout and stderr independently and in total, communicate truncation in a
structured result, and avoid unbounded memory growth. Define explicit per-agent
command concurrency and queue admission; default to one until a safe policy is
designed. Test timeout, cancellation, truncation, retry, and shutdown races.

Implemented for the polling executor. The agent now saves an atomically
protected command journal and bounded result outbox before upload, retries exact
results across outages/restarts/lost acknowledgements, and never re-executes an
`executing` crash state. The server exposes `result_pending`, accepts identical
delivery idempotently, rejects conflicts, and lease-redelivers work that was
dispatched but never started. Windows commands start suspended inside
kill-on-close Job Objects; native tests verify cancellation and parent exit
terminate descendants.

Storage growth is bounded and observable (issue #114): telemetry and aged
command output are pruned on a schedule while audit events, anchors, and anchor
receipts are never touched, so retention cannot break chain or external-anchor
verification. `GET /storage/status` exposes per-class counts, backlog, host disk
headroom, and unpublished-anchor lag with threshold-breach alert flags. Sizing,
retention, and full-disk behavior are documented in `docs/RETENTION.md`.

### Strengthen audit ordering and external verification

Introduce a database-backed monotonic sequence with serialized append behavior
and uniqueness constraints. Include sequence data in event hashing and evidence
formats. Migrate existing events with explicit legacy semantics.

Implemented. A scheduled publisher writes each anchor's Merkle root to an
external immutable destination — S3-compatible Object Lock or an append-only
WORM filesystem — with tamper-evident receipts, idempotent retry, and lag
alerting via `GET /audit/publication-status`. `scripts/verify_anchor_receipt.py`
independently recomputes the root from read-only event hashes and the external
artifact. Publication is opt-in and loud when unconfigured; the operator
chooses and operates the destination. See `docs/AUDIT-ANCHORING.md`.

Audit detail passes through one deterministic, fail-closed policy
(`app/core/redaction.py`) before sequence allocation or hashing. Every action
has an exact field schema; unknown actions, producer drift, malformed/nested
objects, non-canonical values, and resource-bound violations are rejected.
Credential shapes are redacted and arbitrary operator/agent prose becomes only
a digest plus byte count. Registered public evidence (Merkle roots, event
hashes, nonces, envelope digests, IDs, decisions, and counts) remains readable,
so chain and anchor verification stays reproducible. Source-discovered producer
coverage and clean-room verification are tested. See
`docs/AUDIT-EVENTS.md` and `docs/REDACTION-AUDIT.md`.

### Make data and releases recoverable

Alembic now owns the baseline and command-envelope migration, and non-debug
startup requires the exact expected revision. Continue using Alembic for every
supported schema change. Encrypted backup/isolated restore and a fail-closed
release rollback planner now ship with retention/key-custody documentation. CI
rehearses N→bad N+1→N against PostgreSQL, including rollout pause, explicit
data-loss acceptance, exact schema verification, component version selection,
and audit evidence. Scheduled production backup evidence and a timed operator
rollback drill remain deployment responsibilities (`docs/ROLLBACK.md`).
Windows artifacts must be Authenticode-signed and timestamped. Releases must
include checksums, SBOMs, provenance attestations, and verification steps.

### Verify Windows behavior and endurance

Windows CI covers build, unit tests, the DPAPI identity + ACL checks, the
service lifecycle (install/start/stop/restart/refuse-double-install/uninstall),
and a silent installer install/uninstall smoke test. The soak harness and
runbook ship (`deploy/soak/soak.py`, `docs/SOAK-TEST.md`) and are smoke-tested
in CI: it drives a sustained workload with injected outages and samples memory,
handles, heartbeat recovery, command execution, audit integrity, and anchor
publication, failing on any audit break. Remaining: Authenticode signing
(issue #24) and the actual multi-day soak run on the pilot topology (including
server restarts and a mid-run backup/restore), whose evidence goes into the
pilot record.

## Milestone 1 — secure the technician product

Initial monitoring execution now uses revision-pinned check assignments in
authenticated heartbeat responses and a bounded agent result-ingestion API.
The server derives agent identity from the credential, rejects superseded,
stale, future, non-finite, oversized, and server-owned offline results, and
deduplicates durable agent result IDs. Quarantined agents receive no checks and
cannot submit results. Cadence, hysteresis, outbox/probe limits, compatibility,
and rollback behavior are specified in `docs/MONITORING.md`; alert lifecycle
authorization and maintenance suppression remain subsequent work.

The dashboard boundary is partially implemented: server-mediated HTTP-only
sessions, API-enforced role authorization, redacted audited
client/site/endpoint reads, bounded endpoint telemetry history, and the
endpoint command console are in place. The endpoint-detail API limits history
to 168 hours and 500 samples and excludes credentials, token hashes, and raw
inventory. Command dispatch is same-origin-checked, role-gated
(`operator`/`admin`), blocked for untrusted endpoints, bounded by server-side
queue admission, and audited; command history and detail reads are paginated
and bounded, and reading captured output is audited as
`command_detail.viewed`. Arbitrary `powershell` and `shell` dispatch is also
default-deny for every role and requires an explicit admin-granted global,
site, or agent scope. Typed inventory remains role-authorized independently;
every allow/deny decision is audited without the payload before signing or
  queueing (`docs/SCRIPT-AUTHORIZATION.md`). Tenant-scoped authorization and
  mutation-specific CSRF tokens beyond the same-origin check are still required
  before this milestone closes.

Administrator-only operator management now uses same-origin dashboard handlers
for list/create, global-role change, disable/re-enable, script-permission
grant/revoke, and session revocation. Every mutation is audited; user-controlled
email and reason values are digest-only. Role and account changes revoke
existing sessions, `readonly` transitions clear script permission, and the API
prevents removal of the final active administrator. First-run client/site
creation is also same-origin, role-authorized, normalized for duplicate-name
handling, and audited with digest-only names.

Monitoring policy and maintenance-window administration is now API-enforced:
reads require `readonly`, writes require `operator`, every polymorphic scope ID
must resolve to a real client/site/agent, and policy check lists are bounded and
validated against a fail-closed per-check-type schema before storage. Policy
revisions are append-only. Every mutation is audited; operator-controlled
policy/window names and revision notes are stored in the audit chain only as a
SHA-256 digest plus byte count. The dashboard is intentionally read-only.
Agent-side evaluation, result ingestion, maintenance-window enforcement, alert
deduplication, acknowledgement, and delivery remain later Milestone 1 work.

- Use server-mediated dashboard sessions with secure cookie, CSRF, expiration,
  logout, revocation, and role-change behavior. Do not persist operator bearer
  tokens in browser local storage.
- Apply authorization on the API; hiding dashboard controls is not a security
  boundary.
- Redact secrets in UI, logs, command history, webhooks, and notification
  templates.
- Audit token, operator, command, policy, alert, script, schedule, and notification
  administration. Operator creation, role/status changes, script permission,
  session revocation, monitoring-policy revision/deletion, and maintenance-window
  creation/deletion are covered; alert, script-library, recurring-schedule, and
  notification administration remain future work.
- Validate and bound inventory, telemetry, scripts, parameters, schedules, and
  webhook destinations.
- Add SSRF controls for webhooks and delivery backoff with signed webhook
  payloads.
- Require tests for alert deduplication and acknowledgement races.

## Milestone 2 — secure patching and remote operations

- Model patch approval, maintenance window, reboot, and exception policy as
  explicit signed inputs.
- Verify downloaded packages and providers; record source, digest, signer, and
  install result.
- Implement file, registry, service, process, event-log, reboot, and shutdown as
  typed operations with narrow validation and least privilege where feasible.
- Apply stronger session authorization, idle/absolute timeouts, recording
  metadata, and rate limits to interactive shell and streaming transport.
- Constrain technician-to-end-user chat as a message-only channel: the chat
  window the agent surfaces on the endpoint must carry text between the
  machine's user and an authorized technician and nothing else — no command
  execution, file transfer, or remote control piggybacked on it. Require
  operator-role authorization to open a session, visible technician identity
  on the endpoint, endpoint-side accept/close, per-message participant
  identity, size/rate bounds on messages, audited session open/close, and
  bounded transcript retention with the same redaction discipline as command
  output (transcripts can contain sensitive endpoint-user content).
- Treat MeshCentral as a separate trust boundary; synchronize least-privilege
  access and audit NodeLink's session authorization and launch.
- Sign self-updates, stage rollout, enforce anti-rollback policy, and retain a
  recovery path.

## Milestone 3 — productize regulated-environment controls

- Introduce tenant-scoped authorization and isolation tests before describing
  client/site boundaries as tenants.
- Add MFA, WebAuthn, federation, break-glass accounts, and administrative
  session policy.
- Implement approval and two-person authorization for sensitive operations;
  emergency override must require justification and produce prominent evidence.
- Export deterministic evidence bundles in JSON, CSV, PDF, and signed ZIP forms
  with schemas, signatures, manifests, and independent verification.
- Add immutable evidence storage, tenant-specific retention, deletion controls,
  and legal hold with conflict tests.
- Ship a standalone verification CLI and a customer-facing read-only portal.

These are HIPAA-supporting controls and compliance evidence features. They do
not create or guarantee HIPAA compliance without customer-specific policies,
risk analysis, agreements, operations, and legal review.

## Milestone 4 — preserve controls at scale

Shared rate limiting, queues, workers, high availability, public APIs,
extensions, cross-platform agents, and relays must preserve tenant scope,
idempotency, signed-action checks, audit ordering, and evidence completeness.
Failure injection and region/worker partition tests are required before scale
claims are made.

## Security acceptance evidence

Every security issue should identify:

- Threat and trust boundary changed.
- Protocol/schema and migration impact.
- Negative and abuse-case tests.
- Windows test requirements when endpoint behavior changes.
- Audit events and redaction behavior.
- Deployment, recovery, and rollback documentation.
- Compatibility and staged-rollout plan.

A control is not complete if operators cannot verify it or recover safely when
it fails.
