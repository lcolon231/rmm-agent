# Security roadmap

This document sequences security work without overstating the current system.
The [threat model](threat-model.md) describes existing boundaries; this roadmap
defines the controls and evidence required to strengthen them.

## Current security baseline

Implemented controls include operator password authentication (with no
self-service reset: lockout recovery is an audited out-of-band script requiring
database access), global RBAC,
JWT generation revocation, in-process login throttling, hashed server-side agent
tokens, outbound-only polling, negotiated `command-v3` Ed25519 verification
with shared cross-language vectors and downgrade rejection, signed schema/time
window/nonce checks, Windows command timeouts, a hash-chained audit log, and
local Merkle anchor verification.

The system is not approved for production or regulated endpoints. Key gaps are
listed below and tracked as separate GitHub issues.

The Milestone 1 versioned script-custody control is implemented: exact source
digests, append-only versions/final reviews, role-gated terminal deprecation,
bounded inputs, audited reads and mutations, and a strict separation from
execution permission. Typed parameter definitions and encrypted expiring
per-run value preparation are also implemented with strict JSON types,
interpreter-safe variable binding, keyed fingerprints, and secret-redacted
evidence. Scheduling/run policy and immutable run evidence remain the next
automation controls. See
[`SCRIPT-LIBRARY.md`](SCRIPT-LIBRARY.md).

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
authorization now requires `operator` or higher, a same-origin dashboard
request, an expected row version, and an idempotency key. Deduplicated alert
state uses a database uniqueness boundary, row locking, result-keyed
exactly-once observations, deterministic out-of-order handling, and
server-derived maintenance suppression metadata (`docs/ALERTS.md`). Lifecycle
comments are bounded and scrubbed before append-only operational storage; the
tamper-evident audit chain retains only their digest and byte count. The new
PostgreSQL tables enable RLS and revoke direct Supabase Data API roles.

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
SHA-256 digest plus byte count. Policy administration in the dashboard remains
intentionally read-only. Agent-side evaluation, result ingestion,
maintenance-window suppression metadata, alert deduplication/state, and the
live technician alert queue and durable, redacted email transition delivery are
implemented. Generic signed webhook delivery remains later Milestone 1 work.

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
  creation/deletion are covered; alert acknowledgement, assignment, comments,
  manual resolution, failed-email manual retry, script-library, typed parameter
  preparation, and generic webhook administration are covered;
  recurring-schedule administration remains future work.
- Validate and bound inventory, telemetry, scripts, parameters, schedules, and
  webhook destinations.
- Add SSRF controls for webhooks and delivery backoff with signed webhook
  payloads.
- Require tests for alert deduplication and acknowledgement races.

## Milestone 2 — secure patching and remote operations

- [x] Model restart/shutdown maintenance window, reason, delay, user-session
  consent, and cancellation as explicit signed inputs (`POWER-OPERATIONS.md`).
  Patch approval and general exception policy remain open.
- Verify downloaded packages and providers; record source, digest, signer, and
  install result.
- [x] Implement controlled file upload/download and registry read/write/delete
  as administrator-only typed operations with fixed path/hive policy, digest
  and byte bounds, atomic file replacement, capability gating, redacted audit
  evidence, and endpoint-local rollback (`CONTROLLED-REMEDIATION.md`). This does
  not complete general software deployment or least-privilege execution.
- Implement service, process, and event-log operations as typed operations with
  narrow validation and least privilege where feasible. Restart and shutdown
  are implemented; least-privilege service execution remains open.
- [x] Apply owner-bound session authorization, idle/absolute timeouts,
  metadata-only audit, exact replay protection, and bounded backpressure to the
  interactive shell and streaming transport (`SHELL-SESSIONS.md`).
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
  access and audit NodeLink's session authorization and launch. **Integrated,
  disabled by default (issue #62).** NodeLink identity-maps an agent to a
  MeshCentral node, authorizes the launch (operator role **and** explicit
  arbitrary-script scope, admin is not a bypass), audits the decision
  (`meshcentral.launch_*`/`session_*`, metadata only), and mints a short-lived,
  single-device, desktop-scoped access URL through MeshCentral's own API without
  proxying the stream or persisting login material. Availability is fail-closed on
  provider-enabled + non-stale active mapping + authorization; the admin
  credential is environment-only. Automated tests run against a fake MeshCentral;
  a live end-to-end verification (`MESHCENTRAL-INTEGRATION.md`) gates enabling it
  in production.
- Sign self-updates, stage rollout, enforce anti-rollback policy, and retain a
  recovery path. **Implemented (issue #63).** Release metadata is Ed25519-signed
  both on the wire (the `command-v3` envelope) and at rest (a domain-separated
  manifest); the artifact is pinned by a mandatory SHA-256 and byte count with an
  optional Authenticode signer; rollout is staged by a stable per-release bucket
  with a terminal canary halt; anti-rollback is enforced independently at both
  ends; and every endpoint retains a digested previous build that it restores
  automatically when a new build fails its post-restart health check. See
  [`AGENT-SELF-UPDATE.md`](AGENT-SELF-UPDATE.md). Windows release artifacts are
  still not Authenticode-signed by this project (issue #24), so the optional
  signer pin is only as useful as the artifacts an operator publishes.

## Milestone 3 — productize regulated-environment controls

- **Implemented (issue #66).** Tenant-scoped authorization is implemented server
  side: a default-deny operator→client membership boundary with a platform-admin
  superuser, 404 anti-oracle semantics, an audited membership-administration API,
  audit anchoring via `organization_id`, and the forward-only `0037` migration.
  Isolation is verified by `server/tests/test_tenant_authorization.py`
  (cross-tenant IDOR, list exclusion, membership lifecycle with token
  revocation). See [`TENANT-AUTHORIZATION.md`](TENANT-AUTHORIZATION.md). The
  dashboard membership-management UI is a follow-up (backend already filters
  responses per tenant).
- **Delivered (issue #67):** phishing-resistant WebAuthn multi-factor
  authentication. A correct password yields only a restricted token accepted by
  the MFA completion endpoints; challenges are single-use and purpose-bound;
  sessions carry signed authentication-method and step-up claims that gate
  operator-management and factor-reconfiguration operations; recovery codes
  restore access and permit re-enrolment but never satisfy step-up; enforcement
  stages through `off`/`optional`/`required` with configuration-only rollback.
  The trust boundary this does *not* move: registration requests
  `attestation: "none"`, so authenticator make, model, and certification are not
  established and no hardware-provenance claim rests on it. See
  [`MFA.md`](MFA.md).
- **Delivered (issue #69):** administrative session management and break-glass
  access. Sessions are server-side rows bound to a signed `sid` claim, so they
  can be inventoried with device context and revoked individually; absolute and
  idle ceilings bound each one and a lapsed session is refused on read rather
  than by a sweeper. Break-glass provides pre-provisioned, offline-usable
  emergency credentials bound to dedicated identities, opening short marked
  sessions that are audited and must be reviewed, and that cannot provision
  further emergency access. The trust boundary this does *not* move: a stolen
  sealed envelope is a full compromise, bounded by time, noise, and rotation
  rather than by a second factor -- which is precisely what it exists to
  survive. See [`ADMIN-SESSIONS.md`](ADMIN-SESSIONS.md).
- Add OIDC/SAML federation.
- **Partially implemented (issue #64).** Approval and two-person authorization
  for sensitive operations. An opt-in policy at global, client, site, or
  endpoint scope names the command kinds it governs and how many distinct
  eligible identities must agree. The approval binds the SHA-256 of
  `(agent_id, kind, payload)`, so a command mutated after review cannot spend
  it; approver eligibility is re-evaluated live at dispatch, so a demotion,
  disablement, tenant removal, or revoked script grant invalidates the approval
  rather than being papered over by the snapshot on the decision row; and the
  approval is spent exactly once through a conditional status transition. The
  requester can never be an approver, and the database -- not application logic
  -- enforces one verdict per identity. Scheduled tasks and interactive shell
  sessions are refused for a governed kind rather than dispatching around the
  control. The trust boundary this does *not* move: an approval is only as
  strong as the separation between the accounts involved, and two identities
  held by one person defeat it exactly as they would in any dual-control
  system. See [`APPROVAL-WORKFLOWS.md`](APPROVAL-WORKFLOWS.md). A justified
  emergency override that keeps the policy in force while recording the
  exception remains open (issue #65).
- **Implemented (issues #79/#80).** A single-tenant, versioned,
  deterministic manifest exports safe actor/endpoint/policy/signed-action/result
  metadata, sanitized audit events, hash-only chain material, anchors/receipts,
  and public keys. Canonical JSON and normalized CSV reproduce the same bundle
  ID and a standard-library verifier checks either without database access.
  Tagged PDF summaries and fixed-path ZIPs bind the same document, receipts,
  public key, and instructions under a deterministic domain-separated Ed25519
  signature; verification requires an externally trusted key and refuses
  traversal, tamper, or over-limit archives. See
  [`EVIDENCE-BUNDLES.md`](EVIDENCE-BUNDLES.md) and
  [`EVIDENCE-PACKAGES.md`](EVIDENCE-PACKAGES.md).
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
