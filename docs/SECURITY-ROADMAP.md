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

Key IDs and active/overlap/retired registry states are implemented for v3.
Remaining work is an operator-facing rotation workflow, compromise automation,
and independent rollback rehearsal.

The implemented rollout is fail closed, not dual issue: agents report supported
versions, new servers reject incompatible enrollment/dispatch, new agents
reject old unversioned commands, and migration expires queued legacy commands.
There is no implicit legacy fallback.

### Operate signing-key lifecycle

The external key registry stores an active key ID, overlap keys, and retired
keys. Every v3 command records the key ID in its signed envelope and audit
detail; agents replace their public-key bundle on heartbeat and fail closed on
unknown/retired keys. Private keys remain outside the database. Add an
operator-facing activation/retirement workflow and rehearse rotation, rollback,
lost-key, and compromise procedures before pilot use.

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

Production configuration must refuse plain HTTP, placeholder secrets, unsafe
proxy assumptions, and untrusted certificate bypasses. Optional certificate
pinning needs a rotation-safe trust model, multiple pins, expiry handling,
recovery procedures, and tests. Pinning must not replace normal PKI validation.

### Bound execution resources

Limit stdout and stderr independently and in total, communicate truncation in a
structured result, and avoid unbounded memory growth. Define explicit per-agent
command concurrency and queue admission; default to one until a safe policy is
designed. Test timeout, cancellation, truncation, retry, and shutdown races.

### Strengthen audit ordering and external verification

Introduce a database-backed monotonic sequence with serialized append behavior
and uniqueness constraints. Include sequence data in event hashing and evidence
formats. Migrate existing events with explicit legacy semantics.

Publish audit anchors on a schedule to an external immutable destination. Store
publication receipts, retry safely, alert on lag, and provide independent
verification instructions. A local anchor is not external evidence.

### Make data and releases recoverable

Alembic now owns the baseline and command-envelope migration, and non-debug
startup requires the exact expected revision. Continue using Alembic for every
supported schema change. Automate encrypted backup and restore, document
retention and key custody, and rehearse restore and rollback.
Windows artifacts must be Authenticode-signed and timestamped. Releases must
include checksums, SBOMs, provenance attestations, and verification steps.

### Verify Windows behavior and endurance

Windows CI must cover build, install, service start/stop/restart, upgrade,
uninstall, config/identity permissions, and installer lifecycle. After pilot
controls land, run a multi-day soak test measuring memory, handles, logs,
heartbeat recovery, command execution, restarts, audit integrity, and result
delivery.

## Milestone 1 — secure the technician product

- Use server-mediated dashboard sessions with secure cookie, CSRF, expiration,
  logout, revocation, and role-change behavior. Do not persist operator bearer
  tokens in browser local storage.
- Apply authorization on the API; hiding dashboard controls is not a security
  boundary.
- Redact secrets in UI, logs, command history, webhooks, and notification
  templates.
- Audit token, operator, command, alert, script, schedule, and notification
  administration.
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
