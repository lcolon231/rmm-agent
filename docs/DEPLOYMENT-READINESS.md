# Deployment readiness

NodeLink is currently suitable only for development and controlled testing on
non-critical systems. This checklist is the release gate for a controlled
non-production pilot; it is not a compliance certification or approval for
regulated endpoints.

Statuses are:

- **Implemented:** present in code and covered by the evidence noted.
- **Partial:** useful mechanism exists, but the deployment guarantee is
  incomplete.
- **Open:** required mechanism or evidence is absent.

## Current readiness summary

| Area | Status | Current evidence or gap |
|---|---|---|
| Outbound-only polling | Implemented | Agent initiates enroll, heartbeat/poll, and result requests |
| Operator API authentication/RBAC | Implemented | Auth and authorization integration tests |
| Signed command verification | Partial | `command-v2`, negotiation, downgrade rejection, signed schema/time/nonce, and shared vectors implemented; signing-key IDs remain open |
| Agent replay/expiry checks | Implemented | Signed time-window validation plus durable command-ID and nonce replay state |
| Production TLS | Partial | Caddy topology documented; app does not enforce production policy |
| Agent credential protection/revocation | Open | Plaintext endpoint JSON; no revoke/quarantine state |
| Execution limits | Partial | Five-minute timeout and sequential runtime; no output/queue policy |
| Audit integrity | Partial | Hash chain and local Merkle anchors; ambiguous ordering and no external publisher |
| Database lifecycle | Implemented | Alembic baseline/forward revision, fresh PostgreSQL CI migration, data-preservation test, and exact non-debug startup revision check |
| Backup, restore, rollback | Open | No automated process or rehearsal evidence |
| Windows lifecycle CI | Partial | Go build/unit tests run on Windows; service and installer lifecycle automation remains open |
| Release authenticity | Open | Checksums exist; artifacts are unsigned; no SBOM/provenance |
| Soak evidence | Open | No documented multi-day test |

## Controlled pilot gate

All critical items below must be complete before a pilot. Each checked item must
link to reproducible evidence in the release or pilot record.

### Configuration and topology

- [ ] Production mode rejects `DEBUG=true`, placeholder `SECRET_KEY`, missing
      signing keys, and non-HTTPS public URLs.
- [ ] uvicorn is reachable only through the intended loopback/private proxy
      boundary.
- [ ] TLS certificate issuance, renewal, expiration monitoring, and emergency
      replacement are documented and tested.
- [ ] Proxy trust and client-IP handling are explicitly configured; spoofed
      forwarding headers are tested.
- [ ] Firewall rules expose only required services.
- [ ] Time synchronization and clock-skew assumptions for signed expiry are
      monitored.
- [ ] Optional certificate pinning, if enabled, has overlapping pins and a
      documented rotation/recovery path.

### Command trust

- [x] A versioned contract defines the currently signed fields and canonical encoding.
- [x] `expires_at`, nonce, schema version, agent ID, operation/payload, and
      issued-at time are bound into the signature.
- [x] Shared positive and negative vectors pass in server and agent tests.
- [x] Unknown versions, invalid times, duplicate nonces, and malformed
      payloads fail closed without execution.
- [ ] Signing-key activation, overlap, retirement, compromise, and rollback are
      documented and audited.
- [ ] Typed operations are used where available; arbitrary script permission is
      explicit.

### Agent identity and endpoint storage

- [ ] Operators can quarantine and revoke an agent with audited reason.
- [ ] Revoked credentials fail authentication; quarantined agents receive only
      policy-approved recovery behavior.
- [ ] Windows agent secrets are DPAPI-protected under the intended service
      identity and file ACLs are validated.
- [ ] Plaintext identity migration fails safely and does not leave recoverable
      secret copies.
- [ ] Logs, diagnostics, command results, and uninstall paths do not expose
      credentials.
- [ ] Re-enrollment and lost-identity recovery procedures preserve audit
      continuity or explicitly document a new identity.

### Execution resource safety

- [ ] Stdout and stderr have independent and combined byte limits.
- [ ] Truncation is explicit, deterministic, and recorded in command/audit data.
- [ ] Per-agent concurrency and queue/admission limits are configured and tested.
- [ ] Timeout, cancellation, service stop, server outage, and result retry do not
      orphan processes or duplicate execution.
- [ ] Payload and script-size limits exist at API and agent boundaries.
- [ ] Disk and log growth are bounded and observable.

### Audit evidence

- [ ] Every audit event receives a unique monotonic sequence in a serialized
      append transaction.
- [ ] Hash verification detects field changes, removal, reordering, and sequence
      gaps.
- [ ] Anchors are published automatically to an external immutable destination.
- [ ] Publication receipts, lag, retry, and failure alerts are retained.
- [ ] A clean verifier can validate the chain and external anchor without write
      access to the NodeLink database.
- [ ] Sensitive fields and secrets are redacted without removing accountability.

### Database and recovery

- [x] Alembic can create a fresh schema and upgrade every supported prior
      production revision.
- [x] Application startup refuses an unsupported schema state.
- [ ] Automated encrypted backups run on schedule and failures alert.
- [ ] Backup retention, access, encryption-key custody, and deletion are
      documented.
- [ ] A restore rehearsal validates data, authentication, queued work, and audit
      verification.
- [ ] Release rollback includes schema compatibility and a decision point for
      forward-fix versus restore.
- [ ] Recovery objectives are selected and measured by the maintainer.

### Windows and release engineering

- [ ] Windows CI builds the agent and installer and tests install, service start,
      stop, restart, upgrade, and uninstall.
- [ ] Supported Windows versions and architectures are explicitly listed.
- [ ] Agent and installer are Authenticode-signed and timestamped; signatures
      are verified before publication.
- [ ] Release checksums cover final signed artifacts.
- [ ] An SBOM and provenance attestation are published and independently
      verified.
- [ ] Release notes state known limitations, schema/agent compatibility, upgrade,
      rollback, and security impact.

### Pilot operations

- [ ] Pilot scope names endpoints, owners, allowed actions, data handling,
      maintenance window, and stop criteria.
- [ ] Pilot endpoints are non-critical and can be reimaged or recovered.
- [ ] Monitoring covers server health, database, certificate, agents, queues,
      audit anchoring, backup, and disk capacity.
- [ ] A multi-day soak test records versions, topology, workload, restarts,
      outages, resource trends, commands, and audit verification.
- [ ] Critical/high findings from the soak test are resolved or explicitly block
      the pilot.
- [ ] Incident contacts, credential rotation, agent quarantine, server shutdown,
      restore, rollback, and evidence preservation procedures are rehearsed.

## Backup and restore outline (not yet automated)

Until the tracked backup issue is complete, there is no supported production
procedure. The implementation must eventually provide scripts or documented
commands that:

1. Quiesce or consistently snapshot PostgreSQL without silently losing command
   or audit transactions.
2. Encrypt the backup and store it outside the application host.
3. Record database/application/schema versions and a manifest checksum.
4. Restore into an isolated environment.
5. Run migrations only when the compatibility path says to do so.
6. Verify operators, agents, commands, audit chain, anchors, and publication
   receipts.
7. Record recovery time, recovery point, and exceptions.

Do not treat copying a live database directory or SQLite file as a production
backup plan.

### Schema rollout and compatibility

For a fresh database, run `alembic upgrade head` before starting a non-debug
server. For an existing database made by the former debug `create_all` path:

1. Stop writes and take a tested backup.
2. Verify the live schema matches revision `0001`; `alembic stamp` performs no
   validation.
3. Run `alembic stamp 0001`, then `alembic upgrade head`.
4. Start the server with `DEBUG=false` and confirm the revision guard passes.
5. Upgrade agents to a build that advertises `command-v2`; command dispatch is
   intentionally unavailable until each agent reports support.

Revision `0002` preserves historical rows, labels existing commands
`legacy-unversioned`, and expires queued legacy commands. A new agent refuses an
old server's missing version, while a new server refuses enrollment/dispatch to
an old agent. There is no dual-issue or downgrade mode. In-place database
downgrade is unsupported; use a forward fix, or restore a pre-migration backup
with the correspondingly old server and agent only after an explicit data-loss
decision.

## Rollback outline (not yet validated)

Every release needs a release-specific rollback section. At minimum it must
identify the last compatible server, agent, installer, and schema; state whether
the database migration is reversible; prevent an automatic agent rollout from
reapplying the bad version; preserve audit evidence; and define verification
after rollback. A schema restore is a destructive recovery action and must use a
tested backup with an explicit operator decision.

## Progression after the gate

Deployment progresses from developer machine, to owned disposable Windows VM,
to controlled non-production pilot, to broader non-critical use. Regulated
production endpoints require the later identity, tenant, evidence, retention,
operational, and customer-specific controls in Milestone 3 plus appropriate
legal/compliance review.
