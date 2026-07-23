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
| Signed command verification | Implemented | `command-v3`, negotiation, downgrade rejection, signed schema/time/nonce/key ID, and shared vectors; staged key rotation, compromise, and rollback via `scripts/rotate_command_key.py` with a rehearsed test suite and `docs/KEY-ROTATION.md` runbook |
| Agent replay/expiry checks | Implemented | Signed time-window validation plus durable command-ID and nonce replay state |
| Production TLS | Partial | Caddy topology documented; ENVIRONMENT=production fails startup on debug/placeholder-secret/missing-key/non-HTTPS-URL config and proxy trust is explicit opt-in; certificate lifecycle monitoring remains operator evidence |
| Optional certificate pinning | Implemented | Agent `tls_spki_pins` adds strict multi-pin leaf-SPKI SHA-256 matching after normal PKI validation; off by default, fail-closed mismatch/config tests, current+next rotation, and stale/expired recovery runbook |
| Agent credential protection/revocation | Partial | Trust states (quarantine/restore/revoke) with audited, reasoned operator transitions and fail-closed enforcement; DPAPI envelope + restricted ACL on Windows with atomic plaintext migration. Windows-runner evidence for migration/ACL paths ships with Windows CI (issue #23) |
| Execution limits | Partial | Five-minute timeout, sequential runtime, bounded stdout/stderr with audited truncation metadata, and dispatch payload caps; queue/admission and explicit concurrency policy remain open (#20) |
| Audit integrity | Implemented | Hash chain with monotonic, hash-bound sequence numbers under serialized append; local Merkle anchors; scheduled external anchor publication (filesystem/WORM or S3 Object Lock) with tamper-evident receipts, lag alerting, idempotent retry, and a clean-room verifier (`docs/AUDIT-ANCHORING.md`). Publication is opt-in and loud when unconfigured |
| Database lifecycle | Implemented | Alembic baseline/forward revision, fresh PostgreSQL CI migration, data-preservation test, and exact non-debug startup revision check |
| Backup, restore, rollback | Partial | Encrypted backup/isolated restore plus a fail-closed release compatibility planner and N→bad N+1→N PostgreSQL rehearsal verify schema, operators, agents, commands, audit chain, anchors, and explicit data loss in CI. Scheduled production evidence, retention monitoring, and a timed operator drill remain |
| Windows lifecycle CI | Implemented | Windows CI builds the agent and installer and exercises service install/start/stop/restart/refuse-double-install/uninstall plus a silent installer install+uninstall smoke test |
| Release authenticity | Partial | Checksums, an SPDX SBOM (Go + Python), and signed SLSA build-provenance attestations are published for every artifact; Authenticode signing is the one remaining gap (needs a paid certificate) |
| Soak evidence | Partial | Soak harness with workload, fault injection, resource/audit/anchor sampling, and pass/fail reporting ships (`deploy/soak/`, `docs/SOAK-TEST.md`), CI-smoke-tested and demonstrated against a live server; the multi-day pilot run itself is operator evidence |

## Controlled pilot gate

All critical items below must be complete before a pilot. Each checked item must
link to reproducible evidence in the release or pilot record.

### Configuration and topology

- [x] Production mode rejects `DEBUG=true`, placeholder `SECRET_KEY`, missing
      signing keys, and non-HTTPS public URLs (ENVIRONMENT=production fails
      startup with every violation listed; covered by a configuration-matrix
      test).
- [ ] uvicorn is reachable only through the intended loopback/private proxy
      boundary.
- [ ] TLS certificate issuance, renewal, expiration monitoring, and emergency
      replacement are documented and tested.
- [x] Proxy trust and client-IP handling are explicitly configured; spoofed
      forwarding headers are tested (X-Forwarded-For is ignored unless
      TRUST_PROXY_HEADERS=true; only the rightmost, proxy-appended entry is
      trusted).
- [ ] Firewall rules expose only required services.
- [ ] Time synchronization and clock-skew assumptions for signed expiry are
      monitored.
- [x] Optional certificate pinning, if enabled, supports overlapping leaf-SPKI
      SHA-256 pins while retaining normal PKI validation and has documented
      rotation, rollback, expired-certificate, and stale-pin recovery paths
      (`docs/CERTIFICATE-PINNING.md`).

### Command trust

- [x] A versioned contract defines the currently signed fields and canonical encoding.
- [x] `expires_at`, nonce, schema version, agent ID, operation/payload,
      issued-at time, and signing-key ID are bound into the signature.
- [x] Shared positive and negative vectors pass in server and agent tests.
- [x] Unknown versions, invalid times, duplicate nonces, and malformed
      payloads fail closed without execution.
- [x] Signing-key activation, overlap, retirement, compromise, and rollback are
      operator-run, documented, audited, and rehearsed (`scripts/rotate_command_key.py`;
      atomic registry writes with an append-only rotation journal;
      `docs/KEY-ROTATION.md`; full staged + compromise + rollback rehearsal in
      `tests/test_key_rotation.py`).
- [ ] Typed operations are used where available; arbitrary script permission is
      explicit.

### Agent identity and endpoint storage

- [x] Operators can quarantine and revoke an agent with audited reason.
- [x] Revoked credentials fail authentication; quarantined agents receive only
      policy-approved recovery behavior (a bare heartbeat ack: no commands, no
      key material, no recorded telemetry; result submission refused).
- [x] Windows agent secrets are DPAPI-protected under the intended service
      identity and file ACLs are validated (user-scope DPAPI under the
      enrolling account; protected SYSTEM+Administrators DACL asserted by a
      Windows CI test).
- [x] Plaintext identity migration fails safely and does not leave recoverable
      secret copies (atomic write-then-rename replacement; load refuses to
      proceed if the protected form cannot be persisted).
- [x] Logs, diagnostics, command results, and uninstall paths do not expose
      credentials (dedicated redaction audit in
      [`REDACTION-AUDIT.md`](REDACTION-AUDIT.md): a central server boundary
      (`app/core/redaction.py`) and agent `redact` package scrub credential
      shapes from logs/errors; command output is classified sensitive and only
      read through the role-gated, audited command-detail endpoint; the
      uninstaller removes `config.json`, `identity.json`, and
      `seen_commands.json`; sentinel-secret tests cover server, agent, and the
      audit chain).
- [x] Re-enrollment and lost-identity recovery procedures preserve audit
      continuity or explicitly document a new identity (revocation is terminal;
      recovery is re-enrollment as a new agent ID, tested end-to-end).

### Execution resource safety

- [x] Stdout and stderr have independent and combined byte limits (256 KiB
      per stream, 384 KiB combined; excess is counted, never buffered).
- [x] Truncation is explicit, deterministic, and recorded in command/audit data
      (structured flags plus original byte totals persisted on the command and
      in `command.completed` audit detail; stderr preserved over stdout when
      the combined cap binds).
- [x] Per-agent concurrency and queue/admission limits are configured and tested
      (per-agent outstanding-command cap admits/refuses at the dispatch
      boundary; per-heartbeat FIFO batch cap; agent executes one at a time).
- [ ] Timeout, cancellation, service stop, server outage, and result retry do not
      orphan processes or duplicate execution.
- [x] Payload and script-size limits exist at API and agent boundaries
      (64 KiB dispatch payload cap; server refuses over-cap results, and the
      agent's script arrives inside the signed, capped payload).
- [ ] Disk and log growth are bounded and observable.

### Audit evidence

- [x] Every audit event receives a unique monotonic sequence in a serialized
      append transaction (PostgreSQL advisory lock; unique constraint as the
      fail-closed backstop; concurrency-tested).
- [x] Hash verification detects field changes, removal, reordering, and sequence
      gaps (seq is bound into the event hash for all post-0007 events; legacy
      events are explicitly marked hash_schema=1 and may not follow the
      cutover).
- [x] Anchors are published automatically to an external immutable destination
      (scheduled publisher; S3 Object Lock or a WORM filesystem; opt-in with a
      loud warning when unconfigured).
- [x] Publication receipts, lag, retry, and failure alerts are retained
      (`AnchorPublication` rows with receipt + `receipt_sha256`; idempotent
      retry; `GET /audit/publication-status` lag/alert; scheduler warns on lag).
- [x] A clean verifier can validate the chain and external anchor without write
      access to the NodeLink database (`scripts/verify_anchor_receipt.py`
      recomputes the Merkle root from read-only event hashes and the downloaded
      artifact; it does not import NodeLink).
- [x] Sensitive fields and secrets are redacted without removing accountability
      (every `audit.record` runs `detail` through the deterministic
      `app/core/redaction.py` boundary before hashing; secrets are removed by
      key name plus PEM/JWT value shapes while accountable public values —
      Merkle roots, event hashes, nonces, envelope digests, actor/action/target
      IDs — are preserved, so chain and anchor verification stay reproducible;
      tested against every existing producer and clean-room anchor
      verification — see [`REDACTION-AUDIT.md`](REDACTION-AUDIT.md)).

### Database and recovery

- [x] Alembic can create a fresh schema and upgrade every supported prior
      production revision.
- [x] Application startup refuses an unsupported schema state.
- [ ] Automated encrypted backups run on schedule and failures alert
      (tooling shipped and CI-rehearsed — deploy/backup/ + docs/BACKUP-RESTORE.md;
      the checked box requires evidence from the production schedule itself).
- [x] Backup retention, access, encryption-key custody, and deletion are
      documented (docs/BACKUP-RESTORE.md).
- [x] A restore rehearsal validates data, authentication, queued work, and audit
      verification (isolated restore + verify_restore.py checks row counts,
      the audit chain in sequence order, and every stored anchor; rehearsed in
      CI on every run).
- [x] Release rollback includes schema compatibility and a fail-closed decision
      point for forward-fix versus component redeploy versus exact-revision
      restore (`scripts/plan_release_rollback.py`; N→bad N+1→N is rehearsed in
      the PostgreSQL suite with explicit rollout pause and data-loss approval).
- [ ] Recovery objectives are selected and measured by the maintainer.

### Windows and release engineering

- [x] Windows CI builds the agent and installer and tests install, service start,
      stop, restart, refuse-double-install, and uninstall (CLI lifecycle script
      driving the SCM) plus a silent installer install/uninstall smoke test.
- [ ] Supported Windows versions and architectures are explicitly listed.
- [ ] Agent and installer are Authenticode-signed and timestamped; signatures
      are verified before publication (deferred: requires a paid code-signing
      certificate; the workflow has a documented slot for it).
- [x] Release checksums cover final artifacts (`SHA256SUMS.txt` over the
      binaries and SBOM; a `.sha256` sidecar for the installer). They will move
      to cover *signed* artifacts once signing lands.
- [x] An SBOM and provenance attestation are published and independently
      verified (SPDX SBOM; signed SLSA build provenance via
      `actions/attest-build-provenance`, verifiable with `gh attestation verify`).
- [ ] Release notes state known limitations, schema/agent compatibility, upgrade,
      rollback, and security impact.

### Pilot operations

- [ ] Pilot scope names endpoints, owners, allowed actions, data handling,
      maintenance window, and stop criteria.
- [ ] Pilot endpoints are non-critical and can be reimaged or recovered.
- [ ] Monitoring covers server health, database, certificate, agents, queues,
      audit anchoring, backup, and disk capacity.
- [ ] A multi-day soak test records versions, topology, workload, restarts,
      outages, resource trends, commands, and audit verification (harness and
      runbook ready — `deploy/soak/soak.py`, `docs/SOAK-TEST.md`; the checked
      box requires the actual multi-day run's evidence).
- [ ] Critical/high findings from the soak test are resolved or explicitly block
      the pilot.
- [ ] Incident contacts, credential rotation, agent quarantine, server shutdown,
      restore, rollback, and evidence preservation procedures are rehearsed.

## Backup, restore, and rollback evidence

The shipped procedure and automated rehearsal provide:

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
5. Upgrade agents to a build that advertises `command-v3`; command dispatch is
   intentionally unavailable until each agent reports support.

Revision `0002` preserves historical rows, labels existing commands
`legacy-unversioned`, and expires queued legacy commands. A new agent refuses an
old server's missing version, while a new server refuses enrollment/dispatch to
an old agent. There is no dual-issue or downgrade mode. In-place database
downgrade is unsupported; use a forward fix, or restore a pre-migration backup
with the correspondingly old server and agent only after an explicit data-loss
decision.

## Rollback procedure

Every release needs the release-specific compatibility record in
`docs/ROLLBACK.md`. The planner fails closed unless it identifies the target
server, agent, installer, and schema and confirms external agent rollout is
paused. Migrations are forward-only; a schema restore requires a matching tested
backup and explicit acceptance of post-backup data loss. The runbook preserves
failed-state and audit evidence and defines post-rollback verification.

The automated PostgreSQL rehearsal is complete and reproducible in CI. The
incident-response checkbox under Pilot operations remains open until operators
perform a timed drill against the production topology and actual external
software-deployment controls.

## Progression after the gate

Deployment progresses from developer machine, to owned disposable Windows VM,
to controlled non-production pilot, to broader non-critical use. Regulated
production endpoints require the later identity, tenant, evidence, retention,
operational, and customer-specific controls in Milestone 3 plus appropriate
legal/compliance review.
