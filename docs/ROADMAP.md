# NodeLink phased execution roadmap

This roadmap turns the current agent/API scaffold into a staged development
program. GitHub milestones and issues track execution; this document records
scope, ordering, and dependency policy. A milestone is complete only when its
acceptance evidence exists, not when code has merely been merged.

## Delivery principles

1. Deployment and command-path safety precede pilot use.
2. Windows is the primary supported endpoint platform.
3. The dashboard precedes broad feature expansion so technicians can use and
   validate each capability.
4. Inventory precedes monitoring; monitoring precedes scheduled remediation;
   patching precedes broader endpoint operations.
5. Typed endpoint operations are preferred over arbitrary shell commands.
6. Polling remains a resilient fallback after interactive transport is added.
7. Remote desktop is integrated through MeshCentral, not a proprietary
   protocol.
8. Security-sensitive work includes tests and synchronized documentation.
9. No phase may imply HIPAA compliance. The product provides controls and
   evidence designed for regulated environments.

## Current baseline

Implemented today: outbound heartbeat polling, enrollment, basic telemetry,
buffered signed command execution, global operator RBAC, Windows service and
installer, hash-chained audit events, local Merkle anchors, Linux CI for Go and
Python, tagged binaries, installer, and checksums.

Material baseline gaps: the command signature omits expiry and versioning;
endpoint credentials are plaintext; agents cannot be revoked or quarantined;
production TLS is procedural; result and execution resources are not explicitly
bounded; audit ordering and external publication are incomplete; migrations,
recovery automation, Windows CI, signed releases, provenance, and soak evidence
are absent. There is no dashboard or general RMM feature set.

## Live execution program

| Phase | GitHub milestone | Initial issue count |
|---|---|---:|
| 0 | [Deployment Safety](https://github.com/lcolon231/rmm-agent/milestone/1) | 18 |
| 1 | [Windows RMM MVP](https://github.com/lcolon231/rmm-agent/milestone/2) | 26 (including the pre-existing personalized-installer issue) |
| 2 | [Patch and Remediation](https://github.com/lcolon231/rmm-agent/milestone/3) | 13 |
| 3 | [Compliance Productization](https://github.com/lcolon231/rmm-agent/milestone/4) | 12 |
| 4 | [Scale and Ecosystem](https://github.com/lcolon231/rmm-agent/milestone/5) | 9 |

The initial program contains 78 open issues. Counts will change as work is split,
completed, or re-scoped; milestone goals and exit criteria remain authoritative.

## Dependency spine

```text
Versioned signed envelope ─┬─> agent revocation/quarantine ─> controlled pilot
                           ├─> output/concurrency limits ────┘
Migrations ─> backup/restore ─> rollback drill ─────────────┘
Windows CI ─> Authenticode + release evidence ──────────────┘
Audit sequence ─> external anchor publisher ────────────────┘

Controlled pilot ─> dashboard foundation ─> inventory ─> monitoring/alerts
                 ─> script library/scheduling ─> patching/remediation
                 ─> MeshCentral ─> compliance evidence ─> scale/ecosystem
```

Work can run in parallel within a phase when its dependencies are satisfied,
but a later milestone does not redefine an earlier safety gate as complete.

## Milestone 0 — Deployment Safety

**Goal:** make NodeLink safe enough for controlled, non-production pilots.

### Delivery order

1. **Protocol trust:** define a versioned signed command envelope; bind expiry,
   nonce, schema version, and signing-key IDs; publish shared vectors; operate
   key rotation and compromise recovery.
2. **Endpoint trust:** implement revocation/quarantine and DPAPI credential
   protection; define optional certificate pinning.
3. **Execution safety:** enforce stdout/stderr limits, explicit per-agent
   concurrency, admission behavior, and tests.
4. **Audit guarantees:** add monotonic sequence numbers and serialized append
   behavior, then publish anchors to an external immutable destination with
   receipts and verification.
5. **Data safety:** introduce Alembic migrations, automated backup/restore, and
   a tested rollback procedure.
6. **Release confidence:** add Windows installer/service lifecycle CI,
   Authenticode signing, SBOMs, checksums, provenance attestations, and release
   verification.
7. **Pilot evidence:** run and document a multi-day soak test after the above
   controls are deployed.

### Exit criteria

- Production mode rejects unsafe transport and placeholder secrets.
- Supported agents accept only documented envelope versions and active keys.
- A revoked or quarantined agent cannot receive or report normal work.
- Execution resource limits are deterministic and covered by tests.
- Audit events have an unambiguous sequence and externally verifiable anchors.
- A fresh database can migrate forward; a documented backup can be restored and
  rolled back in a rehearsal.
- Windows release artifacts are signed and independently verifiable with SBOM,
  checksum, and provenance evidence.
- The controlled pilot soak report has no unresolved critical finding.

## Milestone 1 — Windows RMM MVP

**Goal:** make NodeLink usable by a technician through a web interface.

### Delivery order

1. **Dashboard foundation:** scaffold Next.js, implement authentication/session
   handling, client/site navigation, and role-aware layout.
2. **Endpoint workflow:** endpoint table and filters, endpoint detail and basic
   telemetry, command dispatch/results, audit timeline/verification,
   enrollment-token management, and operator administration.
3. **Inventory:** complete hardware and installed-software collection; Defender,
   BitLocker, Secure Boot, TPM, and local-administrator state; normalized
   history and diffs.
4. **Monitoring:** policy model; offline, disk, CPU, memory, service, and pending
   reboot checks; deduplication; acknowledgement and resolution.
5. **Notifications:** email and generic webhooks with retry, redaction, and
   delivery history.
6. **Automation:** versioned script library, typed parameter definitions,
   recurring task scheduling, and complete task-run history.

### Exit criteria

- A technician can authenticate and complete the endpoint enrollment, inspect,
  command, and audit workflows without direct API calls.
- Supported inventory fields have timestamps, provenance, history, and diffs.
- Monitoring transitions and alert lifecycle are deterministic and tested.
- Notification failures are visible and retryable.
- Scripts are versioned, parameterized, scheduled, policy-checked, and tied to
  immutable run history.

## Milestone 2 — Patch and Remediation

**Goal:** cover the majority of routine Windows endpoint operations.

Workstreams, in order:

1. Windows Update scan, missing-update inventory, approval policies,
   maintenance windows, installation, reboot policy, and compliance reporting.
2. Winget integration; optional Chocolatey support only after the provider
   boundary is designed; MSI and EXE deployment.
3. Typed service, process, event-log, file-transfer, registry, reboot, and
   shutdown operations.
4. Interactive remote shell and streaming command output over a live transport,
   retaining polling fallback.
5. Technician-to-end-user chat over the same live transport: the agent surfaces
   a chat window on the endpoint so the machine's user can talk to the
   technician from their computer, with sessions initiated or accepted
   endpoint-side, participant identity on every message, complete audit of
   session lifecycle, bounded/retained transcripts, and no remote-control
   capability piggybacked on the chat channel.
6. MeshCentral remote desktop integration with explicit authorization and audit
   boundaries.
7. Signed, staged, rollback-capable agent self-update.

Exit requires maintenance-window and reboot safety tests, idempotent remediation
where appropriate, complete audit coverage, and Windows end-to-end evidence.

## Milestone 3 — Compliance Productization

**Goal:** provide evidence and controls suitable for regulated customers.

Workstreams:

- JSON, CSV, PDF, and signed-ZIP evidence bundles with documented schemas and
  verification instructions.
- Approval workflow, two-person authorization for sensitive actions, and
  justified emergency override.
- Explicit tenant IDs, tenant-scoped authorization, tenant-specific roles and
  retention, and isolation tests.
- MFA, WebAuthn, OIDC or SAML, break-glass accounts, and administrative session
  management.
- Immutable evidence storage, retention policy enforcement, and legal hold.
- Standalone audit verification CLI and a customer-facing read-only audit
  portal.

Exit requires a documented control/evidence mapping, tenant isolation test
suite, export verification from a clean environment, retention/legal-hold
tests, and a security review. This milestone does not by itself constitute a
compliance certification.

## Milestone 4 — Scale and Ecosystem

**Goal:** expand beyond the initial Windows-first regulated-SMB niche.

Workstreams:

- Shared rate limiting, distributed workers, queue-backed task execution, and
  high availability with failure-mode tests.
- Linux and macOS agents after platform contracts and support policy exist.
- Versioned public API and webhook event catalog.
- PSA integrations and Terraform or Ansible deployment automation.
- Moderated community script repository and signed extension system.
- Multi-region relays with explicit tenancy, routing, key, and audit semantics.

Scale work must preserve signed-action, tenant-isolation, and audit guarantees;
availability improvements may not silently weaken them.

## Repository evolution

The repository may evolve toward `agent/`, `server/`, `dashboard/`, `installer/`,
`deploy/`, `contracts/`, `tools/`, `docs/`, and `.github/`. The first structural
change should add `contracts/` for versioned protocol schemas and canonical
signature vectors. Other moves require separate design issues and must preserve
build, test, release, and import paths.

## Prioritization within milestones

Use `priority:critical` only for work that blocks safe deployment or closes a
direct trust-boundary failure. Use `priority:high` for milestone-critical product
flows, `priority:medium` for necessary supporting work, and `priority:low` for
deferred enhancements. `blocked` always names the blocking issue or decision;
`needs-design` identifies unresolved interfaces or security semantics.
