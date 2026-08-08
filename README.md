# NodeLink RMM

NodeLink is a self-hosted endpoint-management platform for regulated small
businesses and MSPs. It provides signed remote actions, outbound-only
connectivity, and independently verifiable administrative audit records without
the operational complexity of traditional RMM platforms.

NodeLink is an early-stage, Windows-first project. It is not ready for production or regulated endpoints, and does not claim
HIPAA compliance. The near-term goal is a controlled non-production pilot with
HIPAA-supporting controls and defensible compliance evidence.

## Project status

| Area | Current state |
| --- | --- |
| Latest tagged release | `v0.1.2` |
| Primary support target | Windows agent and Windows service |
| Server | FastAPI management and agent APIs with PostgreSQL; SQLite is limited to development and tests |
| Dashboard | Authenticated Next.js interface with live enrollment, endpoint, command, inventory, monitoring-policy, audit-evidence, and administrator workflows; the aggregate operations overview remains fixture-backed |
| Deployment | Self-hosted Caddy topology and a Render Docker Blueprint for a stateless backend using external PostgreSQL |
| Current milestone | Milestone 0 pilot gates plus the implemented portion of Milestone 1 |
| Pilot blockers | Authenticode signing and a recorded multi-day soak run on the intended pilot topology |
| Production status | Not approved for production or regulated endpoints |

The source of truth for completion claims is the
[architecture document](docs/ARCHITECTURE.md). Pilot gates are tracked in the
[deployment-readiness checklist](docs/DEPLOYMENT-READINESS.md), and future
product scope is tracked in the [phased roadmap](docs/ROADMAP.md).

## Product direction

NodeLink intends to compete through simpler deployment, policy-controlled and
signed endpoint actions, verifiable audit evidence, and a focused experience for
regulated SMBs and MSPs. General RMM breadth comes later. See the
[competitive strategy](docs/COMPETITIVE-STRATEGY.md) and the
[phased roadmap](docs/ROADMAP.md).

## Current implementation

The code in this repository currently provides:

- A Go agent that runs as a Windows service, connects outbound, and polls the
  FastAPI server through heartbeat responses.
- One-time or limited-use enrollment tokens and long-lived per-agent bearer
  credentials. Server-side token values are stored as SHA-256 hashes.
- Ed25519 signatures over the negotiated `command-v3` envelope: envelope
  version, schema version, command ID, agent ID, kind, payload, issued-at,
  expiry, and nonce. Python and Go consume the same canonical vectors; agents
  reject missing, unknown, malformed, expired, replayed, and downgraded
  envelopes. Key IDs support active/overlap/retired registry states; v2 remains
  available only for mixed-version rollout. Staged key rotation, compromise
  response, and rollback are operator-run via `scripts/rotate_command_key.py`
  (`docs/KEY-ROTATION.md`).
- Basic CPU, memory, system-disk, uptime, and logged-in-user telemetry.
- Windows hardware inventory: manufacturer/model/serial/BIOS, CPU, memory
  totals and modules, disks and volumes, and network adapters. Each section is
  collected under its own timeout and carries a status, so a failed CIM query
  degrades one section to `unavailable` instead of voiding the snapshot — an
  absent field is never reported as an empty one. The agent advertises a
  per-section hash on each heartbeat and uploads only what the server asks for,
  so an unchanged endpoint transfers no inventory bytes. Submissions are atomic
  and bounded: an oversized or malformed section is rejected rather than
  truncated. Defender, BitLocker, Secure Boot, TPM, and local Administrators
  membership are each collected as their own sections, described below.
- Windows installed-software inventory from the uninstall registry across the
  native 64-bit, `WOW6432Node`, and per-user views, deduplicated across them
  and sorted deterministically so an unchanged machine keeps a stable content
  hash. Install dates are reported only when they parse cleanly. This section
  is bounded by encoded bytes rather than row count, so a machine with unusually
  long program names reports a `partial` list instead of being rejected and
  reporting nothing.
- Read-only Windows Defender status: provider state, real-time and tamper
  protection, engine/signature versions, signature age, and scan times. Posture
  is a separate field from collection status, so a machine running a
  third-party antivirus with Defender stood down is reported as configured
  rather than as unprotected — Defender reports itself disabled while passive,
  and treating that as an alarm would bury the genuinely unprotected endpoints.
  Signature age is computed on the endpoint so a wrong clock still yields a
  correct age. Nothing in this path changes configuration.
- Read-only BitLocker, Secure Boot, and TPM state as three independent
  sections, so one permission failure cannot void the others. **No BitLocker
  recovery key is ever collected** — the query names its properties explicitly
  so key material is never read, and the schema has no field able to hold it.
  Section status distinguishes `permission_denied` from `unavailable`, because
  an empty volume list recorded as healthy would read as "nothing is
  encrypted". Secure Boot on legacy BIOS is reported unsupported rather than
  disabled, and an absent TPM is a successful reading, not a failure.
- Read-only local Administrators membership: the built-in group is resolved by
  its well-known SID (`S-1-5-32-544`) rather than the localized name, and each
  member is classified by identity type (local, domain, or Entra ID) and
  principal class. An unreachable directory is reported `unavailable` and a
  non-Windows host `unsupported`, so an empty membership is never mistaken for
  "no administrators". Membership is never expanded beyond the group itself — a
  nested group is one `group` member, not its transitive users.
- Inventory history and deterministic diffs, with per-endpoint dashboard views.
  Snapshots are written only when a section's content changes, so history is a
  change log rather than a sample. Diffs are identity-keyed rather than
  positional: uninstalling one program reports one removal instead of rewriting
  the whole list. Retention is bounded per section and never prunes the newest
  snapshot, so an endpoint always keeps its current reported state. A section
  that could not be read renders distinctly from one that was read and found
  empty.
- Versioned monitoring-policy identities at global, client, site, and agent
  scopes, with bounded typed check definitions, most-specific-wins resolution,
  scoped maintenance-window records, and an append-only check-result contract
  retained newest-N per endpoint/check key. Operator APIs provide role-gated,
  audited policy/window management plus effective-policy and result reads; the
  dashboard provides a read-only policy list, current check set, and revision
  history. Active agents now execute cadence- and hysteresis-bounded CPU,
  memory, disk, service, and pending-reboot checks with a durable idempotent
  result outbox; the server evaluates offline checks from heartbeat age and
  validates revision-pinned result ingestion. Deterministic alert state,
  maintenance suppression, technician lifecycle actions, durable email, and
  signed generic-webhook notification paths are implemented with live delivery
  history. See `docs/MONITORING.md`, `docs/ALERT-NOTIFICATIONS.md`, and
  `docs/SIGNED-WEBHOOKS.md`.
- Buffered PowerShell or shell execution with a five-minute timeout and
  bounded output capture (256 KiB per stream, 384 KiB combined, truncation
  recorded in command and audit data). Completed results are DPAPI-protected
  in a durable agent outbox before upload and retried idempotently across
  outages, lost acknowledgements, and restarts. Windows commands run in
  kill-on-close Job Objects so timeout, service stop, agent exit, and normal
  shell completion terminate the complete process tree.
- Default-deny arbitrary-script authorization: PowerShell and shell require an
  explicit admin-granted global, site, or agent scope even for admins, while
  typed inventory remains role-authorized. Grant changes and every allow/deny
  decision are audited without recording script contents.
- An immutable versioned script library with canonical SHA-256 content
  evidence, bounded language/platform/tag metadata, append-only final reviews,
  terminal idempotent deprecation, role-gated API/dashboard workflows, and no
  implicit execution permission (`docs/SCRIPT-LIBRARY.md`).
- Immutable typed script parameters (`string`, `number`, `boolean`, `choice`,
  `secret`) with strict defaults/bounds, encrypted expiring per-run value sets,
  keyed idempotency, safe PowerShell/POSIX variable binding, and secret-redacted
  API/dashboard/audit evidence. Live scheduling/dispatch remains issue #49.
- Fail-closed production startup validation (`ENVIRONMENT=production` rejects
  debug mode, placeholder secrets, missing signing keys, and non-HTTPS public
  URLs) with explicit opt-in proxy trust for client IPs.
- A Docker deployment path for the FastAPI server and a Render Blueprint that
  runs Alembic before deployment, uses Render's external URL behind its proxy,
  expects PostgreSQL through `DATABASE_URL`, and mounts the command-signing key
  as a secret file. This is deployment scaffolding, not a production-readiness
  claim.
- Operator password authentication, JWT sessions, three global roles, complete
  enrollment-token lifecycle management, transactional limited-use redemption,
  token/agent revocation, and in-process login/enrollment throttling.
- Client and site records, agent listing, command dispatch/history APIs, and an
  offline-status sweeper.
- Agent quarantine/restore (operator) and terminal revocation (admin) with
  mandatory reasons and audit events: revoked tokens fail authentication and
  outstanding work is expired; quarantined agents get bare heartbeat acks only.
- DPAPI-protected agent identity on Windows (versioned envelope, restricted
  file ACL, atomic plaintext migration, no plaintext fallback).
- A hash-chained audit log with serialized, hash-bound monotonic sequence
  numbers, plus APIs that create and verify local Merkle
  anchors, plus a scheduled publisher that writes anchor roots to external
  immutable storage (S3 Object Lock or a WORM filesystem) with receipts and
  clean-room verification (opt-in; `docs/AUDIT-ANCHORING.md`).
- Forward-only Alembic migrations through revision `0021`, with exact revision
  enforcement on non-debug startup, legacy debug-schema repair, and a
  disposable PostgreSQL migration test in CI.
- Encrypted PostgreSQL backup/isolated restore plus a fail-closed release
  rollback planner; CI rehearses an incompatible bad release, exact-revision
  restore, explicit data loss, component selection, and audit verification
  (`docs/ROLLBACK.md`).
- An Inno Setup Windows installer and tagged release workflow that publishes
  checksums, an SPDX SBOM, and signed build-provenance attestations. Windows
  binaries and the installer are not yet Authenticode-signed.
- Optional rotation-safe TLS pinning for high-assurance agents: multiple leaf
  SPKI SHA-256 pins are checked after normal PKI validation, with documented
  overlap and stale/expired recovery (`docs/CERTIFICATE-PINNING.md`).
- Linux and macOS development builds of the polling agent. Windows is the only
  primary support target; those builds are not a supported cross-platform RMM.
- An authenticated Next.js dashboard foundation with a responsive operations
  overview, environment-validated server-only API boundary, same-origin
  operator sessions, and live client, site, endpoint-list, and endpoint-detail
  telemetry views, plus a per-endpoint command console: role-gated
  compose-and-confirm dispatch of the supported signed command kinds, paginated
  command history, and per-command records showing envelope evidence, exit
  code, and bounded stdout/stderr with truncation totals.
- Live dashboard enrollment administration: create/list/filter/revoke temporary
  enrollment tokens, inspect and revoke agent identities, and review enrollment
  audit events without placing plaintext tokens in URLs or browser storage.
  A first-run workflow creates the initial client and site through same-origin,
  role-authorized, audited handlers before token creation.
- Live dashboard audit evidence: a sequence-ordered timeline with event-type,
  actor, agent, and UTC date filters; per-event views of the sanitized detail
  that was hashed; and anchor views carrying local anchor verification, external
  publication lag, and per-receipt tamper checks. Filter options come from the
  redaction registry, so they cannot drift from the actions the chain can hold.
  A verification that could not be performed reads as unknown, never as
  verified. Paging is pinned to a sequence ceiling because the chain only
  appends — and because reading the views is itself audited, so the register
  grows as it is read.
- Administrator-only operator management: list and create administrators or
  technicians, show explicit default-deny script permission, grant/change/revoke
  global, site, or agent script scopes with mandatory audited reasons, and
  invalidate sessions, change global roles, and disable/re-enable identities.
  Operator creation and every privilege/state mutation are audited, and the API
  preserves at least one active administrator. The API bearer token remains
  server-side in an HTTP-only cookie, and browser requests use same-origin route
  handlers. Operator deletion, password reset/change, forced initial-password
  rotation, and list pagination are not implemented.

Aggregate operations and general audit panels remain fixture-backed.

The [architecture document](docs/ARCHITECTURE.md) is the source of truth for
the implementation and its security boundaries.

## Dashboard preview

The technician dashboard combines authenticated live endpoint inventory,
telemetry detail, command console, enrollment, and administrator/operator
management flows with fixture-backed aggregate operations and general audit
panels. The screenshots illustrate the current visual direction; they are not
production or compliance evidence.

![NodeLink dashboard operations overview](docs/images/nodelink-dashboard-overview.png)

<img src="docs/images/nodelink-dashboard-mobile.png" alt="NodeLink dashboard operations overview on a mobile screen" width="360" />

## In progress

Milestone 0, Deployment Safety, is nearly complete. Remaining items are an
Authenticode code signing (needs a paid certificate) and running the multi-day
soak test (the harness and runbook ship in `deploy/soak/` and
`docs/SOAK-TEST.md`) before a controlled non-production pilot.

### Recent progress on `main`

The `v0.1.2` release consolidated the secure enrollment work: limited-use
tokens, agent identity and revocation workflows, the live enrollment dashboard,
PostgreSQL migration/rollback evidence, and release verification.

After `v0.1.2`, `main` has:

- shipped administrator-only operator identity management and explicit
  arbitrary-script permission controls in the dashboard, then completed
  audited role/status changes and last-active-administrator protection;
- added audited first-run client/site creation with normalized duplicate-name
  enforcement and a guided enrollment setup flow;
- hardened the dashboard login flow so credentials use same-origin POST
  requests, legacy credential query parameters are stripped, and protected
  pages render from server-validated HTTP-only sessions;
- replaced the fixture-backed audit panel with live timeline, event-detail, and
  anchor/receipt verification views, and made audit reads auditable;
- added bounded Windows hardware inventory with hash-negotiated upload,
  per-section snapshot history, and observable storage growth, replacing an
  unvalidated free-form inventory field that no released agent ever wrote;
- added a Dockerized Render deployment path for the FastAPI backend, including
  pre-deploy migrations, health checks, proxy-aware production configuration,
  external PostgreSQL configuration, and secret-file signing-key support;
- added read-only local Administrators inventory (#39): a locale-independent
  collector that resolves the built-in group by its well-known SID and
  classifies each member's identity type (local, domain, or Entra ID),
  validated and stored as a bounded inventory section;
- added the phase-1 monitoring foundation (#41): append-only scoped policy
  revisions, typed check definitions, deterministic inheritance, maintenance
  windows, bounded check-result history, role-gated audited APIs, and read-only
  dashboard policy views;
- implemented the first monitoring checks (#42): server-owned offline
  evaluation plus agent CPU, memory, disk, service, pending-reboot, and retained
  uptime evaluation with bounded cadence, hysteresis, durable idempotent
  delivery, explicit unknown states, and revision-pinned ingestion;
- added deterministic alert state (#43): one policy/endpoint/check identity,
  exactly-once bounded observations, automatic recovery/reopen, concurrent
  deduplication, policy cleanup, and maintenance suppression metadata;
- added the technician alert lifecycle (#44): role-gated acknowledgement,
  assignment, comments, manual resolution, automatic recovery/reopen,
  optimistic-concurrency and idempotency protection, immutable actor history,
  redacted audit evidence, and live dashboard controls;
- added alert email delivery (#45): environment-owned Resend configuration,
  escaped/redacted transition templates, transactionally durable recipient
  queues, provider idempotency, bounded retry/backoff, maintenance suppression,
  delivery history, audited manual retry, and live dashboard visibility;
- added signed generic webhook delivery (#46): versioned canonical payloads,
  per-destination encrypted rotating secrets, HMAC-SHA256 verification,
  SSRF- and DNS-rebinding-resistant HTTPS delivery, durable bounded retries,
  audited operations, and a live destination and attempt ledger;
- added the immutable script library (#47): canonical content digests,
  append-only versions and final reviews, terminal deprecation, bounded
  role-gated API/dashboard workflows, and recovery documentation;
- added typed script parameters (#48): version-bound definitions, encrypted
  expiring value preparation, strict validation/default/choice behavior,
  cross-platform quoting, and secret-redacted evidence; and
- kept the merged branch green across license, Go, Windows, Python, dashboard,
  migration, installer, and release-target checks.

The current Milestone 1 work remains focused on recurring tasks and
tenant-aware authorization design.

## Planned

- **Milestone 1 — Windows RMM MVP:** authenticated Next.js dashboard, complete
  Windows inventory, monitoring and alerts, notification delivery, script
  library, and recurring tasks.
- **Milestone 2 — Patch and Remediation:** Windows Update policies and
  installation, software deployment, endpoint operations, interactive shell,
  streaming output, technician-to-end-user chat (a chat window on the endpoint
  so the machine's user can talk to the technician from their computer),
  MeshCentral integration, and agent self-update.
- **Milestone 3 — Compliance Productization:** evidence bundles, approval
  workflows, tenant-scoped authorization, stronger identity controls,
  immutable retention, audit verification tools, and a customer audit portal.
- **Milestone 4 — Scale and Ecosystem:** shared infrastructure, distributed
  execution, high availability, public APIs, integrations, signed extensions,
  and later Linux/macOS support.

## Explicitly not implemented yet

The repository does **not** currently contain:

- A general live audit UI or production-ready dashboard. Client/site
  navigation, endpoint inventory, endpoint telemetry detail, endpoint command
  console, enrollment administration/audit, and operator administration use
  live API data; aggregate overview and general audit panels remain
  fixture-backed.
- A working interactive remote shell, live streaming command output,
  technician-to-end-user chat, or command cancellation. Polling remains the only
  command transport and a dispatched command is bounded only by its signed
  expiry. The interactive shell **foundation** has landed (issue #61, Phase 1):
  the authorized/audited/bounded session lifecycle, agent capability
  negotiation, server-side idle/absolute timeouts, and output-limit contract,
  with fail-closed defaults (`docs/SHELL-SESSIONS.md`). The live streaming
  transport, the agent's shell I/O loop, and the dashboard terminal UI are not
  built yet, so the capability is not usable end to end.
- Complete hardware, software, Windows Defender, BitLocker, Secure Boot, or TPM
  inventory beyond the read-only sections described above.
- Additional notification providers beyond email and signed generic webhooks.
  Policy, initial checks, result ingestion, alert deduplication/state,
  technician lifecycle actions, automatic recovery, maintenance-window
  suppression, email, and generic webhooks are implemented
  (`docs/ALERT-NOTIFICATIONS.md`, `docs/SIGNED-WEBHOOKS.md`).
- Script library, scheduled tasks, patch management, remediation operations,
  file transfer, or remote desktop.
- A least-privilege agent service account.
- Scheduled production backup and timed operator rollback-drill evidence
  (encrypted backup/restore tooling and the automated PostgreSQL rehearsal ship
  in `deploy/backup/` and `docs/ROLLBACK.md`), or Authenticode signing
  (checksums, an SPDX SBOM, and signed build provenance are published; only
  certificate-based signing is
  missing). External audit-anchor publication ships (`docs/AUDIT-ANCHORING.md`)
  but the operator must configure and operate the destination.
- Tenant-scoped authorization, tenant-specific roles or retention, MFA,
  WebAuthn, OIDC/SAML, legal hold, or compliance evidence exports.

## Architecture at a glance

```text
Operator/API client -- JWT --> FastAPI server --> PostgreSQL
                              ^
                              |
Windows agent -- outbound HTTPS heartbeat/poll --+
                signed commands returned in heartbeat response
```

The application does not terminate TLS. The documented deployment topology
places Caddy in front of uvicorn and binds uvicorn to localhost. The repository
also includes `render.yaml` and `server/Dockerfile` for a Render web service
behind Render's TLS-terminating proxy with an external PostgreSQL database.
These are deployment procedures and scaffolding, not evidence that NodeLink is
production-ready. See [deployment readiness](docs/DEPLOYMENT-READINESS.md) and
the [TLS runbook](docs/DEPLOYMENT-TLS.md).

## Repository layout

```text
rmm-agent/
├── agent/       # Go endpoint agent and Windows service integration
├── server/      # FastAPI API and persistence layer
├── dashboard/   # Authenticated Next.js technician and administrator UI
├── installer/   # Inno Setup Windows installer
├── deploy/      # Reverse proxy, backup/restore, and soak-test tooling
├── contracts/   # Versioned schemas and shared Go/Python canonical vectors
├── docs/        # Architecture, security, roadmap, and operations documents
├── tools/       # License and release-target validation helpers
└── .github/     # CI, release automation, and contribution templates
```

The root `render.yaml` describes the optional Render backend service. The
dashboard can be deployed separately and must receive only the server-side
`NODELINK_API_BASE_URL`; the NodeLink API bearer token must never be exposed as
a public browser environment variable.

## Local development

See [server/README.md](server/README.md) to run the backend,
[agent/README.md](agent/README.md) to build and enroll an agent, and
[installer/README.md](installer/README.md) for the Windows installer. See
[dashboard/README.md](dashboard/README.md) to run the dashboard foundation.
The complete enrollment runbooks, API reference, security model, decisions,
known issues, and v0.1.2 candidate notes are under
[`docs/agent-enrollment/`](docs/agent-enrollment/).

Before any pilot, review the [threat model](docs/threat-model.md),
[security roadmap](docs/SECURITY-ROADMAP.md), and
[deployment-readiness checklist](docs/DEPLOYMENT-READINESS.md).

## Contributing

Development work is organized through phased GitHub milestones and actionable
issues. Security-sensitive changes require tests, and architecture/security
documentation must be updated in the same pull request as behavior changes.
See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

NodeLink RMM Community Edition is licensed under the GNU Affero General
Public License v3.0 only. See [LICENSE](LICENSE).

SPDX-License-Identifier: AGPL-3.0-only

Commercial licensing may be offered separately for organizations that need
to embed, redistribute, modify, or operate NodeLink under terms other than
the AGPL.

The NodeLink name, logos, product identity, and branding are not licensed
under the AGPL. See [TRADEMARKS.md](TRADEMARKS.md).
