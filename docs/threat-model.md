# NodeLink RMM — Threat Model & Security Design

This document describes the trust boundaries, the mechanisms protecting each, and
the known gaps to close before production use. It is deliberately honest about
what the Phase 1 scaffold does and does not yet do.

## Assets

1. **Endpoint control.** The ability to run commands on client machines is the
   crown jewel. An attacker who can dispatch commands owns every endpoint.
2. **Audit integrity.** For customers in regulated environments, the record of
   *what was done, when, by whom* must be trustworthy. A tamperable log is worse
   than no log because it invites false confidence.
3. **Telemetry / inventory.** Lower sensitivity, but leaks host and network
   detail useful to an attacker.

## Trust boundaries

```
   Operator ──(1)── Server ──(2)── Network ──(3)── Agent ──(4)── Endpoint OS
```

### (1) Operator → Server

**Status: IMPLEMENTED.** The management API is gated behind operator
authentication and role-based authorization:

- **AuthN.** `POST /auth/login` verifies an email + bcrypt-hashed password and
  returns a signed JWT. `get_current_operator` validates that token on every
  management request. Missing/invalid tokens return 401.
- **AuthZ.** Three roles (`readonly` < `operator` < `admin`). The management
  router requires `readonly` at minimum (nothing is anonymous); mutating routes
  require `operator`; operator management requires `admin`. Insufficient role
  returns 403. Arbitrary PowerShell/shell execution is additionally
  default-deny, including for admins, and requires an explicit global, site, or
  agent scope matching the target. Typed inventory is authorized separately.
- **Accountability.** The acting operator's email is recorded as the `actor` on
  each `command.dispatched` audit event. Allowed and denied authorization
  decisions are also audited before signing/queueing without payload values.
- **Bootstrap.** The first admin is created out-of-band via
  `scripts/create_admin.py` (the create-operator endpoint is admin-only, so it
  can't mint the first admin itself).

Login hardening: unknown-email and wrong-password both return an identical 401,
and a dummy hash verification runs on unknown emails to avoid a timing
side-channel that would reveal which accounts exist.

Two hardening layers on top of that:

- **Token revocation.** JWTs are stateless, so individual tokens cannot be
  recalled — instead each operator row carries a `token_generation` counter,
  every JWT records the generation it was minted under, and validation rejects
  any mismatch. `POST /auth/revoke-tokens` (self) or
  `POST /auth/operators/{id}/revoke-tokens` (admin) bumps the counter,
  instantly invalidating all outstanding tokens for that operator. Both are
  audited (`operator.tokens_revoked`).
- **Login rate-limiting.** Failed logins are counted per (client IP, email) in
  a sliding window; once it fills, `/auth/login` answers 429 with Retry-After,
  even for the correct password. A successful login clears the pair's counter.
  Keying on the pair slows online brute force without letting an attacker lock
  a victim out from a different address. The counters are in-process — behind
  multiple workers the effective limit multiplies by the worker count; move
  them to a shared store before scaling out.

**Dashboard telemetry read boundary.** The browser never receives the operator
bearer token; server-side dashboard code forwards it from an HTTP-only,
same-site cookie only after revalidating the operator. Endpoint inventory and
detail routes require at least the `readonly` role, and successful detail reads
are audited as `endpoint_detail.viewed`. The endpoint ID is an opaque lookup key,
not an authorization boundary: current roles are deployment-global and do not
provide tenant-scoped isolation. A readonly operator can therefore see host
identity, operational telemetry, and the latest logged-in username across the
deployment. The detail response excludes agent credentials, token hashes, and
raw inventory. History queries are constrained to 168 hours and 500 samples to
reduce accidental or abusive bulk extraction and resource use. Missing metrics
remain explicit so an absent value cannot be misread as a healthy zero.

**Alert mutation boundary.** Readonly operators may inspect alerts and their
scrubbed lifecycle history but cannot mutate them. Acknowledge, assign, comment,
and manual-resolve routes require `operator` or `admin`; the dashboard's server
handlers additionally reject cross-origin POSTs and never expose the operator
bearer token to client JavaScript. Every mutation locks the alert row, checks an
expected version, and deduplicates a bounded request ID before changing state.
Technician comments are limited to 2,000 characters and credential-shaped text
is scrubbed before append-only operational storage. The audit chain receives
only a digest and byte count for comments and assignee email, preventing
operator prose or addresses from entering tamper-evident audit detail.

**Script-library custody boundary.** Reusable source is sensitive endpoint-
control material even before execution. Readonly operators may inspect it,
operators may append drafts, and only admins may issue one final review or
terminal deprecation. Content is immutable and SHA-256-bound, mutations use
same-origin dashboard handlers, and source/free-form reasons never enter audit
detail or operational logs. Library roles do not grant the separate
default-deny execution scope. Remaining risks are privileged database-owner
tampering before external audit anchoring and a malicious approved script;
review is accountable evidence, not sandboxing or semantic safety analysis.
See [`SCRIPT-LIBRARY.md`](SCRIPT-LIBRARY.md).

### (2) Server ↔ Network (transport)

Agents connect **outbound only**. There is no inbound agent port to open at a
client site: the agent dials the server, never the reverse. The client accepts
both HTTP and HTTPS URLs today, so TLS is a deployment requirement rather than
an application-enforced invariant.

**Before production:** terminate TLS at the server (or a reverse proxy) with a
valid certificate — the supported pattern (Caddy in front of uvicorn bound to
localhost) is documented in `docs/DEPLOYMENT-TLS.md` with `deploy/Caddyfile`.
For high-assurance clients, optional `tls_spki_pins` adds leaf-SPKI SHA-256
matching after normal chain/hostname/time validation. Multiple pins provide
current+next overlap; mismatch fails closed. Stale/expired recovery requires a
valid certificate using a pinned key or out-of-band config change, never a TLS
verification bypass (`docs/CERTIFICATE-PINNING.md`).

### (3) Network → Agent (command authenticity)

This is the mechanism that lets the audit log mean something. Every command is
signed by the server's **Ed25519 private key**. The agent receives the matching
public key at enrollment and verifies the signature over a canonical encoding of
`{command_id, agent_id, kind, payload}` before executing anything. A command
that fails verification is refused and never run.

Consequences:

- A man-in-the-middle who breaks TLS still cannot forge a command without the
  signing key.
- A compromised *transport* cannot inject endpoint commands.
- The signature binds the command to a specific `agent_id`, so a valid command
  for one endpoint cannot be replayed against another.

**Replay within the same agent — now mitigated.** A captured, still-valid
command could in principle be re-presented to the same agent. The agent now
defends against this on two fronts:

- **Signed time window.** `command-v3` binds canonical `issued_at` and
  `expires_at` into the signature. The agent rejects malformed, expired,
  overlong, or implausibly future-dated windows.
- **Replay journal and result outbox.** The agent atomically persists command
  IDs, signed nonces, lifecycle state, and bounded pending results in
  `seen_commands.json`. Windows protects the file with DPAPI and a restricted
  DACL; other platforms use mode 0600. `reserved` is recorded before process
  start and may be safely released after a crash; `executing` is never replayed
  and recovers as an explicit unknown outcome; results are persisted before
  upload and retained until an idempotent server acknowledgement. A duplicate
  command ID re-reports the exact retained result without execution, while a
  duplicate nonce is reported as a refusal.

Refusal order in the agent is signature → time window → command-ID replay →
nonce replay → execute.

**Version downgrade — mitigated.** The signed `command-v3` bytes include
`envelope_version`. Agents advertise versions during enrollment and heartbeat;
the server withholds dispatch until `command-v3` is reported. Missing, unknown,
and legacy versions fail closed before signature verification. Python and Go
consume the same positive and negative vectors. Existing queued commands are
expired during migration because their legacy signatures do not cover the v2
contract.

**Key lifecycle.** Command-v3 binds a signing-key ID and the agent only trusts
the active/overlap public-key bundle delivered by the server. Rotation is an
operator-run workflow (`scripts/rotate_command_key.py`, `docs/KEY-ROTATION.md`):
a new key is staged as `overlap` so the fleet learns its public key before it
signs, promoted to `active` while the outgoing key steps down to `overlap` so
its in-flight commands still verify, and `retired` only once nothing it signed
is still in flight. Compromise skips the waits (generate + activate + retire
immediately, deliberately refusing the compromised key's in-flight commands),
and rollback re-activates the previous key while it remains `overlap`. Every
mutation is written atomically and appended to a rotation journal, and the full
lifecycle is rehearsed in tests.

### (4) Agent → Endpoint OS

The agent runs commands with the privileges of its own process. It can now be
installed as a Windows service (Gate 2), which by default runs as `LocalSystem` —
high privilege — so anyone who can dispatch a verified command has effective
admin on the endpoint, which is why boundary (1) matters so much. Running under a
least-privilege service account is still future work.

The server reduces this exposure by separating typed operations from arbitrary
scripts. Roles alone cannot dispatch `powershell` or `shell`; an admin must
grant the operator one matching global, site, or agent scope with a reason. The
typed operations `collect_inventory` and `scan_updates` (issue #51) are
read-only, bounded, and need only the operator role — `scan_updates` runs a
Windows Update *scan*, never an installation, and its normalized result is
bounded and carries no secrets. An agent that does not recognize a command kind
rejects it at signature/kind validation, so introducing a new typed operation is
fail-closed for a mixed-version fleet.
Scope changes and every allowed/denied authorization decision are audited, and
denial occurs before command construction, signing, or queueing. This is not a
replacement for approval workflows, expiring grants, or a least-privilege agent
service identity.

Issue #59 adds a narrower privileged-remediation boundary. File and registry
operations require `admin` (not merely the typed-operation operator role), an
active trusted agent, and advertised `file-transfer-v1` or
`registry-operations-v1` capability. The server validates fixed managed roots,
hives, views, types, byte bounds, digests, and explicit deletion before signing;
the agent repeats those checks and additionally rejects reparse points and
device/UNC/alternate-stream paths. Mutations capture endpoint-local rollback
state, and file replacement is atomic. Paths and file/registry contents are
excluded from permanent audit detail. Residual risks remain: LocalSystem can
still alter the allowed resources, downloaded content and authorized command
detail are sensitive, local rollback journals can be destroyed by an endpoint
administrator, and policy checks cannot make a vendor payload trustworthy.
Package provenance/signature policy, two-person approval, least-privilege
service identity, and remote immutable rollback custody remain future work.

Issue #60 adds a distinct disruptive power boundary. Restart, shutdown, and
cancellation require `admin` plus `power-operations-v1`; restart/shutdown also
require a current matching maintenance window, mandatory reason, bounded delay,
and explicit signed user-session policy. The endpoint rechecks no-user-session
claims and window end before invoking Windows, and a minimum delay permits
durable result storage before disconnect. Cancellation is maintenance-window
exempt because it removes disruption and is idempotent when nothing is pending.
Residual risks remain: a compromised administrator can attest false consent,
an already-compromised endpoint can falsify local user state/results, and
Windows may power off before result upload (the local outbox recovers after
boot). Two-person approval and independent endpoint-user confirmation remain
future defenses. See [`POWER-OPERATIONS.md`](POWER-OPERATIONS.md).

Issue #58 adds a bounded event log read boundary. `query_event_log` requires
`admin` plus `event-log-query-v1` and is restricted to a fixed channel allowlist
with a standard tier and an elevated tier (`Security`, Defender) that a query
must explicitly acknowledge and which is separately audited. Every query records
its minimum-necessary scope (channel, tier, time window, event cap, filter
presence) without event contents. The dominant risk is PHI exposure through
event message bodies; v1 mitigates this structurally by returning metadata only
— the agent parses the `<System>` element and never the rendered message,
`<EventData>`, or `<UserData>` — because regex redaction of unpredictable free
text is not a defensible PHI control. Residual risks: structured metadata
(account names, file paths) can be indirectly identifying, and a compromised
endpoint can falsify results. Message-body retrieval is deferred behind opt-in
attestation, short retention, and legal/BAA review. See
[`EVENT-LOG-ACCESS.md`](EVENT-LOG-ACCESS.md).

Issue #57 adds a Windows service and process management boundary. `list_services`
and `list_processes` are operator-level, read-only discovery operations; `control_service`
and `terminate_process` require `admin` plus `service-process-v1`. Service control
and process termination require explicit UI confirmation and a 10–512 printable-byte
reason. Both server and agent enforce identical protected target denylists (agent's
own service/process, security stack, critical Windows OS services/processes, PIDs 0 and 4).
`terminate_process` additionally supports optional expected image name validation to prevent
accidental termination if a PID was recycled. Operational reasons are stored only as SHA-256
digests in audit events. See [`SERVICE-PROCESS-MANAGEMENT.md`](SERVICE-PROCESS-MANAGEMENT.md).

Issue #52 adds a patch approval boundary in front of `install_updates`. A scoped,
versioned policy (most-specific wins) approves, denies, or defers updates by
classification, severity, or KB; the server evaluates the selection against the
endpoint's scanned inventory before signing, narrowing `install_all` to the
approved subset and refusing an explicit denied/deferred selection. The default
action is deny (fail closed), and an optional maintenance-window requirement
prevents out-of-window patching. The gate is server-side and opt-in, so it does
not weaken any existing trust boundary; residual risks are that policies act on
self-reported scan inventory (a compromised endpoint could misreport what is
missing) and that a stale scan can misgate a selection — operators re-scan before
installing, and every decision is audited via `patch_install.gated`. See
[`PATCH-APPROVAL.md`](PATCH-APPROVAL.md).

Issue #53 adds a post-install reboot boundary. A reboot is only injected as
signed evidence when the approval gate allows the install and the agent
advertises `patch-reboot-v1`; the default policy is `never`, and consent wins —
even a `forced` reboot defers while a signed-in user is present unless the policy
explicitly clears `requires_no_user`. The reboot reuses the power-operation
mechanism, so it inherits the signed-window binding and the durable
result-before-restart guarantee (a reboot mid-install is reported as an unknown
outcome, never re-run). Scheduled installs are gated identically, closing the
prior gap where the scheduler dispatched commands without the approval/window
gate. Residual risk: reboot consent relies on the endpoint's self-reported
user-session evidence, the same trust assumption as power operations.

Issue #55 adds a package-management boundary. Discovery (`scan_packages`) is
read-only and operator-level; install/upgrade (`install_packages`) is
administrator-only and installs an explicit, bounded set of package ids — never a
script. Winget is the default and needs no configuration. Chocolatey introduces a
third-party-source trust boundary and is contained two ways: it is opt-in per
endpoint (the agent advertises `chocolatey-provider-v1` only when the operator
enabled it, so the server fails closed for every other endpoint), and a
Chocolatey install must carry signed `source`, `source_digest`, and `signer`
evidence that the server records (`package_install.gated`, storing only counts
and the source digest) and the agent re-validates at the endpoint, optionally
against a config source allowlist. Both kinds require `package-management-v1`, so
a mixed-version fleet fails closed. Residual risks: the provider CLIs
(`winget.exe`/`choco.exe`) and their configured sources are trusted to resolve
and verify package contents — NodeLink does not itself hash-verify the installed
bytes — and a compromised endpoint can misreport discovery results, the same
self-report assumption as inventory. See [`PACKAGE-MANAGEMENT.md`](PACKAGE-MANAGEMENT.md).

Issue #56 adds a software-deployment boundary. `deploy_software` downloads an
MSI/EXE from an operator-supplied HTTPS source and runs it — arbitrary vendor
code on the endpoint, so it is administrator-only and capability-gated
(`software-deployment-v1`). Unlike the package providers, integrity here does not
rely on a third-party CLI: the source URL must be HTTPS, the downloader refuses a
redirect that leaves HTTPS, and a **mandatory SHA-256** of the exact bytes is
verified after download — a mismatch fails closed before the installer runs. An
optional pinned Authenticode `signer_thumbprint` adds signer verification. The
download is bounded (≤1 GiB temp file, always removed) so a hostile source cannot
exhaust disk, and the run is bounded by a signed timeout. Arguments are printable
argv tokens passed without a shell, so there is no quoting/injection surface.
Audit stores only the artifact digest, the source `url_sha256` (never the URL
prose), and the dispatch bounds. Residual risks: the operator is trusted to
supply a correct digest for the intended artifact (a wrong-but-consistent
digest/URL pair deploys whatever the operator pointed at), an EXE installer's own
behavior and any network it performs are outside NodeLink's control, and a
compromised endpoint can misreport the result. Reboot reuses the #53 mechanism
and its self-reported user-session assumption. See
[`SOFTWARE-DEPLOYMENT.md`](SOFTWARE-DEPLOYMENT.md).

Typed script parameters reduce injection and disclosure risk but do not make an
approved script intrinsically safe. Definitions are immutable with the reviewed
source. Values are validated without coercion, then the whole resolved document
is AES-256-GCM encrypted with version/set IDs as authenticated context; the
idempotency fingerprint is keyed so low-entropy secrets cannot be tested from a
plain database digest. Secret defaults are forbidden, browser/audit responses
contain key names only, and missing keys/configuration fail closed. Shell values
are bound to generated variables with interpreter-specific literal quoting,
never substituted into source. Exact secret values are redacted from future
captured output, but scripts can transform/encode a secret, so operators must
still treat execution output as sensitive. Parameter-aware dispatch remains
inactive until #49 defines a negotiated transport that avoids plaintext secret
storage in `commands.payload`.

Each Windows command is created suspended, assigned to its own kill-on-close
Job Object, then resumed. Timeout, SCM stop, agent termination, and ordinary
shell exit kill the entire descendant tree, preventing a script from escaping
limits by starting deferred background work. The bounded result is durably
recorded before network reporting; server conflict checks prevent a retry from
rewriting the original outcome.

- Agent identity is a long-lived bearer token issued at enrollment. The server
  stores only its SHA-256 hash. On the endpoint the token lives in
  `identity.json` inside a versioned envelope: DPAPI-encrypted (user scope,
  under the enrolling account — LocalSystem for the installed service) with a
  protected SYSTEM+Administrators-only DACL on Windows; protection `none` with
  mode 0600 elsewhere. Legacy plaintext files are migrated atomically on first
  load, and protection failures refuse to run rather than fall back to
  plaintext. Server-side, operators can quarantine (reversible, operator role)
  or revoke (terminal, admin role) an agent; revoked tokens fail
  authentication with the same response as unknown tokens.
- Enrollment tokens are one-time (configurable `max_uses`), can expire, and can
  be revoked. They are shown in plaintext only once, at creation.

### (5) Operator → Agent (interactive shell, issue #61)

The interactive shell (`docs/SHELL-SESSIONS.md`) introduces a new live
operator→agent channel and therefore a new trust boundary. Because a shell is at
least as powerful as arbitrary script execution, it inherits boundary (4)'s
concern: anyone who can open one has effective admin on the endpoint. The
fail-closed controls apply in this order at open time: the operator
must hold role ≥ `operator` **and** the explicit arbitrary-script scope; the agent
must be `trust_state == active`; the agent must advertise the `shell-session-v2`
capability (an agent that does not is refused as unsupported, not silently
degraded); and at most one live session is admitted per agent. Every refusal is
audited (`shell_session.denied`) before the response, so denials are as
accountable as grants.

The session is bounded by design: a server-authoritative idle deadline and
absolute lifetime cap (a stalled agent or operator cannot hold the channel open),
and a per-session output-byte cap enforced fail-closed. Streamed input and output
are classified sensitive exactly like command output — they are never written to
an audit detail, a log line, or an error message; only lifecycle metadata is
recorded. The transport is capability-negotiated and additive, so a mixed-version
fleet stays safe: older agents simply never offer the v2 capability and the
feature remains unavailable for them. The relay enforces exact sequences,
idempotent identical retries, acknowledgement bounds, frame/window/output caps,
and owner-bound access. An active session fails closed if volatile relay state is
lost during server restart.

## Audit log: tamper-evidence

Every meaningful action appends an `AuditEvent` to a **hash chain**: each event
stores `prev_hash` (the previous event's hash) and `event_hash` (the SHA-256 of
this event's canonical content, including `prev_hash`). Because each event
commits to its predecessor, altering or deleting any event breaks the chain from
that point forward.

`GET /api/v1/audit/verify` walks the chain and returns the first broken event, if
any. This is demonstrated by a test that mutates one field of one row and
confirms detection.

### Detail redaction: no secret enters the chain (issue #115)

The audit chain is durable and externally published, so a secret written into
an event's `detail` would be *permanently* preserved and hard to expunge.
`audit.record` therefore runs every event's `detail` through one central,
deterministic boundary (`app/core/redaction.py`) **before** a sequence is
allocated or the value is hashed and stored. Each action has an exact field
schema. Unknown actions, field drift, malformed/nested objects, non-canonical
numbers, and oversized values fail closed. PEM/JWT/credential-labelled values
are redacted, while arbitrary operator/agent prose is stored only as SHA-256
plus byte count.

Registered public evidence—Merkle roots, event hashes, replay nonces, target
IDs, policy decisions, timestamps, and counts—remains readable because
accountability and independent verification depend on it. The stored safe form
is the only representation ever hashed, so chain and anchor verification remain
reproducible. The reviewed producer inventory and exact stored fields are in
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md); the cross-surface credential review is in
[`REDACTION-AUDIT.md`](REDACTION-AUDIT.md).

### External verifiability: Merkle anchoring

The local hash chain proves internal consistency but not *when* an event
existed — a sufficiently privileged attacker could rebuild the entire chain
consistently and the chain check alone would pass. The anchoring layer closes
this:

- `POST /api/v1/audit/anchors` (operator+) computes a **Merkle root** over the
  `event_hash` values of every event in the chain (in ascending `seq` order;
  the legacy prefix's `seq` was frozen from the historical `(ts, id)` order by
  migration 0007) and stores it as an `AuditAnchor` covering that prefix. The
  act of anchoring is itself audited (`audit.anchored`).
- `GET /api/v1/audit/anchors/{id}/verify` recomputes the root over the covered
  prefix and compares — any alteration, removal, or reordering of covered
  events is detected, **including a fully consistent chain rebuild** (this is
  demonstrated by a test that rebuilds the chain and shows the chain check
  passing while the anchor check fails).
- The Merkle construction is documented in `app/core/anchor.py` so an external
  verifier can reimplement it: leaves are hex-decoded `event_hash` values;
  levels pair left-to-right with SHA-256(left‖right); an unpaired node is
  carried up unchanged; a single leaf is its own root.

**The root must leave the building.** An anchor row in the same database
proves nothing against an attacker who owns that database — they can rebuild
anchors too. A scheduled publisher (`app/core/anchor_publish.py`, issue #76)
carries each anchor's Merkle root to an external immutable destination and
records a tamper-evident receipt. Two backends ship: an S3-compatible bucket
with Object Lock (COMPLIANCE mode — un-deletable until its retention date, even
by the account root) and an append-only filesystem/WORM directory. Publication
is idempotent (content-addressed keys), retried on outage, and lag past a
threshold alerts. Credentials never enter a receipt. A standalone verifier
(`scripts/verify_anchor_receipt.py`) recomputes the root from read-only event
hashes and the artifact downloaded from the destination, so history can be
validated without trusting — or writing to — the NodeLink database. Publication
is opt-in (the operator chooses and operates the destination) and logs a loud
warning in production when unconfigured. See `docs/AUDIT-ANCHORING.md`.

## Summary of gaps to close before production

| # | Gap | Severity | Status |
|---|-----|----------|--------|
| 1 | Management API unauthenticated | Critical | **Closed** — operator authN + role-based authZ |
| 2 | No token revocation / login rate-limit | Medium | **Closed** — per-operator `token_generation` bump revokes all outstanding JWTs (self + admin endpoints, audited); sliding-window 429 throttle on `/auth/login` per (IP, email). Limiter is per-process — use a shared store when running multiple workers |
| 3 | Command expiry/version/nonce are not signed | Critical | **Closed** — `command-v3` binds schema version, issued-at, expiry, nonce, and signing-key ID with shared Go/Python verification; staged key rotation/compromise/rollback are operator-run and rehearsed (`scripts/rotate_command_key.py`, `docs/KEY-ROTATION.md`) |
| 4 | TLS not enforced by scaffold | High | **Mostly closed** — ENVIRONMENT=production fails startup on unsafe config; proxy trust is explicit; deployment path is documented; optional agent SPKI pinning retains normal PKI, supports overlap, and fails closed (`docs/CERTIFICATE-PINNING.md`). Certificate lifecycle monitoring and deployment evidence remain |
| 5 | Audit chain not externally anchored | Medium | **Mostly closed** — a scheduled publisher writes each anchor's Merkle root to an external immutable destination (S3 Object Lock or a WORM filesystem) with tamper-evident receipts, idempotent retry, lag alerting, and a clean-room verifier. Publication is opt-in (loud when unconfigured); the operator still chooses and operates the destination |
| 6 | Agent runs commands at its own privilege | By design | Partial — installable service (Gate 2) runs as `LocalSystem`; least-privilege service account still open |
| 7 | Agent was foreground-only (no unattended operation) | High | **Closed (Gate 2)** — installable Windows service: auto-start at boot, SCM crash-recovery, rotated file logging, and a network-resilient check-in loop (backoff + jitter) |
| 8 | No agent revocation/quarantine or DPAPI credential protection | Critical | **Mostly closed** — explicit active/quarantined/revoked trust states with reasoned, audited operator transitions; revoked credentials fail auth without an oracle and outstanding work is expired; quarantined agents get bare acks only; identity is DPAPI-protected with a restricted DACL on Windows (envelope-versioned, atomic plaintext migration, no plaintext fallback). Windows service/installer lifecycle automation for these paths remains with issue #23 |
| 9 | Command stdout/stderr and queue policy are unbounded | High | **Closed** — stdout/stderr are capped (256 KiB each, 384 KiB combined, excess counted not buffered) with deterministic UTF-8-safe truncation recorded in command and audit data; dispatch payloads are capped at 64 KiB; per-agent outstanding-command admission (configurable, refuses at dispatch) and a per-heartbeat FIFO batch cap bound queue depth, with the agent executing one command at a time |
| 10 | Audit ordering is not monotonic and anchors remain local | High | **Closed** — every event carries a unique monotonic seq assigned under a serialized append (advisory lock + unique constraint) and bound into its hash; verification/anchoring walk seq order and detect gaps/reorders; anchors are published to external immutable storage with receipts and clean-room verification (`docs/AUDIT-ANCHORING.md`) |
| 11 | No production migrations, automated restore, or rollback rehearsal | High | **Mostly closed** — Alembic startup guard; encrypted backup/isolated restore; and a fail-closed planner requiring rollout pause, named compatible components/schema, matching backup, and explicit data-loss approval. PostgreSQL CI rehearses N→bad N+1→N and verifies operators, agents, commands, audit chain, and anchors (`docs/ROLLBACK.md`). Production schedule evidence and a timed operator drill remain |
| 12 | Windows artifacts are unsigned and release evidence lacks SBOM/provenance | High | Partial — releases publish an SPDX SBOM (Go + Python), signed SLSA build-provenance attestations, and checksums for every artifact; Authenticode signing remains open (needs a paid certificate) |
| 13 | Client/site records are not authorization tenants | High | Open — roles and management access are global |
