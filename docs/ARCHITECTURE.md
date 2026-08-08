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

The current repository is an API, agent, and dashboard-foundation scaffold, not
a complete RMM. The dashboard requires an authenticated operator; client/site
navigation is live and read-only, while the overview remains fixture-backed.
Monitoring policy inventory and revision detail are also live and read-only;
the agent does not execute those checks yet.
There is no production
endpoint console, patch engine, live remote shell, remote desktop, compliance
exporter, or tenant-scoped authorization. Production and regulated endpoint use remain outside the
supported boundary until the deployment-safety gates in
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
3. The heartbeat advertises durable pending-result notices and the response
   carries queued or lease-expired dispatched commands.
4. The agent executes accepted commands sequentially, protects the bounded
   result in its local journal, and retries
   `POST /api/v1/commands/{id}/result` until idempotently acknowledged.

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
- Global `readonly`, `operator`, and `admin` roles. Arbitrary script execution
  is a separate default-deny permission with one admin-granted `global`, `site`,
  or `agent` scope; admin does not bypass it.
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
`collect_inventory` is a typed operation authorized by the operator role.
`powershell` and `shell` are arbitrary-script escape hatches and require a
separate scope matching the target. Authorization is evaluated and audited
before an envelope is created, signed, or queued. See
[`SCRIPT-AUTHORIZATION.md`](SCRIPT-AUTHORIZATION.md).

### 3.3 Product plane

The product plane provides the technician and customer experience. A Next.js
dashboard foundation now exists in `dashboard/`: it has a responsive fixture
overview, runtime configuration validation, a server-only NodeLink API client,
a backend health route, and a same-origin login/logout flow. It stores the API
JWT only in an HTTP-only, same-site cookie, revalidates the authenticated
operator for each dashboard request, and displays bounded client/site
navigation, endpoint inventory, and endpoint telemetry detail from authorized
APIs with redacted audit evidence. Endpoint list rows expose only the latest
heartbeat. Endpoint detail adds a bounded chronological heartbeat history but
never returns raw inventory snapshots, token hashes, or agent credentials.

Administrator-only operator management is available at `/operators`. The page
lists the unpaginated `OperatorOut` register, creates administrators
(`admin`) and technicians (`operator`) through one shared role-locked form,
shows every role's script state as explicit default deny or one global/site/agent
grant, and supports compose-then-confirm permission grant/revoke plus confirmed
session revocation, global-role changes, and disable/re-enable. Role and account
state changes require a 3-to-500-character audit reason, invalidate existing
sessions, and cannot remove or disable the final active administrator. Changing
an operator to `readonly` atomically revokes any script grant. Browser code
calls only same-origin dashboard handlers:
`GET/POST /api/operators`,
`PUT /api/operators/{id}/script-permission`,
`POST /api/operators/{id}/script-permission/revoke`, and
`POST /api/operators/{id}/revoke-tokens`,
`PUT /api/operators/{id}/role`, and
`PUT /api/operators/{id}/disabled`. Those handlers revalidate the
HTTP-only dashboard session, require `admin`, allowlist response fields, and
forward the bearer token server-side to the corresponding `/api/v1/auth/*`
routes. The FastAPI role check remains the authorization boundary. Permission
reasons use the API's 3-to-500-character bound and are recorded by the server's
audit events. Operator creation is audited with a digest-only email and never
records the submitted password; the dashboard never logs or returns it.

First-run enrollment setup is available at `/enrollment/setup` for `operator`
and `admin` roles. It creates a client and then a site through same-origin
`POST /api/clients` and `POST /api/sites` handlers, with the bearer token
forwarded only by server code. Client names are unique after trimming and
case-folding; site names use the same rule within their client. Both creations
are audited with digest-only names. Empty enrollment states direct authorized
operators to this setup before token creation, then carry the new site ID only
as a non-secret preselection parameter to the token form.

Endpoint telemetry detail accepts a 1-to-168-hour history window and a 10-to-500
sample limit. The latest heartbeat is fetched independently of that window and
is classified as current, stale, or unavailable; stale means older than three
configured heartbeat intervals with a five-minute minimum. Nullable values
represent missing or unsupported metrics and are not converted to zero. The
dashboard labels timestamps in UTC and gives charts accessible text and tabular
alternatives. The API records `endpoint_detail.viewed` with the actor, endpoint,
bounded query values, and result count. It stores no new state, performs no
automatic retry, and requires no database migration, so rollback is limited to
the server and dashboard deployment.

The dashboard also has a per-endpoint command console at
`/endpoints/{id}/commands` with a command detail record at
`/endpoints/{id}/commands/{commandId}`. Dispatch is a two-step
compose-then-confirm flow available only to `operator`/`admin` roles and only
for endpoints in the `active` trust state; `readonly` operators see history and
results with an explicit read-only notice, and the server enforces the same
rules regardless of what the UI shows. Operators without a matching explicit
script scope see only typed inventory dispatch; the endpoint-detail API returns
the target-specific `script_execution_allowed` capability. Dispatch input is validated in the
browser and again in a same-origin Next.js route handler (supported kinds only,
script required for `powershell`/`shell` and refused for `collect_inventory`,
56 KiB script bound under the 60 KiB signed-payload cap, 1s-24h TTL) before
being forwarded to `POST /agents/{id}/commands`, whose admission, trust, and
envelope-negotiation refusals are surfaced to the operator as distinct
messages. Cancellation after dispatch is deliberately unsupported — the agent
side has no cancel channel — so the UI states that unpicked work dies at its
signed expiry and shows the queue admission meter instead.

Two operator read APIs back these views, separate from the agent-facing
`CommandOut` delivery contract so dashboard needs never grow the signed
envelope: `GET /agents/{id}/commands` (paginated history, newest first, page
size 1-100, with outstanding-queue counts) and
`GET /agents/{id}/commands/{command_id}` (full record: payload, envelope
version, schema version, nonce, signing key id, signature, lifecycle
timestamps, exit code, and the bounded stdout/stderr with truncation flags and
true total byte counts). Both report an *effective* status: stored
queued/dispatched work past `expires_at` is returned as `expired` without
mutating the row, which the next heartbeat sweep persists. Because captured
output can contain sensitive endpoint data, reading a command detail is
audited as `command_detail.viewed` with the actor and command id. Neither
route stores new state and no schema change was required, so rollback is
limited to the server and dashboard deployment. In-flight views poll by
re-fetching bounded server data; output remains buffered, never streamed.

### Audit timeline and verification views

`/audit` presents the audit chain to a technician: a sequence-ordered timeline
with event-type, actor, agent, and UTC date filters; a per-event view of the
sanitized detail that was hashed; and an anchor view carrying local anchor
verification, external publication lag, and per-receipt tamper checks. Chain
verification and publication status render as banners above the register, and a
failed verification is announced as an alert rather than a status.

Three properties are deliberate. First, filter options come from
`GET /audit/event-types`, which is the redaction registry itself, so the filter
list cannot drift from the actions the chain can contain. Second, a verification
that could not be performed renders as *unknown*, never as verified — including
when external publication is disabled, because an unpublished anchor does not
constrain an attacker holding the database. Third, pagination is pinned to a
sequence ceiling (`before_seq`, echoed by the list response and carried by the
pager): the chain only appends, so newest-first offset pagination would shift
rows onto later pages and show one twice.

That last property is not only about concurrency. Reading these views is itself
audited (`audit_timeline.viewed`, `audit_event.viewed`) — who read the evidence
is evidence — which makes the register grow as it is read and would otherwise
duplicate a row on *every* page turn. Free-text filter values are recorded as
booleans and an unregistered event-type filter is collapsed to `unregistered`,
so a query string cannot write operator prose into the tamper-evident chain.
Both routes are read-only and required no schema change, so rollback is limited
to the server and dashboard deployment.

Milestone 1 adds the remaining live audit workflows, inventory, monitoring,
alerts, notifications, script library, and recurring tasks. Later phases add
patching, remediation, technician-to-end-user chat (planned for Milestone 2:
the agent surfaces a chat window on the endpoint so the machine's user can
talk to the technician from their computer, carried over the same planned live
transport as the interactive shell, with endpoint-side session
initiation/acceptance, per-message participant identity, audited session
lifecycle, bounded retained transcripts, and no remote-control capability on
the chat channel), evidence workflows, and ecosystem integrations.

### Versioned script custody

The Milestone 1 script library is implemented as a stable
`script_library_items` identity, append-only `script_versions`, and one optional
final `script_version_reviews` row per version. Source is canonicalized and
bound to a SHA-256 digest; updates and deletion do not exist. Operators append
drafts, admins issue final reviews and terminal deprecation, and readonly users
inspect audited metadata/source. This storage authority is deliberately
separate from the default-deny endpoint execution authority. Revision `0021`
is additive and the full API, state, limit, compatibility, and recovery
contract is in [`SCRIPT-LIBRARY.md`](SCRIPT-LIBRARY.md).

Revision `0022` extends each immutable `script_versions` row with ordered
`script_parameter_definitions` (`string`, `number`, `boolean`, `choice`, or
`secret`) and adds expiring `script_parameter_value_sets`. The latter contains
one AES-256-GCM encrypted canonical JSON document, an HMAC-SHA256 fingerprint,
safe key-name lists, creator/request evidence, and expiry; plaintext values have
no read route. Definition changes require a new version/review. Only operators
may prepare values, and only for an approved, non-deprecated exact version.
Missing encryption configuration, invalid type/bound/choice input, unknown keys,
and expired state fail closed. The dashboard receives only allowlisted metadata.

PowerShell and POSIX-shell bind values to generated `NL_PARAM_<Key>` variables
with single-quote escaping rather than source token substitution. Parallel
Python and Go test vectors cover quoting and secret redaction. The Go execution
helper is not reachable from legacy signed command schema v1: recurring task
dispatch (#49) must negotiate a parameter-aware contract and transport secrets
without writing plaintext into the existing `commands.payload`. See
[`SCRIPT-LIBRARY.md`](SCRIPT-LIBRARY.md) for limits, compatibility, and recovery.

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

Revision `0010` adds nullable operator script scope and scope-ID columns. Null
means default deny; migration does not grandfather any existing operator or
admin.

Revision `0013` adds database-enforced normalized-name uniqueness for clients
and for sites within a client. It preflights existing data and refuses to
upgrade when case/whitespace-equivalent duplicates require an operator decision.

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

`AgentInventorySnapshot` stores one validated row per `(agent, section)`,
appended only when that section's content hash changes, so the table is
simultaneously current state and change history. Sections carry a status
(`ok`, `partial`, `unavailable`, `unsupported`) and both a `collected_at` and a
`received_at`, so an absent field is distinguishable from an unread one and a
queued or clock-skewed endpoint is visible. Hardware (#35), installed software
(#36), Defender, platform security (BitLocker/Secure Boot/TPM), and local
Administrators membership (#39) are implemented as `section` values; adding a
class is a new section rather than a schema change. Operator-facing history and
diffs are #40. The legacy free-form `Agent.inventory` column is no longer
written and is dropped in a later revision.

`MonitoringPolicy` is a stable named identity at `global`, `client`, `site`, or
`agent` scope. Its content lives in append-only `MonitoringPolicyRevision`
rows; the highest version is current. Check definitions are bounded,
Pydantic-validated JSON with typed per-check parameters. Effective policy is
resolved for one agent from global through client, site, and agent scope, with
the most-specific definition winning for each check key; an `enabled=false`
definition removes an inherited key. `MaintenanceWindow` records a validated
scoped time range, while `CheckResult` is the append-only result contract with
newest-N retention per `(agent, check_key)`. Issue #41 defines these models,
operator APIs, resolution, retention, and the read-only dashboard. Issue #42
adds revision-pinned heartbeat assignments, durable agent evaluation/ingestion,
and server-owned offline evaluation without changing the result table. Alert
state in `Alert` is deduplicated by policy/endpoint/check in #43, with
check-result-keyed observations, automatic recovery/reopen, policy cleanup,
and maintenance-window suppression metadata. Issue #44 adds role-gated,
version-checked, idempotent technician actions and append-only `AlertEvent`
history. Automatic and manual transitions serialize on the alert row; operator
comments are scrubbed before operational storage and digest-only in the audit
chain.

### 4.2 API surface

All application routes except `/healthz` are under `/api/v1`.

| Method | Path | Current purpose | Authorization |
|---|---|---|---|
| POST | `/auth/login` | Exchange credentials for JWT | Public, throttled in-process |
| POST | `/auth/operators` | Create operator | Admin |
| GET | `/auth/operators` | List operators and script scopes | Admin |
| PUT | `/auth/operators/{id}/role` | Change global role and revoke sessions | Admin |
| PUT | `/auth/operators/{id}/disabled` | Disable or re-enable identity and revoke sessions | Admin |
| PUT | `/auth/operators/{id}/script-permission` | Grant/replace one script scope | Admin |
| POST | `/auth/operators/{id}/script-permission/revoke` | Revoke script scope | Admin |
| GET | `/auth/me` | Current operator | Readonly+ |
| POST | `/auth/revoke-tokens` | Revoke caller sessions | Readonly+ |
| POST | `/auth/operators/{id}/revoke-tokens` | Revoke operator sessions | Admin |
| POST | `/enroll` | Enroll with site token | Enrollment token |
| POST | `/heartbeat` | Store telemetry, advertise inventory hashes, poll commands | Agent token |
| POST | `/agents/me/inventory` | Submit requested inventory sections | Agent token |
| POST | `/agents/me/monitoring/results` | Submit revision-pinned idempotent check results | Agent token |
| POST | `/commands/{id}/result` | Submit buffered result | Agent token |
| POST/GET | `/clients` | Create/list clients | Operator / Readonly |
| POST | `/sites` | Create site | Operator |
| POST | `/enrollment-tokens` | Create token | Operator |
| GET | `/agents`, `/agents/{id}` | Legacy list/get endpoint | Readonly |
| GET | `/endpoints` | Filtered, paginated endpoint inventory | Readonly |
| GET | `/endpoints/{id}` | Endpoint identity, current telemetry, and bounded history | Readonly |
| POST | `/agents/{id}/quarantine` | Suspend agent trust (reversible) | Operator |
| POST | `/agents/{id}/restore` | Return quarantined agent to active | Operator |
| POST | `/agents/{id}/revoke` | Permanently revoke agent credentials | Admin |
| GET | `/signing-keys` | View redacted active/overlap/retired key state | Readonly |
| POST/GET | `/agents/{id}/commands` | Dispatch/list commands | Operator / Readonly |
| GET | `/audit/events` | Sequence-ordered, filtered, snapshot-paginated timeline | Readonly |
| GET | `/audit/events/{id}` | One event with its sanitized detail | Readonly |
| GET | `/audit/event-types` | Registered audit actions (filter source) | Readonly |
| GET | `/audit/verify` | Verify hash chain | Readonly |
| POST/GET | `/audit/anchors` | Create/list local anchors | Operator / Readonly |
| GET | `/audit/anchors/{id}/verify` | Verify local anchor | Readonly |
| GET | `/audit/anchors/{id}/receipt` | External publication receipt + tamper check | Readonly |
| GET | `/audit/publication-status` | External anchor publication lag/health | Readonly |
| POST/GET | `/monitoring/policies` | Create/list versioned monitoring policies | Operator / Readonly |
| GET/PUT/DELETE | `/monitoring/policies/{id}` | Read, append a revision, or delete a policy | Readonly / Operator |
| GET | `/monitoring/policies/{id}/revisions` | Append-only policy history | Readonly |
| GET | `/agents/{id}/monitoring/effective-policy` | Resolve inherited checks for one agent | Readonly |
| POST/GET | `/monitoring/maintenance-windows` | Create/list scoped maintenance windows | Operator / Readonly |
| DELETE | `/monitoring/maintenance-windows/{id}` | Delete a maintenance window | Operator |
| GET | `/agents/{id}/monitoring/results` | Read bounded check-result history | Readonly |
| GET | `/monitoring/alerts` | Read bounded/filterable current alert state | Readonly |
| GET | `/monitoring/alerts/{id}` | Read alert state, lifecycle history, and retained observations | Readonly |
| GET | `/monitoring/alert-assignees` | List active alert assignment targets | Operator |
| POST | `/monitoring/alerts/{id}/acknowledge` | Acknowledge an open alert | Operator |
| POST | `/monitoring/alerts/{id}/assign` | Assign or unassign an alert | Operator |
| POST | `/monitoring/alerts/{id}/comments` | Append a scrubbed technician comment | Operator |
| POST | `/monitoring/alerts/{id}/resolve` | Manually resolve an active alert | Operator |
| GET | `/monitoring/email-alerts/status` | Safe provider configuration and delivery counts | Readonly |
| GET | `/monitoring/alerts/{id}/email-deliveries` | Masked recipient delivery/attempt history | Readonly |
| POST | `/monitoring/email-deliveries/{id}/retry` | Idempotently retry a failed email | Operator |

Enrollment-token list/detail/revoke APIs, an enrollment dashboard summary, a
filtered enrollment audit-event list, and the general audit timeline,
event-detail, and anchor/receipt verification views are implemented. Client/site first-run
creation and operator listing, creation, global-role change, disable/re-enable,
script-permission administration, and session revocation are implemented in the
dashboard. Deleting identities and password lifecycle operations remain absent.
Monitoring policy models, read APIs, the initial six checks, result ingestion,
deduplicated automatic alert state, technician alert lifecycle actions, and
durable email notification delivery are implemented; generic webhooks, general
task scheduling, patching, and
evidence export remain absent. Telemetry history is
available only as a bounded read-only endpoint-detail query, not as a general
analytics API.

## 5. Agent

The Go agent shares one runtime between foreground mode and the Windows service.
Windows service support includes automatic start, SCM recovery actions, rotating
logs, network retry with jitter, and graceful cancellation of a running child
process. Go build and unit tests run on Windows CI, but Windows service and
installer lifecycle behavior is exercised in Windows CI: a lifecycle script drives install/start/stop/restart/refuse-double-install/uninstall against the SCM, and a silent installer install+uninstall smoke test builds and runs the Inno Setup package.

The current Windows telemetry collector shells out to PowerShell/CIM once per
heartbeat for CPU, memory, system drive, uptime, user, and OS version.
The heartbeat response also carries the revision-pinned effective monitoring
policy. The agent evaluates due CPU, memory, disk, service, and pending-reboot
checks, persists cadence/hysteresis state plus a bounded result outbox, and
uploads idempotently. The server heartbeat sweeper evaluates offline checks
from `last_seen_at`. Missing, stale, unsupported, and probe-budget states become
explicit `unknown` results rather than passing samples. The complete contract,
rollout order, and bounds are documented in `docs/MONITORING.md`.

Hardware inventory is collected separately and once per process, not per beat:
manufacturer/model/serial/BIOS, CPU, memory totals and modules, disks and
volumes, and network adapters. Each section is collected independently under
its own timeout, so a wedged CIM provider degrades one section to `unavailable`
rather than voiding the snapshot or stalling check-in. Installed software,
Windows Defender status is collected read-only through `Get-MpComputerStatus`,
plus the `root/SecurityCenter2` antivirus registry where it exists. Nothing in
this path changes configuration.

The section carries a `provider_state` field — `active`, `passive`,
`third_party`, `disabled`, or `unknown` — deliberately separate from the
section status. The status answers "could we collect this?"; `provider_state`
answers "what is this machine's posture?". They are independent, and
conflating them would be actively harmful: Defender reports
`AntivirusEnabled=false` while running in passive mode, which is exactly what a
correctly configured machine with a third-party antivirus looks like. Reading
that as "Defender disabled" would raise an alarm on every such endpoint and
bury the genuinely unprotected ones in the noise. Running mode is therefore
evaluated before the enabled flag.

Signature age is computed on the endpoint and stored alongside the update
timestamp rather than derived on read. It is the value staleness is judged on,
and because it is a local subtraction, an endpoint with a wrong clock reports a
misleading timestamp but a still-correct age. A signature timestamp in the
future yields no age rather than a negative one.

Server SKUs have no Security Center. That case is reported as `partial` with
Defender's own facts intact, so an empty third-party product list is never
mistaken for "no antivirus installed".

BitLocker, Secure Boot, and TPM are collected as three independent sections
rather than one, so a BitLocker read denied for lack of elevation cannot void
an otherwise readable Secure Boot or TPM state.

**No BitLocker recovery key is ever collected.** The volume query names its
properties explicitly, so `KeyProtector` — which carries recovery passwords —
is never read and never enters the agent process. The schema is the backstop:
no field can hold key material and `extra="forbid"` rejects any attempt to send
it, so there is no path by which a key could be collected and then dropped. A
test asserts the collector's own source never references key material.

Section status gains `permission_denied`, distinct from `unavailable`. The two
call for different responses — unavailable is a transient fault to retry, while
denied means the agent lacks the privileges its collectors need, a fixable
deployment problem that would otherwise hide inside generic failures forever.
The distinction matters most here: an empty volume list recorded as `ok` would
read as "nothing on this machine is encrypted", the most dangerous possible
misreading of a permission failure on a compliance-evidence section.

Secure Boot on legacy-BIOS firmware is reported `unsupported`, not
`enabled=false`. Secure Boot is a UEFI feature, and describing a BIOS machine
as having it switched off would flag a machine behaving correctly for its
firmware — the same false-alarm shape as reading passive Defender as disabled.
An absent TPM is likewise a successful reading rather than a failure: it is
precisely why such a machine cannot use a TPM-backed BitLocker protector.

Local administrator state is not yet collected.

### 6.2 Inventory history and diffs

Because a snapshot is written only when a section's content hash changes, the
snapshot table is already a change log rather than a sample of collections.
`GET /endpoints/{id}/inventory` returns the newest row per section plus the
sections this build knows about that the endpoint has never reported — named
rather than omitted, so a coverage gap is visible instead of looking like the
section does not exist. `.../inventory/{section}/history` pages that section's
changes, and `.../inventory/{section}/diff` compares two snapshots, defaulting
to the two most recent.

Diffs are **identity-keyed, not positional**. A positional list diff would be
worse than no diff: uninstalling one program shifts every later entry, so a
single change would render as hundreds of modifications and the real event
would be invisible. Each list field therefore declares what identifies an
element — software by name and version, volumes by mount point, adapters by MAC
— and the diff reports elements added, removed, and changed. Identity is
deliberately not equality: a corrected publisher on the same name and version is
a *change* to one program, while a version bump is an add plus a remove, which
states the upgrade explicitly. Lists with no declared identity degrade to
add/remove rather than failing. Output ordering is canonical, so the same two
snapshots always render the same diff.

Retention bounds history per `(agent, section)` rather than by age, because
sections change at wildly different rates — hardware almost never, software on
every patch cycle — and one age rule would either keep nothing useful for the
slow ones or unbounded history for the fast ones. The newest row is never a
pruning candidate at any limit: it is the endpoint's current reported state, and
deleting it would make a managed machine look like it had never reported.

Reading inventory is audited (`inventory.viewed`, `inventory.diff_viewed`) with
section names only — never collected values, which include serials, installed
program lists, and encryption state. A diff whose snapshots belong to a
different endpoint returns the same 404 as a nonexistent one, so the parameter
cannot be used to probe across endpoints or to compare unrelated machines.

### 6.1 Inventory transport

The agent advertises a per-section SHA-256 on every heartbeat; the ack names
only the sections whose stored copy is missing, changed, or older than the
24-hour refresh interval; the agent then POSTs just those to
`/agents/me/inventory`. A steady-state endpoint therefore transfers no
inventory bytes at all, and heartbeat size stays independent of how much
hardware an endpoint has.

Both sides canonicalize identically — Go's `encoding/json` sorts map keys and
emits no incidental whitespace, matching Python's
`json.dumps(sort_keys=True, separators=(",", ":"))` — and pinned digest vectors
are asserted in both test suites, because a canonicalization drift would make
every section look permanently changed or permanently unchanged.

Submissions are atomic and bounded: every section is validated before any is
stored, and an oversized or malformed section fails the whole request with 422
rather than being truncated, so what is persisted is exactly what the endpoint
reported. The agent trims its own lists to the same caps and reports `partial`.

For hardware sections a row-count cap keeps payloads far below the 256 KiB
per-section limit, so the two bounds never disagree. Installed software is the
first section where they can: at the schema's 255-character field bounds a
single entry approaches 1 KiB, so roughly 250 worst-case entries already exceed
the byte limit while remaining well under the 1024-row ceiling. The agent
therefore fits that section to *bytes* — trimming entries until the encoded
payload fits and reporting `partial` — because trimming only to the row count
would produce a payload the server rejects on every attempt, leaving the
machines with the most software silently reporting none at all.
A quarantined or revoked agent is refused, with the refusal audited. Audit
records carry section names, counts, and sizes only — never payload contents,
which include serials, adapter addresses, and volume labels.

This replaced an unvalidated path in which the heartbeat body's free-form
`inventory` object was written straight to the database with no schema and no
size bound. No released agent ever populated it, so there was nothing to
migrate.

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
`seen_commands.json` is a versioned local command journal and result outbox.
Because bounded output can contain sensitive endpoint data, Windows protects
the complete file with DPAPI under the service identity and the same
SYSTEM+Administrators-only DACL as identity; development platforms declare
protection `none` and use mode `0600`. Each command advances durably through
`reserved`, `executing`, `result_pending`, and `acknowledged`. ID and nonce are
atomically reserved before process start. Startup safely releases `reserved`
work for lease-based re-delivery, but converts `executing` to an
unknown-outcome failure without replay. Exact results remain retained through
signed expiry so lost HTTP acknowledgements and server rollback can be repaired
without duplicate execution.

Command concurrency and admission are explicit and configurable. The agent's
contract is one command at a time per runtime: a heartbeat's batch is executed
strictly in delivery order and the next beat is not issued until the batch
drains. The server enforces two bounds: admission control refuses dispatch
(HTTP 429, `agent_command_queue_full`) once an agent has
`max_outstanding_commands_per_agent` non-terminal commands, and each heartbeat
hands out at most `max_commands_per_heartbeat` commands oldest-first, so a
backlog drains over several beats instead of flooding one. A dispatched command
is eligible for re-delivery after `command_redelivery_seconds`; a new agent
either executes a released pre-start reservation or re-reports the retained
result, never re-executes accepted work. `result_pending` counts as outstanding;
terminal commands (succeeded/failed/expired) free admission slots.

Result delivery is at least once and server application is idempotent by
`(agent_id, command_id)`. The first valid result locks and completes the row,
sets `agent_completed_at` from the durable agent record and `completed_at` from
server receipt time, and appends one `command.completed` event. An exact retry
returns 204 without mutation or another audit event; a conflicting retry
returns 409. Pending-result heartbeat notices move dispatched work to
`result_pending`, giving operators truthful visibility during partial outages
without putting captured output in heartbeat or audit data.

On Windows, commands start suspended, are assigned to a Job Object configured
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then resume. Timeout,
context cancellation, SCM stop, agent crash, and normal shell exit therefore
terminate the direct process and descendants. Unix development builds use a
dedicated process group with the same no-deferred-work behavior.

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

Before append, `sanitize_audit_detail` enforces the exact registered field
schema for the action. Unknown actions, missing/extra fields, malformed nested
structures, non-canonical values, and resource-bound violations fail before a
sequence number is allocated. Credential shapes are redacted; arbitrary
operator/agent prose is retained only as SHA-256 plus byte count. The stored
safe representation is the only representation included in `event_hash`.
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md) is the complete producer contract.

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

## 9. Remote access boundary

### Interactive shell sessions (issue #61)

The interactive remote shell is a NodeLink-native capability distinct from remote
desktop. It streams a running command's output to an operator and accepts input
lines over the existing HTTP transport (chunked long-poll), so the agent stays
stdlib-only and the current Caddy/Render proxy needs no change; polling remains
the fallback. A session is a first-class, authorized, audited, bounded entity:
operator role plus explicit arbitrary-script scope, a trusted agent, an advertised
`shell-session-v1` capability, at most one live session per agent, server-authored
idle and absolute deadlines, and a per-session output-byte cap. Streamed I/O is
sensitive like command output and never enters the audit chain. Phase 1 implements
the session lifecycle, authorization, capability negotiation, timeouts, and audit;
the frame relay, the agent shell loop, and the terminal UI are deferred. See
`docs/SHELL-SESSIONS.md`.

### Remote desktop

NodeLink will not invent a proprietary remote desktop protocol. Milestone 2
plans a narrowly scoped MeshCentral integration. MeshCentral remains a separate
security and operational boundary with its own agent, sessions, permissions,
updates, logs, and failure modes. NodeLink must authorize and audit session
launches without treating MeshCentral's activity as automatically covered by
NodeLink's command signature or audit guarantees.

## 10. Repository evolution

The current top-level structure is `agent/`, `dashboard/`, `server/`,
`installer/`, `deploy/`, `docs/`, and `.github/`. Planned additions are:

```text
contracts/   versioned schemas and canonical signature vectors (implemented)
tools/       audit verification and operational utilities (planned)
```

Reorganization must be incremental. Repository moves are separate issues with
import/build/release compatibility criteria; working code must not be deleted or
moved merely to match an aspirational tree.

## 11. Known limitations and documentation corrections

- Polling is the only command transport; output is buffered, not streamed, and
  a dispatched command cannot be cancelled — expiry is the only bound. The
  interactive-shell foundation (issue #61, Phase 1) adds an authorized, audited,
  capability-negotiated, time- and byte-bounded session lifecycle
  (`docs/SHELL-SESSIONS.md`), but the live streaming frame relay, the agent's
  shell I/O loop, and the terminal UI are deferred, so no command yet streams or
  cancels.
- The dashboard requires an authenticated operator but its overview remains
  fixture-backed; beyond the endpoint telemetry and command console views,
  live audit UI, complete inventory, monitoring alerts, scheduling, patching,
  remediation, remote shell, and remote desktop are not implemented.
- Operator administration has no delete endpoint, password change/reset or
  forced-rotation flow, server-enforced password complexity, or pagination.
  The dashboard omits those controls rather than simulating them.
  Administrator-chosen initial passwords without forced rotation remain a
  security weakness; a future server change should add a one-time activation or
  forced-change flow with authorization, audit events, tests, and documentation.
- TLS termination itself remains an operator-run topology, but production
  mode (ENVIRONMENT=production) now fails startup on debug mode, placeholder
  or short secrets, missing signing keys, and a missing/non-HTTPS/loopback
  PUBLIC_BASE_URL. X-Forwarded-For is ignored unless TRUST_PROXY_HEADERS is
  explicitly enabled for a proxy-only topology.
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
- Audit anchors are published to external immutable storage when a backend is
  configured (`docs/AUDIT-ANCHORING.md`); with none configured they remain
  inside the database trust boundary and the publisher warns.
- Roles are global; clients/sites bind token and agent assignments but are not
  authorization tenants.
- Login and enrollment limiters plus enrollment counters are process-local and
  weaken or multiply with multiple workers.
- `CommandStatus.running` remains reserved for a future live start signal;
  `result_pending` is assigned from durable agent outbox notices today.
- `websockets` and `python-multipart` are declared dependencies without
  corresponding implemented product behavior.
- Release binaries are checksummed and carry an SBOM and signed build
  provenance, but are not yet Authenticode-signed (needs a paid certificate).
- Endurance is exercised by the soak harness (`deploy/soak/`, `docs/SOAK-TEST.md`),
  smoke-tested in CI; the multi-day pilot run is operator evidence.

## 12. Change discipline

Security-sensitive behavior requires unit and integration tests across every
affected boundary. Windows service, installer, signing, and credential changes
also require Windows tests. Keep this document, the threat model, deployment
readiness, and relevant runbooks synchronized with code in the same pull
request.
