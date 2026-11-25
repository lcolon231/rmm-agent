# NodeLink

NodeLink is a self-hosted endpoint-management platform for regulated small businesses and MSPs. An operator manages a fleet of endpoints, grouped by client and site, through signed commands, monitoring, and a tamper-evident audit record.

## Tenancy and identity

**Client**:
The unit of isolation: a set of sites and endpoints that only operators with a client membership (or a platform admin) can see. Usually a customer of the MSP, but the MSP's own machines are a client too.
_Avoid_: tenant, organization, customer, account

**Client boundary**:
The default-deny rule that an operator sees and acts only within clients they hold a membership for; a resource in another client is indistinguishable from one that does not exist.
_Avoid_: tenant boundary, tenant isolation, multi-tenancy (as the name of the rule)

**Site**:
A location or grouping of endpoints within exactly one client.
_Avoid_: location, group, office

**Operator**:
A person who signs in to NodeLink to manage endpoints. In copy shown to the person at an endpoint (such as support chat), "technician" is acceptable.
_Avoid_: user, technician (in docs and code), admin (as a noun for any operator)

**End user**:
The person using a managed endpoint, who never signs in to NodeLink.
_Avoid_: user (unqualified), customer, client

**Operator role**:
An operator's deployment-wide tier: `readonly`, `operator`, or `admin`.
_Avoid_: global role, permission level

**Client membership**:
The grant that lets an operator see one client, carrying a client role.
_Avoid_: tenant assignment, access grant

**Client role**:
An operator's tier within one client: `client_readonly`, `client_operator`, or `client_admin`; an additional gate on top of the operator role.
_Avoid_: tenant role, per-client permission

**Platform admin**:
The only kind of operator that crosses the client boundary; holds no client membership of its own.
_Avoid_: superuser, root, global admin

**API token**:
A bearer credential an operator mints for an integration, confined to one client and capped at or below its owner's roles.
_Avoid_: personal access token, API key

**Script scope**:
A separate, default-deny grant (`global`, `site`, or `agent`) that allows an operator to run arbitrary scripts; admin does not imply it.
_Avoid_: script permission, execution role

## Sessions and authentication

**Operator session**:
A server-tracked sign-in, bounded by an absolute ceiling and an idle timeout, revocable individually.
_Avoid_: login, JWT (for the session itself)

**Step-up**:
Recent proof of a registered second factor, required before sensitive account and tenancy changes.
_Avoid_: re-auth, elevation, sudo

**Break-glass credential**:
A pre-provisioned offline secret that opens a short, marked, audited emergency session without MFA.
_Avoid_: emergency login, backdoor, recovery account

**Recovery code**:
A one-time code that restores access and allows enrolling a replacement authenticator but never satisfies step-up.
_Avoid_: backup code

## Endpoints and agents

**Endpoint**:
A managed computer, always belonging to one site.
_Avoid_: device (including dashboard copy), machine, host, node

**Agent**:
The NodeLink software and enrolled identity on one endpoint.
_Avoid_: client (never), daemon, bot

**Enrollment**:
The one-time exchange of an enrollment token for an agent identity and agent token.
_Avoid_: registration, onboarding

**Enrollment token**:
A site-bound credential that permits an endpoint to enroll.
_Avoid_: install key, registration code

**Trust state**:
An agent's standing, separate from whether it is online: `active`, `quarantined`, or `revoked`.
_Avoid_: status (that means online/offline), health

**Quarantine**:
The reversible trust state in which an agent still checks in but receives no commands and has no results, telemetry, or inventory recorded.
_Avoid_: isolate, suspend, disable

**Revocation**:
The terminal trust state: the agent's credentials stop working and the endpoint must re-enroll as a new identity.
_Avoid_: delete, deactivate, ban

**Reattach**:
The bounded path by which an active agent whose bearer expired while powered off rotates to a fresh credential.
_Avoid_: re-enroll, re-register

**Heartbeat**:
The agent's periodic check-in, which reports telemetry and returns queued commands.
_Avoid_: ping, poll

**Capability**:
A versioned feature flag an agent advertises (e.g. `service-process-v1`); dispatch of a gated command kind fails closed without it.
_Avoid_: feature, version, support flag

**Relay**:
A regional forwarder that carries signed agent polling traffic to the server; origin is always the final fallback.
_Avoid_: proxy, gateway, edge

## Commands and automation

**Command**:
One signed instruction for one agent, of one command kind.
_Avoid_: job, task, action, request

**Command kind**:
The typed category of a command, such as `collect_inventory`, `install_updates`, or `powershell`.
_Avoid_: command type, operation

**Command envelope**:
The signed, versioned wrapper that binds a command's payload, expiry, and nonce.
_Avoid_: message, packet

**Dispatch**:
Admitting, signing, and queuing a command for an agent.
_Avoid_: send, run, execute (that happens on the endpoint)

**Approval policy**:
A scoped rule that puts command kinds behind two-person authorization.
_Avoid_: approval rule, gate

**Approval**:
Recorded agreement by enough eligible operators to one exact command, spent once at dispatch.
_Avoid_: sign-off, consent

**Emergency override**:
A brief, reviewed exception that stands in for the approvals one exact governed command requires.
_Avoid_: bypass, break-glass (that is a credential)

**Scheduled task**:
A recurring definition that dispatches commands on a schedule.
_Avoid_: cron job, automation, job

**Maintenance window**:
A recurring, timezone-aware period during which disruptive actions such as updates and reboots are allowed.
_Avoid_: change window, blackout

**Shell session**:
An operator-owned, line-oriented, live PowerShell session on one endpoint.
_Avoid_: terminal, remote shell, console

**Support chat**:
A text conversation started by an end user and answered by an operator; never remote control.
_Avoid_: live chat, helpdesk

**Ticket**:
A request an end user submits from an endpoint for an operator to triage and resolve; asynchronous, unlike support chat.
_Avoid_: issue, case, incident, helpdesk request

## Scripts

**Script library**:
The deployment's versioned, reviewed collection of scripts.
_Avoid_: script repo, snippets

**Script version**:
An immutable, digest-bound revision of a library script, approved by a final review.
_Avoid_: script revision, edit

**Community package**:
A publisher-signed, moderated script that an admin can install into the script library.
_Avoid_: plugin, marketplace script

## Inventory, patching, and monitoring

**Inventory section**:
One class of endpoint state (hardware, installed software, Windows updates, and so on), stored as an append-only snapshot only when its content changes.
_Avoid_: inventory category, inventory table

**Patch approval policy**:
A scoped, versioned set of first-match rules deciding which updates may install, and when.
_Avoid_: patch rule, update policy

**Patch compliance**:
A read-only classification of each endpoint against its effective patch approval policy: compliant, non-compliant, stale, unknown, or exempt.
_Avoid_: patch status, patch health

**Monitoring policy**:
A scoped, named set of checks whose content lives in append-only revisions.
_Avoid_: monitor, alert rule

**Check**:
One bounded probe defined in a monitoring policy and run by the agent.
_Avoid_: monitor, test, sensor

**Alert**:
The single durable identity for one check on one agent under one policy, moving through `open`, `acknowledged`, and `resolved`.
_Avoid_: incident, notification, alarm

**Alert event**:
One append-only transition in an alert's history, whether system-driven or operator-driven.
_Avoid_: alert update, alert log

**Alert notification**:
An outbound email or signed webhook delivered for an alert event.
_Avoid_: alert (for the message itself), ping

## Audit and evidence

**Audit event**:
One entry in the append-only, hash-chained record of who did what.
_Avoid_: log entry, activity, history

**Audit chain**:
The ordered sequence of audit events, each linked to the hash of the one before.
_Avoid_: audit log, trail

**Anchor**:
A Merkle-root commitment to the audit chain's state at a sequence point.
_Avoid_: checkpoint, snapshot

**Anchor publication**:
Writing an anchor to storage an attacker who owns the database cannot alter, producing a receipt.
_Avoid_: export, backup

**Redaction**:
Scrubbing and schema-checking an audit event's detail before it is hashed, so secrets never enter the chain.
_Avoid_: masking, sanitization (as the domain term)

**Evidence bundle**:
The canonical, versioned record of one client's audit evidence up to a sequence point.
_Avoid_: export, report

**Evidence package**:
An evidence bundle rendered for delivery: a tagged PDF summary or a signed, deterministic ZIP.
_Avoid_: bundle (for the rendered form), archive

**Evidence vault**:
Immutable storage for evidence packages with retention and legal hold.
_Avoid_: archive, backup store

**Legal hold**:
A freeze on disposing of one evidence package, or every package for a client, regardless of retention.
_Avoid_: lock, freeze, preservation order

**Retention policy**:
The rule bounding how long a data class is kept; it never prunes audit events or anchors.
_Avoid_: TTL, cleanup rule
