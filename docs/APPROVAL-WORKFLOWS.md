# Approval workflows and two-person authorization

NodeLink can require that a sensitive command be authorized by people other
than the operator who wants to run it. The control is opt-in per scope and per
command kind: with no policy in place, dispatch behaves exactly as it did
before, under the existing role and [script authorization](SCRIPT-AUTHORIZATION.md)
rules.

This is a control and evidence capability. It does not by itself make a
deployment compliant with any regime; it produces the record a reviewer needs
to answer "who asked, who agreed, against what exactly, and did their authority
still exist when it ran".

## The shape of the control

1. An administrator writes an **approval policy**: a scope (global, client,
   site, or endpoint), the command kinds it governs, how many approvals are
   required (1 or 2), and how long a request stays usable.
2. An operator raises an **approval request** describing the exact command they
   intend to run — endpoint, kind, and payload. The request records the SHA-256
   of that `(agent, kind, payload)` tuple.
3. Other eligible identities **approve or reject** it. A rejection is terminal.
4. Once the request has enough approvals, the requester **dispatches the
   command** citing the approval. The server re-derives the digest from what
   was actually submitted, re-checks every approver's authority, and spends the
   approval — once.

Validation and spending happen at different points in the dispatch, and
deliberately so. The approval is checked *before* any server-side payload
transform, so what the approvers reviewed is what is verified; it is marked
consumed only after every remaining gate has passed, in the same transaction
that creates the command. A dispatch refused later — a closed maintenance
window, a denied patch selection — therefore leaves the approval intact and
usable, rather than burning two people's review on a command that never ran.
The audit trail shows this honestly: `approval_gate.allowed` records that the
approval gate agreed, and the separate refusal event records why the command
still did not run.

## What the control actually guarantees

| Property | Where it is enforced |
|---|---|
| The requester cannot approve their own request | Refused when the verdict is recorded, and re-checked when the approval is spent |
| Two approvals means two *distinct* identities | `ux_approval_decision_one_per_operator`, a database unique constraint |
| An approver could have run the command themselves | Live `authorize_command` + `client_operator` membership check |
| Nothing changed between review and execution | SHA-256 binding over `(agent_id, kind, payload)`, recomputed at dispatch |
| The approval authorizes one run | Conditional `UPDATE ... WHERE status='approved'`; the loser of a race is refused |
| A refused dispatch does not burn the approval | Validated before the payload transforms, spent only once every other gate has passed |
| Authority still exists when used | Every approver's eligibility is re-evaluated at dispatch, never read from the decision row |
| An approval cannot outlive its window | `expires_at`, applied on every read and every use |

## Policy configuration

Policies are administered at `/api/v1/approval-policies` and require the
`admin` role. A **global** policy governs every tenant, so only a platform
administrator may write one. A client-, site-, or endpoint-scoped policy is
written by a `client_admin` on the tenant it targets.

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/approval-policies \
  -d '{
        "name": "Dual control for scripts",
        "scope": "client",
        "scope_id": "CLIENT_ID",
        "command_kinds": ["powershell", "shell"],
        "required_approvals": 2,
        "request_ttl_seconds": 3600
      }'
```

There is no wildcard for command kinds. An administrator names what they are
putting behind dual control, so a later addition to the command vocabulary is
never swept into (or silently out of) an existing policy.

**Resolution is most-specific-wins, and it is specificity rather than union.**
The single most specific enabled policy that *names the dispatched kind*
governs it: endpoint, then site, then client, then global. A narrow policy that
omits a kind does not suppress a broader policy that names it — the broader one
still matches. This means a policy can only ever be authored to add a
requirement, never to quietly drop one.

Editing a policy does not reach requests already in flight. A request carries
the `required_approvals` and deadline it was raised under, so lowering the bar
cannot retroactively unlock work that is mid-review.

`request_ttl_seconds` is clamped to between 60 seconds and 7 days regardless of
what a policy asks for.

## Raising and deciding a request

```bash
# Raise
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/approval-requests \
  -d '{"agent_id":"AGENT_ID","kind":"powershell",
       "payload":{"script":"Restart-Service -Name Spooler"},
       "reason":"Spooler wedged on the print server, INC-4711"}'

# Approve (a different, eligible identity)
curl -X POST -H "Authorization: Bearer $APPROVER_TOKEN" -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/approval-requests/REQUEST_ID/approve \
  -d '{"reason":"Change window confirmed, INC-4711"}'

# Dispatch, citing the approval
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/agents/AGENT_ID/commands \
  -d '{"kind":"powershell",
       "payload":{"script":"Restart-Service -Name Spooler"},
       "approval_request_id":"REQUEST_ID"}'
```

A reason is mandatory on the request and on every verdict: 10–512 printable
UTF-8 bytes. An approval with no stated basis is a click, not evidence.

The requester must already be authorized to run the command. Approval adds a
control on top of the existing ones; it is never a route to authority the
requester does not hold, so an operator with no script permission for the
endpoint is refused at request time exactly as they would be at dispatch.

Only the requester may spend the approval. A third operator presenting someone
else's approved request is refused (`approval_request_requester_mismatch`) —
otherwise attribution would break and the approver count would be meaningless,
since the person who actually ran it was never counted.

### Eligibility to approve

An eligible approver is someone who **could have dispatched the command
themselves**, and is not the requester. Concretely, all of:

- the account is enabled;
- it is not the requester;
- it holds at least `client_operator` on the request's tenant (or is a platform
  administrator);
- `authorize_command` allows this exact endpoint and kind for it — including
  the separate arbitrary-script grant, which `admin` does not bypass.

Anything less would let approval launder authority.

## States

| Status | Meaning | Usable? |
|---|---|---|
| `pending` | Raised, not yet at its approval bar | Can be approved, rejected, cancelled |
| `approved` | At its bar; spendable by the requester | Can be spent or cancelled |
| `rejected` | An eligible identity declined it | Terminal |
| `cancelled` | Withdrawn by the requester or a tenant admin | Terminal |
| `expired` | Deadline passed | Terminal |
| `consumed` | Spent on exactly one dispatch | Terminal |

`approved` and `consumed` are deliberately distinct. Collapsing them would make
a replay of a single approval invisible; keeping them apart makes it a
detectable, audited refusal.

Expiry is applied on every read and every use, not only by a background pass, so
a request is never actionable past its deadline even if nothing has swept it.

Cancellation applies to an already-approved request as well. Work that turned
out to be unnecessary must not leave a spendable approval lying around.

## Refusal codes

Every refusal is fail-closed: no command row is created, nothing is signed, and
nothing is queued.

| Code | Status | Meaning |
|---|---|---|
| `approval_required` | 409 | Policy governs this kind and no approval was cited |
| `approval_not_required` | 409 | An approval was cited (or requested) where no policy applies |
| `approval_request_not_found` | 404 | Unknown, or belonging to another tenant — deliberately indistinguishable |
| `approval_request_not_approved` | 409 | Not at its bar, or rejected/cancelled |
| `approval_request_expired` | 409 | Deadline passed |
| `approval_request_already_consumed` | 409 | Already spent on a dispatch |
| `approval_request_payload_mismatch` | 409 | The submitted payload is not what was approved |
| `approval_request_agent_mismatch` / `_kind_mismatch` | 409 | The approval was granted for a different target |
| `approval_request_requester_mismatch` | 409 | Someone other than the requester tried to spend it |
| `approval_approver_no_longer_eligible` | 409 | An approver's authority has since lapsed |
| `approval_self_not_permitted` | 403 | The requester tried to decide their own request |
| `approval_already_recorded` | 409 | That identity has already decided this request |
| `approval_request_not_pending` | 409 | Terminal state; no further verdicts |
| `approval_request_not_authorized` | 403 | The requester may not run this command at all |
| `approver_*` | 403 | The deciding identity is not eligible (disabled, wrong tenant, insufficient role, no script grant) |
| `approval_request_limit_reached` | 429 | This operator already holds 50 open requests in the tenant |
| `approval_policy_global_requires_platform_admin` | 403 | Only a platform admin may write a global policy |

## The two bypasses, and how they are closed

A control that can be walked around is not a control. Two other paths can put a
command on an endpoint, and both are handled explicitly.

**Scheduled tasks.** An unattended run cannot obtain two-person authorization at
fire time, and pre-approving every future occurrence would defeat the
per-execution binding entirely. So a scheduled task whose kind is under an
approval policy for the target endpoint is **refused** at dispatch time — the
task's `last_status` becomes `approval_required` and a
`scheduled_task.approval_refused` event is written. This mirrors how power
operations are already refused in the scheduler.

**Interactive shell sessions.** A shell runs whatever the operator types, so
there is no payload to bind an approval to and nothing to review in advance.
When a policy puts `powershell` behind approval for an endpoint, opening an
interactive session against it is refused with
`shell_session_requires_approval`. Bounded, reviewable work goes through an
approved command dispatch instead.

MeshCentral remote-desktop launches are **not** gated by this capability. They
are governed by their own authorization and launch records
(see [MESHCENTRAL-INTEGRATION.md](MESHCENTRAL-INTEGRATION.md)); an approval
policy on a command kind does not restrict them.

## Evidence

Every step writes to the hash-chained audit log
(see [AUDIT-EVENTS.md](AUDIT-EVENTS.md)):

- `approval_policy.created` / `.updated` / `.deleted`
- `approval_request.created` / `.denied` / `.cancelled` / `.expired`
- `approval_request.decision_recorded` / `.decision_denied`
- `approval_gate.allowed` / `.denied`
- `scheduled_task.approval_refused`

`approval_gate.allowed` carries the identities whose authority was still live at
execution (`approver_operator_ids`) and the binding digest, which is the
two-person evidence in its most compact form.

The proposed command's payload is **never** written to the chain — only its key
names and SHA-256, exactly as `command.dispatched` already does. Operator prose
(the request and decision reasons, policy names) is stored as a digest plus byte
count, never verbatim.

The run itself carries the binding: `commands.approval_request_id` links the
command row to the approval it spent, and the request detail read resolves the
link in the other direction. `NULL` on a command means no policy required
approval for that run — never a claim that approval was waived.

## Compatibility, rollout, and recovery

**Server/agent/dashboard.** Nothing in this capability reaches the agent. The
command envelope, its schema version, and the signing path are unchanged, so
agents of any supported version are unaffected and no capability negotiation is
involved. The dashboard adds a reviewer queue; an older dashboard against a
newer server simply does not show it, and the server remains the security
boundary either way.

**Rollout.** Applying migration `0041` changes no behavior: with no policy rows,
every dispatch follows the pre-existing rules. Turning the control on is a
deliberate, separate step (create a policy), and it takes effect immediately for
new dispatches.

**Recovery and rollback.** Backing the capability out is a data change, not a
schema change: disable or delete the policy rows and dispatch returns to its
previous behavior immediately, leaving the request and decision history intact
for audit. Migrations are forward-only; crossing back below `0041` requires the
exact-revision restore procedure in [ROLLBACK.md](ROLLBACK.md).

**If approval is blocking urgent work.** A tenant administrator can disable the
policy (`PATCH /approval-policies/{id}` with `{"enabled": false}`), which is
itself audited as `approval_policy.updated`. A justified emergency override
workflow that keeps the policy in force while recording the exception is
tracked separately as issue #65 and is not implemented here.

## Limits

- `required_approvals` is 1 or 2. Deeper approval chains are not modelled.
- A request is bound to one endpoint. Approving one change across a fleet means
  one request per endpoint.
- Requests are not routed or notified to specific approvers; the queue is
  polled. Alert routing is a separate capability.
- One operator may hold at most 50 open requests per tenant.
