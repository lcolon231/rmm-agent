# Justified emergency overrides

NodeLink can let one authorized person stand in for the approvers an
[approval policy](APPROVAL-WORKFLOWS.md) requires, for one exact command,
briefly, loudly, and on the record. The capability is opt-in per policy: a
policy that has not set `emergency_override_allowed` cannot be overridden, and
with no such policy nothing about dispatch changes.

This is an *exception record*, not a bypass. The policy stays in force. A
governed dispatch must still spend either an approval or an override; nothing
dispatches on neither. It is the dual-control analogue of a
[break-glass login](ADMIN-SESSIONS.md): the thing you reach for when the delay
itself is the harm, and that someone else must afterwards account for.

## The shape of the control

1. An administrator sets `emergency_override_allowed: true` on an approval
   policy. The default is false.
2. During an incident, a tenant administrator (or platform administrator)
   **activates an override** describing the exact command they intend to run:
   endpoint, kind, payload, a justification of at least 20 bytes, and an
   expiry of 1 to 60 minutes (default 15). Activation is behind step-up
   authentication when the operator holds a second factor.
3. The service **notifies the configured alert recipients immediately** by
   email and records on the override whether that succeeded.
4. The activator **dispatches the command** citing the override. The server
   re-derives the binding digest, re-checks the activator's authority, and
   spends the override — once.
5. A **different** tenant or platform administrator **reviews** the override
   afterwards. Until then it sits in the queue as an open debt.

## What the control guarantees

| Property | Where it is enforced |
|---|---|
| Only an opted-in policy can be overridden | `activator_eligibility` refuses without the policy flag; re-checked at dispatch, so withdrawing the flag invalidates open overrides |
| The activator could have run the command anyway | Live `authorize_command` plus `client_admin` membership (or platform admin) |
| Nothing changed between activation and execution | SHA-256 binding over `(agent_id, kind, payload)`, recomputed at dispatch |
| An override authorizes one run | Conditional `UPDATE ... WHERE status='active'`; the loser of a race is refused |
| Only the activator can spend it | `activated_by_operator_id` must match the dispatcher |
| It cannot outlive the incident | `expires_at`, bounded to 60 minutes, applied on every read and every use |
| Someone was told | Email sent at activation; outcome stored as `notified_at` or `notification_error` and audited either way |
| Someone else checks | Review refused for the activator; one review per override |
| Authority still exists when used | Activator eligibility is re-evaluated at dispatch, never read from the row |

The trust boundary this does *not* move: an override is a single person's
decision, by design. The controls around it (opt-in, admin standing, step-up,
notification, review) make that decision visible and accountable; they do not
make it a second opinion.

## Configuration

Set the flag when creating or editing a policy. Only the same identities that
may write the policy may flip it (platform admin for a global policy,
`client_admin` for a scoped one).

```bash
curl -X PATCH -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/approval-policies/POLICY_ID \
  -d '{"emergency_override_allowed": true}'
```

Notification recipients are the alert email recipients
(`EMAIL_ALERT_RECIPIENTS`), sent through the transactional provider the MFA
email factor uses. With no recipients or no provider configured, every override
records `no_recipients_configured` or `email_provider_unavailable` and is
flagged as unnotified in the queue. Fix the configuration; do not rely on an
override nobody was told about.

## Activating, running, reviewing

```bash
# Activate (step-up applies if the caller has a second factor)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/emergency-overrides \
  -d '{
        "agent_id": "AGENT_ID",
        "kind": "powershell",
        "payload": {"script": "Restart-Service -Name Spooler"},
        "justification": "Print server down for 40 users, INC-9001, approvers unreachable",
        "ttl_seconds": 900
      }'

# Dispatch, citing the override (same operator, same agent/kind/payload)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/agents/AGENT_ID/commands \
  -d '{"kind": "powershell",
       "payload": {"script": "Restart-Service -Name Spooler"},
       "emergency_override_id": "OVERRIDE_ID"}'

# Review (a different tenant or platform admin)
curl -X POST -H "Authorization: Bearer $OTHER_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/emergency-overrides/OVERRIDE_ID/review \
  -d '{"note": "Checked INC-9001; the override was warranted and the script matched the ticket"}'
```

The dashboard's **Emergency overrides** page does the same: an activation form
behind a warning, a queue sorted unreviewed-first, and a **Run now** action
that dispatches the bound command server-side so the payload never round-trips
the browser.

An unspent override can be **revoked** by the activator or a tenant admin
(`POST .../revoke` with a reason). Use it when the approver turns out to be
reachable after all.

## States

| Status | Meaning | Usable? |
|---|---|---|
| `active` | Minted, unexpired, unspent | Can be spent by the activator, or revoked |
| `consumed` | Spent on exactly one dispatch | Terminal |
| `expired` | Deadline passed | Terminal |
| `revoked` | Withdrawn before use | Terminal |

Review state is orthogonal: every override, whatever its status, stays
`reviewed_at IS NULL` until a different admin signs it off. Review is allowed
at any point, including while the override is still active, so an
administrator who sees the notification can look immediately rather than wait.

## Refusal codes

Every refusal is fail-closed: no row, no command, nothing signed or queued.

| Code | Status | Meaning |
|---|---|---|
| `emergency_override_not_required` | 409 | No approval policy governs this kind here (at activation or at dispatch) |
| `emergency_override_not_permitted` | 409 | The governing policy has not opted in |
| `emergency_override_role_insufficient` | 403 | Caller is not `client_admin` on the tenant and not a platform admin |
| `emergency_override_tenant_not_visible` | 403 | Caller has no membership on the endpoint's tenant |
| `emergency_override_operator_disabled` | 403 | Caller's account is disabled |
| `emergency_override_script_permission_*` / other `emergency_override_<authz reason>` | 403 | Caller could not run the command themselves |
| `emergency_override_limit_reached` | 429 | Caller already holds 5 open overrides in the tenant |
| `step_up_required` | 403 | A recent authenticator proof is required |
| `emergency_override_not_found` | 404 | Unknown, or belonging to another tenant — indistinguishable |
| `emergency_override_payload_mismatch` / `_agent_mismatch` / `_kind_mismatch` | 409 | The dispatch is not what the override was bound to |
| `emergency_override_activator_mismatch` | 409 | Someone other than the activator tried to spend it |
| `emergency_override_expired` / `_revoked` / `_already_consumed` / `_not_active` | 409 | Terminal state |
| `emergency_override_activator_no_longer_eligible` | 409 | Role, membership, script grant, or the policy's opt-in changed since activation |
| `approval_and_override_both_cited` | 409 | A dispatch cited both an approval and an override |
| `emergency_override_self_review_not_permitted` | 403 | The activator tried to review their own override |
| `emergency_override_review_not_permitted` | 403 | Reviewer is not a tenant or platform admin |
| `emergency_override_already_reviewed` | 409 | One review per override |
| `emergency_override_revoke_not_permitted` | 403 | Revoker is neither the activator nor a tenant admin |

## What an override does not reach

**Scheduled tasks** and **interactive shell sessions** remain refused for a
governed kind exactly as [APPROVAL-WORKFLOWS.md](APPROVAL-WORKFLOWS.md)
describes. An override is bound to one interactive dispatch; there is no
payload to bind in a shell and no activator present at a scheduler fire.

## Evidence

Every step writes to the hash-chained audit log (see
[AUDIT-EVENTS.md](AUDIT-EVENTS.md)):

- `emergency_override.activated` / `.denied` / `.expired` / `.revoked` / `.reviewed`
- `emergency_override.notified` / `.notification_failed`
- `approval_gate.allowed` with `reason: emergency_override_satisfied` and the
  `emergency_override_id`; `approval_gate.denied` with the refusal code

The justification, revoke reason, and review note are stored on the row for
the reviewer and only ever **digested** into the chain. The payload is never
written to the chain or sent by email; only its key names and SHA-256 are.

`commands.emergency_override_id` links the run to the override it spent, and
the override detail read resolves the link the other way. `NULL` on a command
means no override was involved, never that one was waived.

## Compatibility, rollout, and recovery

**Server/agent/dashboard.** Nothing reaches the agent; the envelope and
signing path are unchanged. An older dashboard simply does not show the page.

**Rollout.** Applying migration `0046` changes no behavior: the policy flag
defaults to false and the new table is empty. Turning the capability on is a
deliberate, per-policy step.

**Recovery and rollback.** Clear `emergency_override_allowed` on the policy
and every open override becomes unspendable immediately (eligibility is
re-checked live). History stays for audit. Migrations are forward-only;
crossing back below `0046` requires the exact-revision restore procedure in
[ROLLBACK.md](ROLLBACK.md).

## Limits

- One override binds one command on one endpoint. A multi-step incident needs
  one override per step; that is the point.
- Expiry is capped at 60 minutes and is not configurable per policy.
- Notification is email to the alert recipients only; webhooks are not emitted.
- One operator may hold at most 5 open overrides per tenant.
