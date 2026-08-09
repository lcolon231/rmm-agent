# Audited remote power operations

Issue #60 adds three typed Windows commands: `reboot`, `shutdown`, and
`cancel_power_action`. They use the existing signed `command-v3` transport and
durable result path; they never accept a script or fall back to shell execution.

## Contract

`reboot` and `shutdown` accept exactly:

```json
{
  "confirm": true,
  "reason": "Approved maintenance ticket and expected impact",
  "delay_seconds": 60,
  "user_consent": "confirmed"
}
```

The reason is trimmed, printable, and 10–512 UTF-8 bytes. Delay is an integer from 30 to
3,600 seconds. `user_consent` is either `confirmed` or `no_user_session`.
Before signing, the server adds `maintenance_window_id`,
`maintenance_window_ends_at`, and `user_present_at_dispatch`. Those fields are
signed policy evidence, not caller-controlled input. `cancel_power_action`
accepts exactly `confirm: true` and a reason under the same bound.

The endpoint returns bounded JSON evidence in stdout. Status values are:

- `scheduled`, `cancelled`, or `none_pending`: valid, successful outcomes;
- `refused`: the signed window or current user-session policy no longer permits
  the action;
- `invalid`: the signed typed payload failed endpoint-side validation;
- `unavailable`: a required local policy signal, such as active-user state,
  could not be read;
- `unsupported`: the agent build or operating system has no safe implementation;
- `failed`: Windows received a valid request but rejected the operation.

Evidence contains the action, delay, maintenance-window ID/end, consent mode,
and SHA-256 of the reason. It does not duplicate the reason into output. Generic
command status is `succeeded` only for the first three outcomes; all others are
`failed` with an actionable bounded diagnostic.

## Authorization and policy

- All three commands require an administrator operator, an active trusted
  agent, `command-v2` or `command-v3`, and advertised `power-operations-v1`.
- Restart and shutdown require an active global/client/site/agent maintenance
  window. The earliest-ending matching window bounds the signed authorization.
- The requested delay must fit inside that window. Command expiry is clamped to
  the window end, so an offline endpoint cannot pick the action up later.
- If the latest heartbeat reports a user—or no heartbeat exists—
  `no_user_session` is refused. `confirmed` is an accountable administrator
  attestation. The agent rechecks the active user immediately before execution
  when `no_user_session` was selected and fails closed if the state changed or
  cannot be read.
- Cancellation needs no maintenance window because it only removes a pending
  disruptive action. Windows `shutdown /a` with nothing pending is the
  idempotent successful outcome `none_pending`.
- Power operations cannot be recurring scheduled tasks. Confirmation and live
  policy must be evaluated for each dispatch.

## Windows execution and durable evidence

The agent invokes Windows `shutdown.exe /r` or `/s` with the validated delay,
planned reason code `p:4:1`, and operator reason. Cancellation uses
`shutdown.exe /a`. Non-Windows builds return `unsupported` without invoking an
OS action.

The server commits `command.authorization_allowed` and the hash-chained
`command.dispatched` event in the same transaction as the queued command. The
agent cannot poll an uncommitted row, so durable intent exists before execution.
At the endpoint, the protected command journal moves through `reserved` then
`executing` before `shutdown.exe` starts. The minimum 30-second delay gives the
agent time to store `result_pending` and upload it before disconnect; a network
failure still leaves the exact result in the durable outbox for the next boot.
The server records `command.result_pending` and `command.completed` as ordinary
command evidence. Audit detail stores typed decision codes, payload key names,
envelope hash, timestamps, and result sizes—not the operational reason or
captured output. Viewing the full signed payload/result remains administrator-
only and emits `command_detail.viewed`.

Existing nonce and command-ID replay protection provides at-most-once endpoint
execution. An acknowledged result may be re-reported after server rollback but
the OS action is not run again. Outstanding-queue limits and the 64 KiB envelope
cap remain in force; this contract is much smaller than either bound.

## Offline, expiry, compatibility, and rollback

Offline agents retain the queued command server-side and pick it up on a later
heartbeat only while both signed expiry and maintenance-window evidence remain
valid. Expired commands are marked `expired` and never delivered. A late pickup
whose delay would cross the signed window is refused by the agent.

Revision `0031` only adds the three PostgreSQL `commandkind` enum values; SQLite
needs no physical enum change. Roll out migration and server first, then canary
agents that advertise `power-operations-v1`, then the dashboard. Old agents
fail closed with `agent_capability_unsupported`. The migration is forward-only.
Before rolling a component back, stop new power dispatch, cancel or deliberately
expire pending actions, preserve command/audit IDs, and prefer a forward fix.
Crossing before `0031` requires an exact-revision database restore and explicit
acceptance of post-backup data loss; PostgreSQL enum values are not removed in
place.

## Verification

- Server unit/integration coverage validates payload abuse cases, admin and
  capability boundaries, maintenance and consent refusal, audit-before-pickup,
  cancellation, offline pickup, expiry, and recurring-task denial:
  `server/tests/test_power_operations.py`.
- Agent tests validate strict payloads, delayed scheduling evidence, consent
  recheck, expired maintenance authorization, idempotent cancellation, and
  unknown-field refusal: `agent/internal/power/power_test.go`.
- Dashboard tests cover typed request building and untrusted result parsing;
  `npm run build` checks the complete Next.js route/component graph.
- Real-Windows release qualification must run on an owned disposable VM: open a
  maintenance window, schedule a 60-second restart, confirm the dispatch audit
  exists before pickup, cancel it, verify `cancelled`; repeat without cancel,
  verify result persistence before disconnect and result recovery after boot.
  Also verify signed-in-user refusal, no-action cancellation, offline expiry,
  and an agent without `power-operations-v1`.

The feature is implemented but does not change NodeLink's overall pilot or
production-readiness claims. Real-Windows qualification remains required before
pilot activation.
