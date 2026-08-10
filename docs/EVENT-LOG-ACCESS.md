# Bounded Windows event log access

Issue #58 adds one typed Windows command, `query_event_log`, that reads bounded,
**metadata-only** records from an allowlisted Windows event channel. It uses the
existing signed `command-v3` transport and durable result path; it never accepts
a script or falls back to shell execution.

The v1 contract is deliberately metadata-only: the agent returns structured
`<System>` fields and **never** the rendered message, `<EventData>`, or
`<UserData>`. Because Windows event message bodies — especially in the
Application channel — can contain PHI written by line-of-business healthcare
apps, excluding them keeps that free text on the endpoint. Message-body
retrieval is out of scope for v1 (see "Deferred" below).

## Contract

`query_event_log` accepts:

```json
{
  "channel": "Security",
  "tier_ack": true,
  "time_window_seconds": 86400,
  "max_events": 100,
  "providers": ["Microsoft-Windows-Security-Auditing"],
  "levels": [2, 3],
  "event_ids": [4624, 4625],
  "cursor": 918273
}
```

- `channel` must be on the server allowlist (below).
- `tier_ack` is required `true` for an elevated-tier channel and is rejected for
  a standard-tier channel.
- `time_window_seconds` is mandatory, 60 to 604,800 (7 days).
- `max_events` is mandatory, 1 to 500.
- `providers` (≤16), `levels` (unique 1–5), and `event_ids` (≤32, 0–65535) are
  optional filters. `cursor` is an optional non-negative `EventRecordID`
  watermark for pagination.

The endpoint returns bounded JSON evidence in stdout. Each record carries only
`record_id`, `time_created`, `provider`, `event_id`, `level`, `task`,
`keywords`, `computer`, and `channel`. The result also reports `count`,
`has_more`, and `next_cursor` (the highest `EventRecordID` on the page). Status
values are:

- `ok`: the bounded query ran and returned zero or more records;
- `invalid`: the signed typed payload failed endpoint-side validation;
- `failed`: the platform query (wevtutil) returned an error;
- `unsupported`: the agent build or operating system has no implementation.

Generic command status is `succeeded` only for `ok`; the others are `failed`
with an actionable bounded diagnostic.

### Pagination

The cursor is a per-channel `EventRecordID` watermark. Each query selects
`EventRecordID > cursor` inside the channel, time window, and filters, ordered
oldest-first, capped at `max_events`. The agent requests one extra record to set
`has_more` without a second round trip. To read the next page, dispatch another
query with `cursor` set to the previous `next_cursor`.

## Channel allowlist and tiers

The allowlist is fixed server-side and split into two tiers:

- **Standard:** `System`, `Application`, `Setup`.
- **Elevated (require `tier_ack`, separately audited):** `Security`,
  `Microsoft-Windows-Windows Defender/Operational`.

Any channel off the allowlist is refused. The Security channel is the
endpoint's own audit log; querying it supports HIPAA audit-controls review, but
it is gated behind the elevated tier and an explicit acknowledgment.

## Authorization and audit evidence

- `query_event_log` requires an administrator operator, an active trusted agent,
  `command-v2` or `command-v3`, and advertised `event-log-query-v1`. A non-admin
  is denied with `event_log_query_not_authorized`. An agent that does not
  advertise the capability fails closed with `agent_capability_unsupported`.
- On dispatch the server records the standard `command.authorization_allowed`
  and hash-chained `command.dispatched` events, plus a dedicated
  `event_log_query.dispatched` event capturing the minimum-necessary **scope** of
  the read: channel, tier, time window, max events, and whether provider/level/
  event-ID filters and a cursor were supplied. It never records event contents.
- Viewing the metadata result is the ordinary administrator-only command-detail
  view and emits `command_detail.viewed`. Because v1 is metadata-only, the
  result carries no free text and there is no separate ePHI store to protect.

## Windows execution and durable evidence

The agent invokes `wevtutil qe <channel> /q:<xpath> /c:<max_events+1> /rd:false
/f:XML` under a bounded 30-second context. It parses **only** each event's
`<System>` element; `<EventData>`/`<UserData>` and any rendered message are never
mapped, retained, or reported, even though wevtutil emits them. Non-Windows
builds return `unsupported` without invoking an OS action. The result is
JSON-serialized so the server and dashboard present structured metadata without
parsing free-form text, and it is subject to the same bounded output limits as
every other command.

Existing nonce and command-ID replay protection, outstanding-queue limits, and
the 64 KiB envelope cap remain in force; this contract is far smaller than either
bound.

## HIPAA control mapping

Event logs on healthcare endpoints can contain PHI, so the design was reviewed
against the HIPAA Security Rule and the minimum-necessary standard. v1's
metadata-only posture is the primary safeguard.

| Control (45 CFR) | How this feature satisfies it |
| --- | --- |
| Access control §164.312(a)(1) | Administrator-only, capability-gated, fail-closed. |
| Audit controls §164.312(b) | Signed, hash-chained `event_log_query.dispatched` records the query scope; `command_detail.viewed` audits the read. |
| Integrity §164.312(c)(1) | Command is Ed25519-signed; results ride the tamper-evident command/result path. |
| Transmission security §164.312(e)(1) | Signed commands over TLS. |
| Minimum necessary §164.502(b) | Metadata-only by default; mandatory time window and `max_events`; provider/level/event-ID filters; fixed channel allowlist with an elevated tier. |

**Residual risk:** v1 deliberately excludes free-text message bodies because
regex redaction of unpredictable free text is not a defensible PHI control. The
Security and Application channels' structured metadata (account names, file
paths) can still be indirectly identifying; admin-only access, the elevated-tier
acknowledgment, and full audit of query scope and reads are the compensating
controls.

## Deferred (message-body retrieval)

Returning event message bodies / `EventData` is a separate future issue. It
would require per-query opt-in with a recorded attestation, a SENSITIVE body
column inheriting the `Command.stdout` classification, a short dedicated
retention clock, encryption-at-rest verification, tenant-isolation review, and
out-of-band legal work (BAA amendment enumerating event-log collection and
central storage, Supabase BAA verification, service-terms disclosure, and review
of stricter state statutes such as the Washington My Health My Data Act and
California CMIA). None of that is required for the metadata-only v1.

## Offline, expiry, compatibility, and rollback

Offline agents retain the queued command server-side and pick it up on a later
heartbeat while the signed expiry remains valid; expired commands are marked
`expired` and never delivered. Revision `0032` only adds the `query_event_log`
PostgreSQL `commandkind` enum value; SQLite needs no physical enum change. Roll
out migration and server first, then canary agents that advertise
`event-log-query-v1`, then the dashboard. Old agents fail closed with
`agent_capability_unsupported`. The migration is forward-only; crossing before
`0032` requires an exact-revision database restore, because PostgreSQL enum
values are not removed in place.

## Verification

- Server coverage validates payload abuse cases, the channel allowlist and
  elevated-tier acknowledgment, filter/bound rejection, cursor validation, admin
  and capability boundaries, and the `event_log_query.dispatched` audit shape:
  `server/tests/test_event_log_access.py`.
- Agent tests validate XPath construction, `<System>`-only parsing with
  `<EventData>` exclusion, cursor/`max_events` bounds, strict payload decoding,
  and capability advertisement: `agent/internal/eventlog/`.
- Dashboard tests cover typed request building, allowlist/tier/bound rejection,
  admin-only permission filtering, and untrusted result parsing;
  `npx tsc --noEmit` checks the route/component graph.
- Real-Windows qualification on an owned disposable VM: run a `System` query and
  confirm metadata rows and pagination via `next_cursor`; confirm a `Security`
  query without `tier_ack` is refused; confirm no message text or `EventData`
  appears in any result; confirm an agent without `event-log-query-v1` fails
  closed.

The feature is implemented but does not change NodeLink's overall pilot or
production-readiness claims. Real-Windows qualification remains required before
pilot activation.
