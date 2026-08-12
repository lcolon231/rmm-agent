# Interactive shell sessions (issue #61)

Status: **implemented end to end.** NodeLink provides an authenticated,
operator-owned, line-oriented PowerShell session with live stdout/stderr,
bounded input/output queues, reconnect-by-sequence, server timeouts, and a
dashboard terminal. It is not a PTY/ConPTY and does not support full-screen or
cursor-addressed console programs.

## Contract and states

An authorized operator opens a session in `pending`; the matching agent attaches
and moves it to `active`. Operator close, agent completion, timeout, output
limit, lost relay state, or a transport/process failure ends it as `closed`,
`timed_out`, or `failed`. `denied` records an open refusal. Terminal states never
return to a live state.

Only the operator that opened a session may read its status, poll output, send
input, or close it. Another operator receives 404 to avoid a session-ID oracle.
Only the authenticated agent whose ID matches the session may attach or exchange
frames. The operator needs role `operator` or higher plus explicit arbitrary-
script scope, and the agent must be active and advertise `shell-session-v2`.

## Transport

The existing authenticated HTTPS transport uses bounded long polling:

- operator: `POST /agents/{agent}/shell-sessions`, `POST .../{id}/input`,
  `GET .../{id}/output?after=N&ack=N`, `POST .../{id}/close`;
- agent: `POST /agents/me/shell-sessions/attach`,
  `GET .../{id}/input?after=N&ack=N`, `POST .../{id}/output`, and
  `POST .../{id}/complete`.

Frames are JSON `{seq, stream, data_b64, eof}`. Sequence numbers are contiguous
and per direction. An identical retry of the most recent frame is idempotent; an
altered replay, skipped number, impossible acknowledgement, or expired cursor is
rejected. A reconnect resumes from the last acknowledged sequence while frames
remain in the relay window.

If the open response is lost, repeating open as the same operator returns the
existing live session; another operator remains blocked by the one-session
admission gate. The agent retries temporary network/5xx/429 failures with the
same sequence, and the browser preserves its output cursor while reconnecting.

Payload bytes exist only in a bounded in-memory relay and browser terminal. They
are never persisted, audited, or logged. Database rows keep lifecycle,
high-water marks, byte counts, and frame counts only.

## Bounds and backpressure

- frame: 16 KiB decoded;
- unacknowledged output: 128 KiB / 128 frames;
- queued input: 64 KiB / 128 frames;
- total output: 1 MiB per session;
- idle timeout: 5 minutes; absolute lifetime: 30 minutes;
- concurrent sessions: one per agent;
- long poll: 25 seconds.

A full relay returns 429 with `Retry-After`; the agent pauses and retries the same
frame. Crossing the total output limit fails and closes the session before the
frame is accepted. The browser keeps at most 256 KiB visible.

## Compatibility, migration, and recovery

`shell-session-v1` meant lifecycle-only support and must never unlock the live
terminal. `shell-session-v2` is the explicit compatibility boundary for framed
I/O. Older agents continue using signed command polling unchanged and show the
shell as unsupported. No new database migration is required because Alembic
`0027` already added the counters and sequence high-water fields.

Relay payloads intentionally do not survive a server process restart. A pending
session may attach to a fresh empty relay; an active session whose relay vanished
fails closed as `relay_unavailable`. The operator opens a new session. Rollback is
therefore code-only: deploy the previous server/dashboard/agent and v2 agents
stop advertising the capability on their next heartbeat; signed commands remain
available throughout.

## Verification

Server tests cover authorization, owner/agent hijack, replay and idempotency,
backpressure, cursor expiry, reconnect, concurrent admission, timeouts, output
limits, persistence metadata, and audit redaction. Go tests exercise the framed
client and a real Windows contained PowerShell process with streaming output.
The dashboard production build type-checks the terminal and proxy routes.
