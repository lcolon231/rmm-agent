# Interactive shell sessions (issue #61)

Status: **Phase 1 — foundation only.** The authorization, persistence, audit,
timeout, output-bound, and capability-negotiation contract is implemented and
tested. The live streaming transport (the frame relay), the agent's shell I/O
loop, and the dashboard terminal UI are **not** built yet and are called out as
deferred below. Do not describe this capability as complete until the streaming
phases ship and their tests pass.

## Goal

A live, authorized, audited, bounded interactive shell that streams a running
command's stdout/stderr to an operator and lets the operator send input lines to
it — over the existing HTTP transport, with polling preserved as the fallback.
It is **not** a pseudo-terminal (no ConPTY/pty, no curses/arrow-key TUIs).

## Design (full feature)

A **shell session** is a first-class entity linking one operator to one agent.

- **Transport:** HTTP chunked long-poll. No new agent dependency (the agent stays
  stdlib-only) and it works through the existing Caddy/Render proxy.
- **Framing:** sequence-numbered frames `{seq, stream: stdout|stderr|input|control,
  bytes, eof}`. Output frames flow agent→server→operator; input frames flow
  operator→server→agent.
- **Backpressure:** a bounded server-side ring buffer per session. The agent
  pauses producing when unacknowledged bytes exceed a window; the operator's poll
  acknowledges the highest consumed sequence number.
- **Limits:** a per-session total output byte cap and a per-frame cap. Exceeding a
  bound fails closed — the session is terminated and truncation is recorded. This
  mirrors the agent's existing bounded capture in
  `agent/internal/executor/limits.go` (count, never buffer past the cap).
- **Timeouts:** an idle timeout (no I/O) and an absolute lifetime cap, both
  server-authoritative. A stalled agent or operator cannot hold a channel open.
- **Reconnect:** a session tolerates brief disconnects and resumes by sequence
  number; it fails closed after a grace period.
- **Authorization:** the operator needs role ≥ `operator` **and** the explicit
  arbitrary-script scope (a shell is at least as powerful as running a script);
  the agent must be `trust_state == active`; at most one live session per agent.
- **Audit:** only lifecycle events are recorded, never streamed I/O bytes — the
  same rule that keeps command stdout/stderr out of the audit chain.
- **Compatibility / fallback:** additive and capability-negotiated. The command
  dispatch/poll path is unchanged. An agent that does not advertise
  `shell-session-v1` makes the server fail closed as `shell_session_unsupported`.

## State machine

```
            open (authorized)                 agent attaches
   (none) ────────────────────▶ pending ───────────────────▶ active
                                   │                            │
             operator close / idle / absolute deadline / fault │
                                   ▼                            ▼
                        closed | timed_out | failed  ◀──────────┘
```

`denied` is the recorded outcome of a refused open. Terminal states are
`closed`, `denied`, `timed_out`, and `failed`.

## Phase 1 (implemented in this change)

- **Schema:** `shell_sessions` table and `agents.supported_capabilities`
  (Alembic `0027`). No streamed I/O bytes are ever persisted — only the session,
  its bounds, and its outcome.
- **Operator API** (all under `/api/v1`, operator session required):
  - `POST /agents/{agent_id}/shell-sessions` — open. Fail-closed order:
    authorize (arbitrary-script scope) → require a trusted agent → require the
    advertised capability → admit at most one live session. `201` with the
    session, or `403 shell_session_not_authorized`, `409 agent_not_trusted`,
    `409 shell_session_unsupported`, `409 shell_session_already_active`.
  - `GET /agents/{agent_id}/shell-sessions/{id}` — audited status read.
  - `POST /agents/{agent_id}/shell-sessions/{id}/close` — idempotent close.
- **Capability negotiation:** the agent advertises `shell-session-v1` in its
  enroll/heartbeat body (`agent/internal/protocol` + `client`); the server
  persists it to `agents.supported_capabilities`.
- **Timeouts:** a background sweeper (`shell_session_sweeper`) transitions idle or
  over-lifetime sessions to `timed_out`.
- **Audit events:** `shell_session.opened`, `shell_session.viewed`,
  `shell_session.denied`, `shell_session.closed`, `shell_session.timed_out` —
  metadata only (see `docs/AUDIT-EVENTS.md` / `app/core/redaction.py`).

## Deferred (later phases)

- **Frame relay:** `POST .../input`, long-poll `GET .../output?since=seq`, the
  agent attach endpoint, the ring buffer, and sequence/ack backpressure.
- **Agent shell I/O loop:** spawning the child shell, streaming framed
  stdout/stderr, applying input lines, honoring backpressure and limits.
- **Dashboard terminal UI:** the live terminal component and the endpoint-detail
  session panel. Phase 1 ships the route handlers and the state logic
  (`available | unavailable_untrusted | unavailable_forbidden | unsupported`)
  with tests, but no visible terminal.

## Configuration

`shell_session_max_lifetime_seconds` (1800), `shell_session_idle_timeout_seconds`
(300), `shell_session_output_byte_limit` (1 MiB),
`shell_session_max_concurrent_per_agent` (1),
`shell_session_poll_timeout_seconds` (25) — in `app/core/config.py`.

## Security notes

- Streamed input and output are sensitive exactly like command output: they are
  never written to an audit detail, a log line, or an error message.
- Every open refusal is audited (`shell_session.denied`) before the fail-closed
  response, so denials are as accountable as grants.
- The feature adds a new trust boundary — a live operator→agent channel — covered
  in `docs/threat-model.md`.
