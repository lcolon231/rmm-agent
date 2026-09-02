# Spec: support-chat

Module id: `support-chat` — single capability, no capability map required.

## Objective

Let a person sitting at a managed endpoint start a text conversation with a
technician, and let that technician answer from the dashboard, without either
side needing a phone call or a ticket system.

**User story.** A user at an enrolled Windows endpoint opens NodeLink Support
from their Start menu (or the technician pops it open for them). They type
"my VPN keeps dropping". A conversation appears on the dashboard's Support Chat
page with an unread badge in the nav. A technician with access to that endpoint's
client opens it, replies, and the two exchange messages until the technician
closes the conversation. The full transcript is retained as a redacted,
retention-governed record tied to the endpoint.

**Explicitly not this feature.**

- **Not remote control.** MeshCentral (`docs/MESHCENTRAL-INTEGRATION.md`) already
  covers screen sharing, and its own chat is out of scope here precisely because
  its history lives outside NodeLink's audit chain.
- **Not an interactive shell.** `docs/SHELL-SESSIONS.md` is technician-to-machine.
  This is technician-to-human, and unlike shell frames the content is persisted.
- **Not a ticketing system.** No queues, SLAs, priorities, or assignment routing
  in v1. A conversation is open or closed.
- **Not operator-to-operator chat.** Exactly one endpoint user and one or more
  technicians per conversation.

## Assumptions

Recorded because they were decided, not derived. Overturning any of these
invalidates parts of the design below.

1. "User" means the person at the endpoint; "technician" means an authenticated
   dashboard operator subject to `core/tenant_scope.py`.
2. Chat is text-only. No attachments, no images, no file transfer in v1.
3. Chat content may be PHI-adjacent and is therefore treated as evidence:
   persisted, redacted, retention-governed, and audit-logged.
4. Transport is HTTP polling on both sides. The server has no WebSocket for
   agents or the dashboard, and `app/api/agents.py:382` states outright that the
   heartbeat doubles as the command poll. This feature does not change that.
5. Windows-first, matching the rest of the agent. Non-Windows builds compile and
   report the capability as absent.

## Tech Stack

- Server: Python 3, FastAPI, SQLAlchemy 2 (async), Pydantic v2, Alembic
- Agent: Go 1.22, `golang.org/x/sys` v0.21.0 (the only dependency — this feature
  adds none)
- Dashboard: Next.js 16.2.12, React 19.2.4, TypeScript 5, Node >= 24
- Tests: `pytest` + `pytest-asyncio` (asyncio_mode=auto); `go test`; `node --test`

## Commands

```
# Server
cd server
pip install -r requirements.txt pytest pytest-asyncio httpx aiosqlite "moto[s3]"
python scripts/gen_command_keys.py     # once, before the first test run
pytest -q
pytest -q tests/test_support_chat.py
alembic upgrade head

# Agent
cd agent
go build ./...
go vet ./...
go test ./...
go test ./internal/chatlaunch/...

# Dashboard
cd dashboard
npm ci
npm run lint
npm run typecheck
npm test
npm run build
```

## Project Structure

Files this module touches:

```
server/alembic/versions/0041_support_chat.py   -> new (head is 0040)
server/app/models/models.py                    -> SupportConversation, SupportMessage
server/app/schemas/support_chat.py             -> new
server/app/api/support_chat.py                 -> new: operator + agent + endpoint-token routers
server/app/core/support_chat.py                -> new: conversation lifecycle, token mint/verify
server/app/core/retention.py                   -> prune closed conversations
server/app/core/config.py                      -> 5 new settings
server/app/main.py                             -> include the three routers
server/app/schemas/schemas.py                  -> HeartbeatAck.chat_launch_requested
server/app/api/agents.py                       -> populate that field
server/tests/test_support_chat.py              -> new

agent/internal/chatlaunch/chatlaunch.go         -> new: portable entry point
agent/internal/chatlaunch/chatlaunch_windows.go -> new: WTSQueryUserToken + CreateProcessAsUser
agent/internal/chatlaunch/chatlaunch_other.go   -> new: returns ErrUnsupported
agent/internal/chatpipe/chatpipe.go             -> new: portable pipe API
agent/internal/chatpipe/chatpipe_windows.go     -> new: pipe server + client, ACL, reject-remote
agent/internal/chatpipe/chatpipe_other.go       -> new: returns ErrUnsupported
agent/internal/service/runner.go                -> serve the pipe; handle chat_launch_requested
agent/cmd/agent/main.go                         -> `chat` subcommand; advertise the capability

dashboard/src/app/support/page.tsx              -> conversation list
dashboard/src/app/support/[conversationId]/page.tsx -> transcript + composer
dashboard/src/app/chat/page.tsx                 -> end-user page (unauthenticated route)
dashboard/src/components/support-chat-panel.tsx -> shared message list + composer
dashboard/src/components/dashboard-shell.tsx    -> nav entry + unread badge
dashboard/src/lib/support-chat-core.ts          -> types + pure helpers
dashboard/test/support-chat-core.test.ts        -> new

installer/                                      -> Start-menu shortcut running `rmm-agent chat`
docs/SUPPORT-CHAT.md                            -> new
```

## Design

### Why the browser, and not a tray app

The agent runs as a Windows service in session 0 and has no UI surface anywhere
in `agent/internal/*`. Three options were considered; the chosen one is that the
service launches the user's **default browser** into their interactive session,
pointed at a server-hosted chat page.

The rejected alternative was a `rmm-agent chat` subcommand drawing a native tray
icon and window. It has better UX, but a Go GUI toolkit is a large transitive
dependency tree for a `go.mod` that currently contains exactly one line, and
Authenticode signing is already a stated pilot blocker
(`docs/DEPLOYMENT-READINESS.md`). Revisit after signing lands.

Consequences accepted: the chat window is a browser tab and can be closed and
lost; the user must have a default browser and an active desktop session. No
desktop session means no chat, which is correct — there is nobody to chat with.

### Conversation creation is agent-authenticated

The end user never presents a credential. The Start-menu shortcut runs
`rmm-agent chat`, which asks the **service** — over a local named pipe — to open
a conversation. The service already holds the agent credential and calls the
server with it, through the existing `get_current_agent` dependency
(`app/api/deps.py:34`). The server creates the conversation, mints a chat token,
returns a complete URL, and the service launches the browser at it.

This is why there is no per-endpoint secret anywhere in this design. The agent
credential is DPAPI user-scope under LocalSystem with the identity file ACL'd to
SYSTEM, Administrators and Owner (`agent/internal/config/protect_windows.go:62`),
so no user-context process can read it — and none needs to. **The chat token is
the only new credential the feature introduces**, and it is already short-lived
and scoped to one conversation.

The claim this buys is the strong one: a conversation exists because a process
in a live interactive session on that endpoint asked for it. No other option
considered could prove that.

### The named pipe

Pipe name `\\.\pipe\nodelink-agent-chat`, served by the service.

- **`FILE_PIPE_REJECT_REMOTE_CLIENTS` is mandatory.** Named pipes are reachable
  over SMB by default. Without this flag the pipe is a remote endpoint.
- **The pipe accepts one message and it carries no parameters.** The client says
  "open chat" and nothing else. A local caller cannot influence the agent id, the
  URL, the conversation, or any field — so the pipe's ACL is the entire
  authorization surface, and there is no input to validate.
- **ACL**: connect for `INTERACTIVE`; no `Everyone`, no `NETWORK`. The claim
  being enforced is "a logged-on user of this machine", which is exactly the
  claim the feature needs.
- Rate-limited per session, so a loop cannot spam the tenant's queue.
- The service never echoes the URL back over the pipe. It launches the browser
  itself, so the token never crosses the pipe boundary at all.

### Two authorization models, two routers

`support_chat.py` exposes two routers with different auth, mirroring the
`router` / `agent_router` split in `app/api/shell_sessions.py:54-58`.

**Operator router** (`/api/v1/support/...`) uses
`Depends(require_role(OperatorRole.operator))` and `assert_agent_visible(...,
minimum=ClientRole.client_operator)`, exactly as
`open_shell_session` does at `app/api/shell_sessions.py:213-221`. A technician
sees only conversations on endpoints they can already see.

**Agent router** (`/api/v1/support/agent/...`) uses the existing
`get_current_agent` dependency. It carries one route: open a conversation and
return its URL.

**Endpoint router** (`/api/v1/support/chat/...`) is authorized by the chat
token alone — not an operator session, not an agent credential. The token is:

- Minted server-side and never stored in plaintext — `sha256` only, matching how
  enrollment tokens and agent credentials are already stored.
- Scoped to exactly one `agent_id` and one `conversation_id`.
- Short-lived (`support_chat_token_ttl_seconds`, default 900) and refreshed by
  the page while the conversation is open, so an abandoned URL in browser history
  is inert within the TTL.
- Rate-limited per token through the existing `core/ratelimit.py`.

The token is the whole security boundary for the end-user side, so it must be
`secrets.token_urlsafe(32)` and compared with `hmac.compare_digest`.

### Data model

```python
class SupportConversation(Base):
    id: Mapped[str]                       # uuid4 hex
    agent_id: Mapped[str]                 # FK -> agents.id, indexed
    client_id: Mapped[str]                # denormalized for tenant filtering
    status: Mapped[SupportConversationStatus]   # open | closed
    opened_by: Mapped[SupportParty]       # end_user | technician
    subject: Mapped[str | None]           # first 120 chars of first message
    created_at / last_message_at / closed_at: Mapped[datetime]
    closed_by_operator_id: Mapped[str | None]
    token_hash: Mapped[str]               # sha256 of the active chat token
    token_expires_at: Mapped[datetime]

class SupportMessage(Base):
    id: Mapped[str]
    conversation_id: Mapped[str]          # FK, indexed with (conversation_id, seq)
    seq: Mapped[int]                      # monotonic per conversation, from 1
    sender: Mapped[SupportParty]
    operator_id: Mapped[str | None]       # set when sender is technician
    body: Mapped[str]                     # already scrubbed on write
    created_at: Mapped[datetime]
    read_at: Mapped[datetime | None]      # technician-side read marker
```

`client_id` is denormalized onto the conversation so the unread-count query
filters by tenant without joining through `agents` on every dashboard poll.

`seq` is per-conversation and monotonic so both sides poll with `?after=<seq>`
and get exactly the messages they have not seen. This is the same cursor idea as
`core/shell_relay.py`, minus the eviction — messages here are durable.

### Redaction, retention, audit

- **On write**, `body` passes through `redaction.scrub_text`
  (`app/core/redaction.py:1154`), which already strips bearer tokens and
  `key=value` secret pairs. A user pasting a credential into chat is a realistic
  event, and scrubbing at write time means the plaintext never lands in Postgres.
  Store the scrubbed text only; there is no "original".
- **Retention**: `prune_expired` (`app/core/retention.py:54`) gains a third
  class, deleting `SupportMessage` rows for conversations closed longer ago than
  `support_chat_retention_days` (**default 30**), then the empty conversations.
  It follows the existing conventions: `synchronize_session=False`, a setting of
  0 disables pruning, and the caller owns the transaction.
- **Audit**: `audit.record` is called for conversation opened, notice
  acknowledged, technician joined, conversation closed, and token minted —
  lifecycle only. Message *bodies* never enter the audit chain; the audit event
  carries the conversation id and message count. This keeps chat content out of
  the anchored hash chain while leaving the chain able to prove a conversation
  happened.

**Why 30 days, and why the split matters.** HIPAA sets no retention period for
PHI. The widely cited six years is §164.316(b)(2)(i) and §164.530(j)(2), which
govern *required documentation* — policies, procedures, and records of required
actions and assessments — not clinical records or PHI generally; medical-record
retention is state law. §164.312(b) requires audit controls but names no
duration, while §164.502(b) minimum-necessary argues toward holding less.

That maps cleanly onto the split above:

| | Regulatory treatment | Here |
|---|---|---|
| Message bodies (incidental PHI, not a designated record set) | No minimum; minimum-necessary favors short | `support_chat_retention_days`, prunable |
| Lifecycle audit events (§164.312(b), §164.316) | Effectively six years | Never pruned (`docs/RETENTION.md:23`) |

Keeping bodies out of the audit chain therefore yields the long accountability
record *without* the long PHI liability. Thirty days is chosen because nothing
requires longer and every retained day is breach-notification scope under
§§164.400-414. It remains a setting so a deployment with a state-law or
contractual reason can raise it deliberately. This is engineering rationale, not
legal advice; confirm with counsel before pilot.

### Consent notice

Before the first message can be sent, the end-user page presents the recording
and retention notice and requires an explicit acknowledgment. The acknowledgment
is recorded as an audit event carrying the notice version and timestamp, and the
composer stays disabled until it is given.

This is **not** a HIPAA authorization. The person typing is almost always a
workforce member at their own workstation, not a patient; the notice is a
recording and monitoring disclosure, governed by state recording law and
employment policy. `docs/SUPPORT-CHAT.md` must say so rather than implying HIPAA
requires it.

Notice text is versioned (`support_chat_notice_version`) so a later wording
change is distinguishable in the audit record from the original.

### Message flow

**User opens a chat** (via the Start-menu shortcut):

1. Shortcut runs `rmm-agent chat` in the user's session. It connects to the
   named pipe and sends the single parameterless "open chat" message.
2. The service calls `POST /support/agent/conversations` with its own agent
   credential. The server creates a `SupportConversation` (`opened_by=end_user`),
   mints a chat token, and returns the complete URL.
3. The service calls `chatlaunch.Open(url)`. The URL never crosses the pipe back
   to the user-context process.
4. The conversation appears on the dashboard's next poll.

The end user's browser therefore receives a short-lived, conversation-scoped
token and nothing else — no long-lived secret exists to leak.

**Technician opens a chat:**

1. `POST /support/conversations` with `agent_id`, subject to the same
   `assert_agent_visible` check as every other endpoint action.
2. Server sets `chat_launch_requested` on the next `HeartbeatAck`.
3. Agent's `runner.go` sees the field and calls `chatlaunch.Open(url)`.
4. Latency is one heartbeat interval (default 60s). Acceptable: the technician
   is asking for the user's attention, not mid-conversation.

**Steady state:** both sides `GET .../messages?after=<seq>` every
`support_chat_poll_interval_seconds` (default 3) while the conversation is open,
and `POST .../messages` to send. The dashboard's unread badge polls a separate
cheap `GET /support/unread-count` on the existing nav refresh cadence.

### Agent side

`chatlaunch.Open(url string) error` is the entire agent surface. The Windows
implementation calls `WTSGetActiveConsoleSessionId` → `WTSQueryUserToken` →
`DuplicateTokenEx` → `CreateProcessAsUser`, launching the default browser via
`rundll32 url.dll,FileProtocolHandler <url>` so no browser is hardcoded. All
four syscalls are already reachable through `golang.org/x/sys/windows`. The
build split follows `internal/eventlog` and `internal/svcproc`:
`_windows.go` has the real implementation, `_other.go` returns
`ErrUnsupported`, and the portable file holds the interface and tests.

The agent advertises `support-chat-v1` in `supported_capabilities`. The server
refuses technician-initiated chat with `409 {"code": "support_chat_unsupported"}`
when it is absent, matching `app/api/shell_sessions.py:238`.

The URL is never built by the agent. The server sends the full URL, token
included, in the heartbeat ack. The agent treats it as opaque and must not log
it — it contains a credential. Add it to the existing log-redaction path.

### Bounds

Every one of these is enforced server-side and returns `400` with a `code`:

| Bound | Setting | Default |
|---|---|---|
| Message body bytes | `support_chat_max_message_bytes` | 4096 |
| Messages per conversation | `support_chat_max_messages` | 500 |
| Open conversations per agent | `support_chat_max_open_per_agent` | 1 |
| Token TTL seconds | `support_chat_token_ttl_seconds` | 900 |
| Idle auto-close seconds | `support_chat_idle_close_seconds` | 3600 |
| Message body retention days | `support_chat_retention_days` | 30 |

One open conversation per endpoint keeps the model simple and matches the
physical reality of one person at one machine. Idle conversations are closed by
the existing sweep in `core/tasks.py`, which already runs every heartbeat
interval.

## Code Style

Server code matches the surrounding modules: async SQLAlchemy 2 style, explicit
`HTTPException` with a `{"code": ...}` detail body, comments that explain *why*
rather than restating the call.

```python
async def append_message(
    db: AsyncSession,
    conversation: SupportConversation,
    *,
    sender: SupportParty,
    body: str,
    operator_id: str | None = None,
    now: datetime | None = None,
) -> SupportMessage:
    """Append one message and advance the conversation cursor.

    The body is scrubbed here rather than at the route so every writer -- user
    poll, technician reply, idle-close notice -- goes through one redaction
    path. Caller owns the transaction.
    """
    if conversation.status is not SupportConversationStatus.open:
        raise ConversationClosed()
    scrubbed = scrub_text(body)
    if len(scrubbed.encode()) > settings.support_chat_max_message_bytes:
        raise MessageTooLarge()
    ...
```

Go code matches `internal/eventlog`: a portable file declaring the API and
`ErrUnsupported`, platform files behind build tags, no new dependencies.

## Testing Strategy

`pytest` in `server/tests/`, `go test` beside the package, `node --test` in
`dashboard/test/`. Tests assert behavior through the API, not internals — the
existing suite's convention.

**Server** (`tests/test_support_chat.py`), each a named test:

- A chat token scoped to conversation A is rejected on conversation B (403).
- An expired chat token is rejected (401), and refresh issues a new one.
- A technician in a different client cannot see or post to the conversation (404,
  not 403 — matching the `detail="Agent not found"` convention that avoids
  confirming existence across tenants).
- `?after=<seq>` returns exactly the unseen tail, and is idempotent on repeat.
- A body containing `Bearer abc123...` is stored scrubbed.
- Oversize body, message-count cap, and second-open-conversation each return the
  documented code.
- Retention deletes messages of a conversation closed beyond the cutoff and
  leaves an open conversation of the same age untouched.
- `support_chat_retention_days = 0` disables pruning.
- Idle auto-close fires at the boundary and is a no-op before it.
- Audit events are recorded for open/join/close and contain **no** message body.
- Technician-initiated chat against an agent lacking the capability returns 409.

**Agent** (`internal/chatlaunch`): `Open` returns `ErrUnsupported` on non-Windows;
the Windows path is covered by a `_windows_test.go` guarded like
`eventlog_windows_test.go`, plus a test that the URL never reaches the log
writer.

**Dashboard**: pure helpers in `support-chat-core.ts` — cursor merge, unread
count, timestamp formatting — tested directly. No component tests, consistent
with the existing suite.

Coverage expectation: every bound in the table above and every authorization
branch has a named test. Untested new branches block the PR.

## Boundaries

- **Always:** run `pytest -q`, `go test ./...`, and `npm run lint && npm run
  typecheck && npm test` before committing; scrub message bodies on write; apply
  `assert_agent_visible` on every operator route; store token hashes, never
  plaintext; add a test with each new bound.
- **Ask first:** any change to `HeartbeatAck` beyond the single additive field;
  adding a dependency to `agent/go.mod`; introducing WebSocket or SSE; changing
  redaction or retention defaults; anything that widens the chat token's scope.
- **Never:** log the chat URL or token; put message bodies in the audit chain;
  reuse an agent credential or operator session to authorize the end-user page;
  make the end-user route reachable without a token; commit a migration that
  isn't `0041` on top of `0040`.

## Success Criteria

1. A user at an enrolled Windows endpoint opens the Start-menu shortcut, sends a
   message, and it appears on the dashboard Support Chat page within 5 seconds.
2. The nav shows an unread badge whose count matches unread messages on
   conversations visible to that operator, and clears when the technician opens
   the conversation.
3. A technician reply appears in the user's browser within 5 seconds.
4. A technician opening a conversation causes the browser to launch on the
   endpoint within one heartbeat interval.
5. An operator in a different client receives 404 on every route for that
   conversation.
6. A chat token from one conversation is rejected on another; an expired token is
   rejected.
7. A message containing a bearer token is stored scrubbed.
7a. The composer is disabled until the notice is acknowledged, and the
    acknowledgment is recorded with its notice version.
7b. The named pipe rejects a remote client and rejects a caller outside
    `INTERACTIVE`; the chat URL never crosses the pipe back to the user process.
8. `prune_expired` removes messages from conversations closed beyond the
   retention cutoff and leaves open ones alone.
9. `alembic upgrade head` reaches `0041`, and `alembic downgrade -1` reverses it
   cleanly.
10. `go build ./...` succeeds on Windows and Linux; `agent/go.mod` is unchanged.
11. Full suite green: `pytest -q`, `go test ./...`, `npm run lint`,
    `npm run typecheck`, `npm test`, `npm run build`.
12. `docs/SUPPORT-CHAT.md` exists and `docs/ARCHITECTURE.md` reflects the feature,
    since the README names it the source of truth for completion claims.

## Resolved Questions

All five are closed. Recorded with their reasoning so implementation does not
reopen them.

1. **Consent and disclosure.** *Explicit acknowledgment before the first
   message*, recorded as an audit event with the notice version. See the Consent
   notice section. It is a recording disclosure, not a HIPAA authorization.
2. **How the chat page identifies its endpoint.** *It doesn't.* The service
   mediates over a named pipe and authenticates with the agent credential, so no
   per-endpoint secret exists. See "Conversation creation is agent-authenticated".
3. **Unauthenticated route in an authenticated app.** *No middleware exists.*
   The dashboard enforces auth per file by calling `getDashboardSession()`
   (`app/login/page.tsx:16`), so `/chat` is public by not calling it. The
   inverse is now the risk: a `/support` page that forgets the call is silently
   public, so that call is an explicit acceptance criterion on Tasks 6 and 7.
4. **Non-Windows endpoints.** *Out of scope, and never in it.* `ci.yml:81` and
   `release.yml:158` build `GOOS=windows` only; there is no shipped non-Windows
   agent. `_other.go` returns `ErrUnsupported` so `go build ./...` stays green on
   developer machines. Nothing for the dashboard to hide.
5. **Retention default.** *30 days*, with the reasoning in "Redaction,
   retention, audit".

## Remaining Risk

One thing is unresolved and cannot be settled by discussion: whether
`CreateProcessAsUser` from session 0 actually launches a browser on the target
Windows builds. Because conversation creation is now service-mediated, this
gates **both** directions of chat, not just the technician-initiated one. It is
the first thing built (Spike 0 in `tasks/todo-support-chat.md`) and the plan
states what happens if it fails.
