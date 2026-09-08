# Tasks: Support Chat

Plan: `tasks/plan-support-chat.md`. Spec: `specs/SPEC-support-chat.md`.

Standing bar for every task is the Definition of Done in
`tasks/plan-support-chat.md`.

---

# Phase 0 — De-risk

## Spike 0: Prove a session-0 service can launch the user's browser

**Description:** Throwaway proof that `WTSGetActiveConsoleSessionId` →
`WTSQueryUserToken` → `DuplicateTokenEx` → `CreateProcessAsUser` opens a browser
in the interactive session on the target Windows builds. Since conversation
creation is service-mediated, this gates **both** directions of chat — the whole
feature, not one path. Delete the spike code once the answer is known.

**Acceptance criteria:**
- [ ] A scratch Windows service launches `rundll32 url.dll,FileProtocolHandler https://example.com` visibly in the logged-in user's session
- [ ] Behavior recorded for: no user logged in, locked workstation, RDP session, fast-user-switching with two sessions
- [ ] Confirmed reachable through `golang.org/x/sys/windows` with no new dependency

**Verification:**
- [ ] Manual check on a Windows 11 test endpoint per `docs/WINDOWS-SUPPORT-MATRIX.md`
- [ ] Findings written into `tasks/plan-support-chat.md` under Risks

**Dependencies:** None — do this first

**Files likely touched:** Scratch only. Nothing committed.

**Estimated scope:** S

> **Gate.** If this fails, stop. Do not improvise a fallback — every alternative
> (tray app, user-context credential, static per-endpoint secret) was considered
> and rejected on the record, and reviving one requires re-approving the spec.

---

# Phase 1 — Foundation

## Task 1: Add the support-chat schema and migration

**Description:** `SupportConversation` and `SupportMessage` with their enums, and
the Alembic migration on top of `0040`. `client_id` is denormalized onto the
conversation so the unread-count poll filters by tenant without joining through
`agents`.

**Acceptance criteria:**
- [ ] Models and enums match the spec's Data Model section, plus `notice_version` and `notice_acknowledged_at` on the conversation
- [ ] Indexes on `(agent_id, status)`, `(client_id, status)`, `(conversation_id, seq)`
- [ ] `alembic upgrade head` reaches `0041`; `downgrade -1` reverses cleanly; `alembic heads` returns exactly one

**Verification:**
- [ ] `cd server && alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
- [ ] `cd server && pytest -q`

**Dependencies:** None

**Files likely touched:**
- `server/alembic/versions/0041_support_chat.py`
- `server/app/models/models.py`

**Estimated scope:** S

---

## Task 2: Conversation lifecycle, tokens, bounds and redaction

**Description:** All of `core/support_chat.py` and its schemas: open, append,
close, mint token, verify token — every bound enforced and `scrub_text` applied
on write. Deliberately one task, because no commit may contain a write path
without its size cap or its redaction.

**Acceptance criteria:**
- [ ] `append_message` scrubs via `redaction.scrub_text` and stores only the scrubbed text
- [ ] All six bounds from the spec's table enforced, each raising a distinct error carrying a `code`
- [ ] Tokens are `secrets.token_urlsafe(32)`, stored sha256-only, compared with `hmac.compare_digest`, scoped to one `agent_id` **and** one `conversation_id`
- [ ] `seq` is monotonic from 1 per conversation

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] Named tests: bearer-token scrubbing, each of the six bounds, cross-conversation token rejection, token expiry
- [ ] `cd server && pytest -q`

**Dependencies:** Task 1

**Files likely touched:**
- `server/app/core/support_chat.py`
- `server/app/schemas/support_chat.py`
- `server/app/core/config.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** M

---

### Checkpoint: Foundation
- [ ] `pytest -q` green; migration reversible
- [ ] No route exists yet — core is testable in isolation
- [ ] Review with human before building routes

---

# Phase 2 — Walking skeleton

Goal: **a user launches the shortcut, types a message, and it lands in
Postgres.** No dashboard yet.

## Task 3: Agent router — open a conversation

**Description:** `POST /api/v1/support/agent/conversations`, authenticated by the
existing `get_current_agent` dependency (`app/api/deps.py:34`). Creates the
conversation, mints the token, returns the complete URL.

**Acceptance criteria:**
- [ ] Uses `get_current_agent`; no new auth model
- [ ] Returns a complete URL including the token; the server builds it, never the agent
- [ ] Second call while a conversation is open returns the existing one rather than creating a second (idempotent reconnect, as `open_shell_session` does)
- [ ] Refuses when the agent's `trust_state` is not `active`

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q`

**Dependencies:** Task 2

**Files likely touched:**
- `server/app/api/support_chat.py`
- `server/app/main.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** S

---

## Task 4: The `chatlaunch` package

**Description:** `chatlaunch.Open(url string) error`, split as
`internal/eventlog` and `internal/svcproc` are: portable file with the API and
`ErrUnsupported`, `_windows.go` with the syscalls, `_other.go` returning
`ErrUnsupported`. Launches the default browser via
`rundll32 url.dll,FileProtocolHandler` so no browser is hardcoded.

**Acceptance criteria:**
- [ ] `Open` returns `ErrUnsupported` on non-Windows; `go build ./...` green on both
- [ ] No new entry in `agent/go.mod`
- [ ] "No interactive session" is a distinguishable, non-fatal error — nobody logged in is not a failure

**Verification:**
- [ ] `cd agent && go build ./... && go vet ./... && go test ./...`

**Dependencies:** Spike 0

**Files likely touched:**
- `agent/internal/chatlaunch/chatlaunch.go`
- `agent/internal/chatlaunch/chatlaunch_windows.go`
- `agent/internal/chatlaunch/chatlaunch_other.go`
- `agent/internal/chatlaunch/chatlaunch_test.go`

**Estimated scope:** M

---

## Task 5: Endpoint router — token-authorized message routes

**Description:** `/api/v1/support/chat/*`: `POST messages`,
`GET messages?after=<seq>`, token refresh, and notice acknowledgment. Authorized
by chat token alone.

**Acceptance criteria:**
- [ ] A token scoped to conversation A returns 403 on conversation B
- [ ] Expired token returns 401; refresh issues a new one and invalidates the old
- [ ] `?after=<seq>` returns exactly the unseen tail and is idempotent on repeat
- [ ] `POST messages` is refused until the notice is acknowledged
- [ ] Rate-limited per token through `core/ratelimit.py`

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q`

**Dependencies:** Task 2

**Files likely touched:**
- `server/app/api/support_chat.py`
- `server/app/main.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** M

---

## Task 6: The `chatpipe` package and the `chat` subcommand

**Description:** Named pipe `\\.\pipe\nodelink-agent-chat`, served by the
service; client side is a new `rmm-agent chat` subcommand in the existing
dispatcher (`agent/cmd/agent/main.go:52`). One parameterless message. The URL
never travels back across the pipe — the service launches the browser itself.

**Acceptance criteria:**
- [ ] `FILE_PIPE_REJECT_REMOTE_CLIENTS` set, with a test asserting a remote client is refused
- [ ] ACL grants connect to `INTERACTIVE` only; test asserts a non-interactive caller is refused
- [ ] The protocol carries no parameters — a test asserts extra client bytes change nothing
- [ ] Rate-limited per session
- [ ] `chat` subcommand exits non-zero with a clear message when the service is not running

**Verification:**
- [ ] `cd agent && go test ./internal/chatpipe/...`
- [ ] `cd agent && go build ./... && go vet ./... && go test ./...`

**Dependencies:** Tasks 3, 4

**Files likely touched:**
- `agent/internal/chatpipe/chatpipe.go`
- `agent/internal/chatpipe/chatpipe_windows.go`
- `agent/internal/chatpipe/chatpipe_other.go`
- `agent/internal/chatpipe/chatpipe_test.go`
- `agent/cmd/agent/main.go`

**Estimated scope:** M

---

## Task 7: Wire the service, advertise the capability, redact the URL

**Description:** `runner.go` serves the pipe and, on request, calls the agent
router then `chatlaunch.Open`. `main.go` advertises `support-chat-v1`. The URL
contains a credential and must never reach a log line.

**Acceptance criteria:**
- [ ] `support-chat-v1` in `supported_capabilities` at enrollment and renewal
- [ ] A test asserts the chat URL never reaches the log writer
- [ ] A failed launch is logged without the URL and does not stall the heartbeat loop
- [ ] Pipe server starts with the service and shuts down cleanly with it

**Verification:**
- [ ] `cd agent && go test ./...`
- [ ] Manual: run `rmm-agent chat`, browser opens at the chat page

**Dependencies:** Task 6

**Files likely touched:**
- `agent/internal/service/runner.go`
- `agent/internal/service/runner_test.go`
- `agent/cmd/agent/main.go`

**Estimated scope:** M

---

## Task 8: End-user chat page and consent gate

**Description:** The unauthenticated `/chat` route: notice acknowledgment gate,
message list, composer, 3-second poll, token refresh. Public simply by not
calling `getDashboardSession()` — there is no middleware to configure.

**Acceptance criteria:**
- [ ] Composer disabled until the notice is acknowledged; acknowledgment posts and records the notice version
- [ ] Notice states recording and retention, and does not claim HIPAA requires it
- [ ] Token read from the URL, refreshed before expiry, never rendered into visible text or a link
- [ ] Degrades to a clear "conversation closed" state

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`
- [ ] Manual: acknowledge, send a message, see it echo

**Dependencies:** Task 5

**Files likely touched:**
- `dashboard/src/app/chat/page.tsx`
- `dashboard/src/components/support-chat-panel.tsx`
- `dashboard/src/lib/support-chat-core.ts`
- `dashboard/test/support-chat-core.test.ts`

**Estimated scope:** M

---

### Checkpoint: Walking skeleton
- [ ] `rmm-agent chat` on a test endpoint opens a browser, the user acknowledges and sends a message, and the row is in Postgres
- [ ] Pipe refuses remote and non-interactive callers
- [ ] Chat URL appears in no log
- [ ] Review with human before the technician side

---

# Phase 3 — The technician side

## Task 9: Operator router

**Description:** `/api/v1/support/*`: list conversations, get transcript, post
reply, close, and a cheap `GET /support/unread-count` for the badge. All behind
`require_role(OperatorRole.operator)` and `assert_agent_visible(...,
minimum=ClientRole.client_operator)`.

**Acceptance criteria:**
- [ ] An operator in a different client gets **404** (not 403), matching the `detail="Agent not found"` convention that avoids confirming cross-tenant existence
- [ ] `unread-count` covers only visible conversations and does not join through `agents`
- [ ] Opening a transcript sets `read_at` on the delivered messages

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] Named test per authorization branch
- [ ] `cd server && pytest -q`

**Dependencies:** Task 2

**Files likely touched:**
- `server/app/api/support_chat.py`
- `server/app/main.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** M

---

## Task 10: Support Chat list page and nav badge

**Description:** `/support` listing open conversations for the operator's
visible endpoints, plus the unread badge in `dashboard-shell.tsx`.

**Acceptance criteria:**
- [ ] **The page calls `getDashboardSession()`.** The dashboard has no middleware; a forgotten call publishes the page silently
- [ ] Shows endpoint, subject, last-message time, unread count; open conversations first
- [ ] Badge matches the API and clears when the conversation is opened
- [ ] Empty state renders without error

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`
- [ ] Pure helpers tested directly

**Dependencies:** Task 9

**Files likely touched:**
- `dashboard/src/app/support/page.tsx`
- `dashboard/src/components/dashboard-shell.tsx`
- `dashboard/src/lib/support-chat-core.ts`
- `dashboard/test/support-chat-core.test.ts`

**Estimated scope:** M

---

## Task 11: Conversation detail and technician composer

**Description:** `/support/[conversationId]`: transcript, composer, close
action, 3-second poll. Reuses `support-chat-panel.tsx` from Task 8.

**Acceptance criteria:**
- [ ] **The page calls `getDashboardSession()`**
- [ ] Technician reply appears in the end user's browser within 5 seconds
- [ ] Close ends the conversation; the end-user page reflects it on its next poll
- [ ] Cursor merge never duplicates or drops a message across polls

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`
- [ ] Manual: full round trip, user → technician → user

**Dependencies:** Task 10

**Files likely touched:**
- `dashboard/src/app/support/[conversationId]/page.tsx`
- `dashboard/src/components/support-chat-panel.tsx`
- `dashboard/test/support-chat-core.test.ts`

**Estimated scope:** M

---

### Checkpoint: The loop closes
- [ ] User message reaches the dashboard within 5 seconds; badge appears and clears
- [ ] Technician reply reaches the user within 5 seconds
- [ ] Cross-tenant access returns 404 on every route
- [ ] Review with human before Phase 4

---

# Phase 4 — Technician-initiated chat and packaging

## Task 12: Carry a chat launch request on the heartbeat

**Description:** Add `chat_launch_requested: str | None` to `HeartbeatAck` and
populate it when an open technician-initiated conversation exists.

**Acceptance criteria:**
- [ ] Field is additive and defaulted, so older agents ignore it
- [ ] Populated only for `opened_by=technician` conversations still open; cleared once acknowledged
- [ ] Technician-initiated open against an agent lacking `support-chat-v1` returns `409 {"code": "support_chat_unsupported"}`, matching `shell_sessions.py:238`

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q` — no heartbeat test regresses
- [ ] Manual: technician opens a conversation, browser appears within one heartbeat interval

**Dependencies:** Tasks 7, 9

**Files likely touched:**
- `server/app/schemas/schemas.py`
- `server/app/api/agents.py`
- `server/app/api/support_chat.py`
- `agent/internal/service/runner.go`
- `server/tests/test_support_chat.py`

**Estimated scope:** S

---

## Task 13: Installer Start-menu shortcut

**Description:** A "NodeLink Support" Start-menu shortcut that runs
`rmm-agent chat`. No secret is written — there is none.

**Acceptance criteria:**
- [ ] Created on install, removed on uninstall, not duplicated on upgrade
- [ ] Shortcut runs as the logged-in user, not elevated
- [ ] `docs/INSTALLER-E2E-WINDOWS.md` steps still pass

**Verification:**
- [ ] Manual install / uninstall / upgrade on a Windows test endpoint

**Dependencies:** Task 7

**Files likely touched:**
- `installer/`

**Estimated scope:** S

---

# Phase 5 — Governance

## Task 14: Retention pruning

**Description:** Add a third class to `prune_expired`
(`app/core/retention.py:54`): delete messages of conversations closed beyond
`support_chat_retention_days` (default 30), then the emptied conversations.

**Acceptance criteria:**
- [ ] Existing conventions: `synchronize_session=False`, caller owns the transaction, `0` disables pruning
- [ ] Deletes messages of a conversation closed beyond the cutoff; leaves an **open** conversation of the same age untouched
- [ ] Audit events for the conversation survive pruning — a test asserts this
- [ ] `PruneResult` reports the counts

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q` — existing retention tests unaffected

**Dependencies:** Task 1

**Files likely touched:**
- `server/app/core/retention.py`
- `server/app/core/config.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** S

---

## Task 15: Idle auto-close

**Description:** Close conversations idle beyond
`support_chat_idle_close_seconds` from the existing sweep in `core/tasks.py`.

**Acceptance criteria:**
- [ ] Fires at the boundary; no-op before it
- [ ] Closing invalidates the token
- [ ] One indexed query, not a per-agent scan

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q`

**Dependencies:** Task 2

**Files likely touched:**
- `server/app/core/tasks.py`
- `server/app/core/support_chat.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** S

---

## Task 16: Audit events

**Description:** `audit.record` for conversation opened, notice acknowledged,
technician joined, conversation closed, and token minted. Lifecycle only.

**Acceptance criteria:**
- [ ] Events carry conversation id, agent id, message count, and for the acknowledgment the notice version
- [ ] A test asserts **no message body** appears in any audit event
- [ ] `verify_chain` passes with support-chat events in the chain

**Verification:**
- [ ] `cd server && pytest -q tests/test_support_chat.py`
- [ ] `cd server && pytest -q` — audit chain tests green

**Dependencies:** Tasks 3, 5, 9

**Files likely touched:**
- `server/app/api/support_chat.py`
- `server/app/core/support_chat.py`
- `server/tests/test_support_chat.py`

**Estimated scope:** S

---

## Task 17: Documentation

**Description:** `docs/SUPPORT-CHAT.md` and updates to `docs/ARCHITECTURE.md` —
the README names it the source of truth for completion claims.

**Acceptance criteria:**
- [ ] Covers the pipe's threat model, the auth model, the six bounds, retention, and what is deliberately out of scope
- [ ] States plainly that the consent notice is a recording disclosure, **not** a HIPAA authorization, and that the 30-day default is a minimum-necessary choice rather than a regulatory requirement
- [ ] `docs/RETENTION.md` table gains the support-chat row
- [ ] `docs/ARCHITECTURE.md` reflects the feature and its Windows-only constraint

**Verification:**
- [ ] Manual read-through against shipped behavior

**Dependencies:** Tasks 1-16

**Files likely touched:**
- `docs/SUPPORT-CHAT.md`
- `docs/RETENTION.md`
- `docs/ARCHITECTURE.md`
- `README.md`

**Estimated scope:** S

---

### Checkpoint: Complete
- [ ] All success criteria in `specs/SPEC-support-chat.md` met
- [ ] Full Definition of Done green
- [ ] Ready for review
