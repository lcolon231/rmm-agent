# Implementation Plan: Support Chat

Spec: `specs/SPEC-support-chat.md`. Tasks: `tasks/todo-support-chat.md`.

**Why not `tasks/plan.md`:** that file holds the in-flight patch-alerting plan
(92 unchecked tasks, uncommitted work on `codex/issue-229-patch-age`). This plan
is separate work and does not touch it.

**Revision.** Open Question 2 was resolved in favor of the service-mediated
named pipe. That decision moved the agent onto the critical path and this plan
was restructured around it. All five open questions are now closed; see the
spec's Resolved Questions section.

## Overview

Sixteen tasks plus one throwaway spike, in five phases. Phase 2 builds a
**walking skeleton** — the thinnest complete path from a user typing to a row in
Postgres — before any dashboard work. Phase 3 closes the loop on the technician
side. Phases 4 and 5 add technician-initiated chat, the installer shortcut, and
governance.

**What changed from the first draft, and why it matters.** Because conversation
creation is now authenticated by the service's own agent credential, end-user
chat depends on the agent. The earlier plan's "Phase 2 ships without an agent
release" property is **gone**. Everything now rests on Spike 0. That is the
price of the stronger identity claim, and it was paid knowingly.

## Architecture Decisions

Carried from the approved spec; recorded so implementation does not relitigate.

- **One binary, no new dependencies.** `chatlaunch` and `chatpipe` both build on
  `golang.org/x/sys/windows`. `agent/go.mod` must be byte-identical at the end.
- **Browser, not tray app.** A Go GUI toolkit is a large transitive tree for a
  one-line `go.mod`, and Authenticode signing is already a pilot blocker.
- **Polling, not WebSocket.** `app/api/agents.py:382` states the heartbeat
  doubles as the command poll. No new transport primitive.
- **The service mediates; the user process is dumb.** The pipe carries one
  parameterless message, and the chat URL never travels back across it. The pipe
  ACL is the entire authorization surface, so there is no input to validate.
- **The chat token is the only new credential in the system.** No per-endpoint
  secret exists to leak, rotate, or protect.
- **Bounds and redaction ship with the write path, never as later polish.** No
  commit may contain a write path lacking its size cap or its `scrub_text` call.
- **Audit records lifecycle, never bodies.** This is also what keeps the
  six-year §164.316 documentation record separate from the 30-day PHI liability.

## Dependency Graph

```
Spike 0 (CreateProcessAsUser) ── gates ALL chat, both directions
    │
Task 1: migration 0041 + models
    │
    └── Task 2: core/support_chat.py (lifecycle, tokens, bounds, redaction)
            │
            ├── Task 3: agent router (open conversation)
            │       │
            │       ├── Task 4: chatlaunch package
            │       │       │
            │       │       └── Task 6: chatpipe + `chat` subcommand
            │       │               │
            │       │               └── Task 7: runner wiring, capability, log redaction
            │       │
            │       └── Task 5: endpoint token router (messages)
            │               │
            │               └── Task 8: end-user chat page + consent gate
            │
            └── Task 9: operator router
                    │
                    ├── Task 10: /support list + nav badge
                    │       │
                    │       └── Task 11: detail + composer
                    │
                    └── Task 12: HeartbeatAck.chat_launch_requested
                            │
                            └── Task 13: installer shortcut

Task 14: retention    ── depends on Task 1
Task 15: idle close   ── depends on Task 2
Task 16: audit events ── depends on Tasks 3, 5, 9
Task 17: docs         ── depends on everything
```

## Vertical Slices

Phase 2 is one slice, deliberately thin: **a user launches the shortcut, types a
message, and it lands in the database.** It crosses schema, core, two routers,
two agent packages, and a page — but it is one behavior, and until it works
nothing else can be demonstrated.

Phase 3 is the second slice: **a technician sees it and replies.**

## Parallelization

| Track | Tasks | Notes |
|---|---|---|
| Server core | 1 → 2 → 3, 5, 9 | Sequential. Everything blocks here. |
| Agent | 0, 4 → 6 → 7 | Spike 0 and Task 4 start immediately. Task 6 needs Task 3's contract. |
| Dashboard | 8, 10 → 11 | Needs the routers. 10 before 11. |
| Governance | 14, 15, 16 | Parallel after their deps. |

Two sessions is the useful maximum — one server+dashboard, one agent.

**Must be sequential:** Task 1 is an Alembic migration. Nothing else may create
a migration while it is unmerged, or the revision chain forks.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `CreateProcessAsUser` from session 0 fails on the pilot topology | **Critical** — now kills the entire feature, not just technician-initiated chat | **Spike 0 first, before any other work.** Fallback options are in the gate note on that task, and all of them require re-approving the spec. |
| Named pipe reachable remotely | **High** — pipes are SMB-reachable by default | `FILE_PIPE_REJECT_REMOTE_CLIENTS` is an acceptance criterion with its own test, not a code-review hope. |
| Pipe ACL too permissive | **High** — the ACL is the whole authorization surface | `INTERACTIVE` only; explicit test that a non-interactive caller is refused. |
| Chat token leaks through agent logs | **High** — the URL *is* a credential | Log redaction is an acceptance criterion of Task 7, with a test asserting the URL never reaches the log writer. |
| A `/support` page forgets `getDashboardSession()` and is silently public | **High** — the dashboard has no middleware; auth is opt-in per file | Explicit acceptance criterion on Tasks 10 and 11. |
| Migration 0041 collides with another branch | Medium | Head is `0040`. `alembic heads` must return exactly one before merge. |
| 3s polling load from concurrent conversations | Low | One open conversation per agent; unread count indexed on denormalized `client_id`. |
| Scope creep into ticketing | Medium | The spec's "Explicitly not this feature" section is the boundary. |

## Definition of Done

The standing bar for every task in `tasks/todo-support-chat.md`:

- [ ] `cd server && pytest -q` — full suite, not just the focused file
- [ ] `cd agent && go build ./... && go vet ./... && go test ./...`
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`
- [ ] `agent/go.mod` unchanged
- [ ] Every new bound and every authorization branch has a named test
- [ ] No message body in any audit event, log line, or error message

## Open Questions

None. All five are resolved in the spec. The one unresolved item is empirical,
not a decision: Spike 0.
