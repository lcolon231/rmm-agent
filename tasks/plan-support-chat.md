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

### Spike 0 / issue #233: pilot verification (2026-09-08, concluded with two cases blocked)

**Gate: closed. RDP and fast user switching are BLOCKED, not passed.**
Unlocked-console, locked-workstation, and clean no-user behavior are confirmed
on the pilot. The two multi-session cases could not be exercised on the only
available hardware, so this spike answers the single-console question and
explicitly does not answer the multi-session one. No production implementation
or fallback is authorized by these partial results.

- Pilot: Windows 11 Pro, version `10.0.26200`, build `26200`, x64 probe.
  Installed `NodeLinkAgent` runs as `LocalSystem`.
- Scratch service: `NodeLinkBrowserSpike233`, manual startup, LocalSystem,
  automatically stops after 30 minutes. Executable and current log are in
  `C:\ProgramData\NodeLinkBrowserSpike233`; source/build/test artifacts are in
  ignored `.tmp/issue-233/`. Nothing from this spike is committed.
- At `2026-09-08 19:29:31 UTC`, service PID `29944`, session `0`, SID
  `S-1-5-18` selected console session `3` (Luis). The exact
  `WTSGetActiveConsoleSessionId` -> `WTSQueryUserToken` -> `DuplicateTokenEx` ->
  `CreateProcessAsUser` path created rundll32 PID `456`, independently checked
  in session `3`, with the user's token. No API error. Luis confirmed the exact
  visible tab `https://example.com/#spike233-20260908T192931.904472500Z`.
- After sign-out/sign-in, control `128` at `19:41:27 UTC` successfully created
  rundll32 PID `20832` in the new console session `4`, proving API recovery
  without restarting the service. The recovery tab's fragment is
  `#spike233-20260908T194127.905543500Z`; separate visibility confirmation is
  not yet recorded for this extra recovery check.
- The service self-stopped on its 30-minute limit at `19:59:31 UTC` and was
  restarted at `20:02:40 UTC` as PID `16540`. Its startup probe, and a later
  control `128` at `20:05:42 UTC`, both created rundll32 in console session `4`
  with no API error. This repeats the already-confirmed single-console case and
  adds no new topology, but it does confirm the path survives a full service
  stop/start cycle.
- Scratch `go test -v ./...`, `go vet ./...`, and `go build -mod=readonly`
  passed with Go `1.24.7 windows/amd64`. Executable module metadata confirms
  the sole dependency is `golang.org/x/sys v0.21.0`; `agent/go.mod` and
  `agent/go.sum` are untouched.

| Required state | Evidence so far | Verdict |
|---|---|---|
| Logged-on, unlocked console | Current service and child sessions verified as 0 -> 3; API success; Luis confirmed the exact marked browser tab | PASS |
| No user logged in | Current log: sign-out at 19:34:47 UTC; delayed probe at 19:35:01 UTC shows all usernames empty, console session 4, `WTSQueryUserToken` returns `ERROR_NO_TOKEN` (1008), result `SKIPPED_NO_USER`, no child PID. Sign-in event at 19:35:44; service still Running | PASS: clean non-fatal skip, service survives sign-out/sign-in |
| Locked workstation | Current log: lock event at 19:31:05 UTC; delayed probe at 19:31:17 UTC created PID 9900 in session 3. Luis confirmed `https://example.com/#spike233-20260908T193117.175378400Z` after unlocking; no unlock-triggered launch exists in this probe | PASS: launched while locked, visible after unlock |
| RDP | **Not tested.** No remote session was ever established, so no probe ever observed one. Client attempts failed first with connection error `0x204`, then `Test-NetConnection 10.20.20.194 -Port 3389` from the laptop returned `PingSucceeded: False` and `TcpTestSucceeded: False` with `InterfaceAlias: NordLynx` and `SourceAddress: 10.5.0.2`: the client routes over a VPN that cannot reach the host Ethernet address. The host side was verified correct and is not the fault: TermService Running, 3389 listening on `0.0.0.0` and `::`, RDP TCP allow rule enabled for Any remote address, `fDenyTSConnections=0`, and `spiketest` already a member of Remote Desktop Users. Every `SESSION` line in the log shows `id=65536 station="RDP-Tcp" state=Listen user=""`, that is the listener only and never a session | BLOCKED by topology, no evidence either way |
| Fast user switching, two logged-on users | **Not tested.** A second local account is staged and ready (`spiketest`: enabled, member of Remote Desktop Users, `PasswordLastSet` 2026-09-02, never signed in, no profile at `C:\Users\spiketest`), but reaching a second session requires a human at the Winlogon secure desktop (Ctrl+Alt+Del, Switch user). The pilot operator cannot switch Windows users on this machine, and the secure desktop cannot be driven by automation. Every probe in the log shows exactly one logged-on user, `Luis` | BLOCKED by topology, no evidence either way |

**Selection limitation to test explicitly:** Microsoft's
[WTSGetActiveConsoleSessionId documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid)
defines the result as the physical console session, not the active RDP user.
`0xFFFFFFFF` means no console is attached, not necessarily nobody logged on.
The scratch probe records all sessions but deliberately does not change the
proposed selection algorithm. Because RDP and fast user switching were never
exercised, this limitation is **unmeasured rather than disproven**. On the
documented behaviour of the API an RDP user should receive nothing, and a fast
user switch should send the browser to whoever currently holds the console
rather than to the technician's intended user, but this spike produced no
evidence for or against either. Both remain open risks.

**What #234 needs before it can rely on this path.** Either (a) a pilot host
where a second interactive session can actually be created, meaning a machine
the operator can sign into twice, or a client that can reach 3389 with no VPN
in the path, followed by a re-run of the two blocked rows; or (b) a selection
algorithm that does not depend on `WTSGetActiveConsoleSessionId` at all:
enumerate with `WTSEnumerateSessions`, filter to `WTSActive` sessions with a
resolvable token, and choose the target user explicitly. Option (b) is the
safer default precisely because the console-only assumption is the part that
was never tested. This is a spec decision, not an implementation detail.

Procedure for the blocked re-runs, once suitable hardware exists: record the
UTC probe time, session table, API result,
and human observation of the matching URL fragment. For the locked case, arm
control `129` (one attempt after 30 seconds), lock before it fires, then unlock
afterward. This separates the locked launch from an unlock-triggered launch.
Control `128` performs one immediate attempt. Finish by stopping/removing only
`NodeLinkBrowserSpike233`, retaining evidence, and deleting throwaway code once
the answer is known. The pre-existing `spike233` service remains untouched.

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
