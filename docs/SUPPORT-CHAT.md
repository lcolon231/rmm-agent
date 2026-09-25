# Endpoint support chat

Endpoint support chat lets the person at a managed Windows endpoint start a text
conversation with a technician, and lets the technician answer from the
dashboard. It shipped across issues #233–#237 (`v0.1.9`–`v0.1.11`, plus the
governance in #237). The design record is
[`../specs/SPEC-support-chat.md`](../specs/SPEC-support-chat.md); this document
describes shipped behavior.

It is deliberately **not** remote control, not an interactive shell, not a
ticketing system, and not operator-to-operator chat. The chat channel carries
text only and cannot trigger any endpoint action.

## Flow

1. The user activates the NodeLink Support tray icon (or runs `rmm-agent chat`).
   Both send one parameterless "open chat" message to the agent service over a
   local named pipe.
2. The service calls `POST /api/v1/support/agent/conversations` with its own
   agent credential. The server opens (or reuses) the endpoint's single open
   conversation, mints a chat token, and returns a URL.
3. The service launches the user's default browser in their interactive session
   at that URL. The token rides in the URL **fragment**, so it never reaches
   access logs or a `Referer` header, and it never crosses the pipe.
4. The end-user page shows the recording and retention notice. The composer is
   disabled until the user acknowledges it.
5. Technicians see the conversation on the dashboard's Support Chat page with an
   unread badge, reply, and close it.

A technician can also start a conversation from the endpoint's detail page. The
server records the request and the agent opens the browser on its next heartbeat
(`chat_launch_requested`). This path requires the `support-chat-launch-v1`
capability, which only agents that act on the heartbeat field advertise, so the
button never lights up for an agent that cannot honor it.

## Threat model and authorization

| Surface | Authorized by | Enforced claim |
|---|---|---|
| Local named pipe `\\.\pipe\nodelink-agent-chat` | Pipe ACL: SYSTEM and `INTERACTIVE` only; `PIPE_REJECT_REMOTE_CLIENTS` | A logged-on user of this machine asked for a chat. The message has no parameters, so a local caller cannot choose the agent, conversation, or URL |
| Agent router `/api/v1/support/agent/...` | The agent's existing bearer credential; trusted agents only | The conversation belongs to that endpoint |
| Endpoint router `/api/v1/support/chat/...` | The chat token alone | The browser holds a live credential for exactly one conversation |
| Operator router `/api/v1/support/...` | Operator session + tenant membership (`client_operator` to reply, close, or launch) | The technician can already see that endpoint. Cross-tenant access returns 404, never 403 |

The chat token is the only new credential this feature adds. It is
`secrets.token_urlsafe(32)` (or, for a technician launch, an HMAC-derived value
that the heartbeat can reconstruct). Only its SHA-256 is stored, it is compared
in constant time, it is scoped to one conversation, it expires after
`support_chat_token_ttl_seconds`, and it is rate-limited per token. Closing a
conversation, whether by a technician or the idle sweep, clears the stored hash,
so the old URL stops working immediately. Quarantining or revoking the endpoint
also stops its chat tokens from working.

Message bodies pass through `redaction.scrub_text` before they are stored. Only
the scrubbed text is stored, so a credential pasted into chat never reaches the
database in plaintext.

The feature is Windows-only. Non-Windows agent builds compile, report
`ErrUnsupported`, and do not advertise the capabilities.

## Bounds

All of these are enforced by the server.

| Bound | Setting | Default |
|---|---|---|
| Message body bytes | `support_chat_max_message_bytes` | 4096 (max 4096) |
| Messages per conversation | `support_chat_max_messages` | 500 (max 500) |
| Open conversations per endpoint | `support_chat_max_open_per_agent` | 1 (max 1) |
| Chat token lifetime | `support_chat_token_ttl_seconds` | 900 (60–900) |
| Idle auto-close | `support_chat_idle_close_seconds` | 3600 (min 60) |
| Message body retention after close | `support_chat_retention_days` | 30 (`0` disables pruning) |

## Idle close

The offline sweep in `core/tasks.py` runs every heartbeat interval. It closes
open conversations with no message for `support_chat_idle_close_seconds`. The
candidates come from a single query on the `(status, closed_at)` index. Each
close invalidates the token and records a `support_chat.closed` audit event
with `reason = "idle"`.

The sweep skips a conversation whose latest message is from the end user. That
conversation is a request still waiting for a technician, and closing it would
drop the request and block the late reply that technicians are allowed to send.
The technician's reply restarts the idle clock, and the conversation closes
normally once the end user goes quiet after it. From the end user's side, a
conversation past the idle window is already treated as closed: the page shows
it closed and refuses new messages. Opening chat again starts a fresh
conversation and closes the idle one, which is also audited with
`reason = "idle"`. Otherwise an unanswered request stays in the technician's queue until someone
answers or closes it.

## Retention

Chat keeps two kinds of data with different lifetimes:

| | Regulatory treatment | NodeLink |
|---|---|---|
| Message bodies: incidental PHI, not a designated record set | No minimum; §164.502(b) minimum-necessary favors less | Deleted `support_chat_retention_days` (default **30**) after the conversation closes |
| Lifecycle audit events: §164.312(b) audit controls, §164.316 documentation | Effectively six years | Never pruned, like all audit data ([`RETENTION.md`](RETENTION.md)) |

The retention sweep (`retention.prune_expired`) deletes the messages of
conversations **closed** before the cutoff, then deletes those empty
conversation rows. It never touches an open conversation, however old. Message
bodies never enter the audit chain, so the chain can still prove that a
conversation happened, who joined it, and when and why it closed after the
transcript is gone. Hash-chain and anchor verification are unaffected.

**Why 30 days.** HIPAA sets no retention period for PHI. The widely cited six
years comes from §164.316(b)(2)(i) and §164.530(j)(2), which cover *required
documentation* (policies, procedures, and records of required actions and
assessments), not PHI in general. Medical-record retention is state law. Thirty
days is a **minimum-necessary engineering choice, not a regulatory
requirement**: nothing requires keeping transcripts longer, and every day they
are kept is in scope for breach notification under §§164.400–414. It remains a
setting so a deployment with a state-law or contractual reason can raise it
deliberately. This is engineering rationale, not legal advice; confirm with
counsel before a pilot.

## Consent notice

Before the first message, the end-user page shows the recording and retention
notice and requires an explicit acknowledgment. The acknowledgment is recorded
as a `support_chat.notice_acknowledged` audit event carrying the notice version.
Reopening chat in a new browser requires a new acknowledgment, and changing the
wording (`support_chat_notice_version`) can be told apart in the audit record.

**The notice is a recording and monitoring disclosure. It is not a HIPAA
authorization.** The person typing is almost always a workforce member at their
own workstation, not a patient. The notice is governed by state recording law
and employment policy, and HIPAA does not require it.

## Audit events

Every event carries the endpoint's `agent_id`, the `conversation_id`, and the
conversation's `message_count`. No event carries a message body, a subject, or
a chat token. The full field contract is in [`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

| Action | When | Actor |
|---|---|---|
| `support_chat.opened` | A new conversation is created (`opened_by`: `end_user` or `technician`) | `agent:<id>` or the technician |
| `support_chat.token_minted` | A chat token is issued (`reason`: `open`, `refresh`, or `technician_launch`, with `token_expires_at`) | Agent, end user, or technician |
| `support_chat.notice_acknowledged` | The end user acknowledges the notice (`notice_version`) | `support_chat:end_user` |
| `support_chat.technician_joined` | A technician's first reply in a conversation | The technician |
| `support_chat.closed` | A technician closes it (`reason = "operator"`) or it goes idle (`reason = "idle"`) | The technician or `system` |

The end user is authenticated only by the conversation-scoped token, so the
chain records the role (`support_chat:end_user`) rather than an identity it
cannot prove. The endpoint's `agent_id` and the source IP identify the machine.

## Out of scope

- Attachments, images, and file transfer.
- Queues, SLAs, priorities, and assignment routing.
- Including chat transcripts in evidence bundles or packages. Making a
  transcript citable evidence would change its retention and needs its own
  design.
- An operator-triggered purge of a single conversation.
- Per-tenant retention periods (#88).
- A native chat window. The chat page is a browser tab until Authenticode
  signing lands and a GUI dependency can be reconsidered.
