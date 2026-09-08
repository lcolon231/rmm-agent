# Dashboard AI assistant pilot

Release 1 is read-only. Open **AI assistant**, select a client, and ask “Which
endpoints are offline?” Results contain permission-filtered device links, last-seen
timestamps, observed data and a separately labelled model interpretation. Endpoint
detail pages also link into an investigation with their client and endpoint context.

The assistant covers endpoint search/status, current and recent telemetry,
hardware/software inventory, retained inventory history and latest changes,
open/acknowledged monitoring alerts (including the recorded check definition),
and patch compliance. It uses existing NodeLink status and policy evaluation;
it never initiates a scan or sends an endpoint command. Support chat and command
approval workflows are separate and unchanged.

## Server configuration

Apply migrations using the normal release procedure (`alembic upgrade head` from
`server/`). This release adds **0042**, directly after the verified local head
**0041**. The migration adds two tables and does not rewrite existing endpoint data.
Downgrade drops assistant history, so disable the pilot before any rollback.

All settings below belong to FastAPI's secret/configuration environment. None
belong in a `NEXT_PUBLIC_*` setting or the browser. No new dashboard secret is needed.

| Setting | Default | Pilot configuration |
| --- | --- | --- |
| `ASSISTANT_ENABLED` | `false` | Explicitly `true` for the pilot |
| `ASSISTANT_PROVIDER` | `openai` | Only the OpenAI Responses adapter ships in v1 |
| `ASSISTANT_MODEL` | empty | A model available to the deployment that supports strict function tools and Responses |
| `ASSISTANT_API_KEY` | absent | Dedicated provider credential stored through secure secret management; use the secure OpenAI Platform setup flow when provisioning |
| `ASSISTANT_HISTORY_KEY` | absent | Dedicated base64url-encoded random 32-byte AES-GCM key, including base64 padding |
| `ASSISTANT_PILOT_OPERATOR_IDS` | empty | Comma-separated operator UUIDs; empty enables every authenticated operator who has client access |

No credential was provisioned as part of implementation. Missing model, credential,
or valid history key returns an understandable unavailable state. Other NodeLink
routes do not require provider availability. Disable `ASSISTANT_ENABLED` to stop
new reads and runs; in-flight runs recheck the flag before tools and publication.

The adapter calls the fixed HTTPS OpenAI Responses endpoint, disables redirects
and provider-managed response storage (`store: false`), and registers only the
seven read-only NodeLink functions. There is no arbitrary provider URL, shell,
SQL, HTTP, hosted tool, or MCP option exposed to the model. The interface allows
a future adapter and a deterministic test provider without changing the policy
boundary. See the [official function-calling documentation](https://developers.openai.com/api/docs/guides/function-calling).
Provider-side processing and retention remain governed by the deployment's
provider agreement; `store: false` is not a promise of zero provider retention.

## Limits and storage

- One immutable client and one owning operator per conversation, including for
  platform administrators. Operators cannot read each other's conversations.
- 20 conversations/operator and 20 runs/conversation; one live run/operator and
  100 new runs/operator in a rolling 24 hours. PostgreSQL row locks serialize
  admission across workers. SQLite is supported for deterministic development
  tests; use PostgreSQL for multi-worker pilots.
- Question: 4,000 characters; raw HTTP body: 20,000 bytes. Provider input: 64 KiB;
  provider response: 128 KiB; each tool result: 12 KiB. Oversized evidence is
  rejected explicitly rather than silently represented as complete.
- At most six tool calls and seven model responses/run. A run expires after
  45 seconds; each provider request times out after 20 seconds. Each response is
  limited to 2,048 output tokens. Processing stops once reported cumulative usage
  exceeds 40,000 tokens; a single in-flight response can cross that threshold.
  Configure an additional provider project budget for a monetary ceiling.
- Endpoint, alert and compliance pages contain 25 rows; inventory history contains
  five snapshots. Compliance summaries are explicitly **page summaries**, with
  total scoped endpoints and `has_more`. No fleet-wide extrapolation is supported.
- Context includes up to six previous completed question/answer pairs and at most
  150 inherited endpoint dependencies. Older or oversized context is omitted.
  Each answer retains its inherited access dependencies for later authorization.
- Conversations expire 30 days after creation (not after the last message).
  Expired conversations cannot be read; the existing daily retention sweeper
  erases their encrypted bodies. Recent run admission metadata remains until it
  leaves the 24-hour quota window, then is deleted with conversation metadata.
  This prevents expiry from resetting daily usage limits. New conversation creation also
  sweeps expiry. Sweeper downtime delays physical deletion, not access expiry.
  Account/client removal cascades history deletion at the database level.

Bodies are encrypted with AES-GCM and authenticated against run, conversation,
operator and client IDs. Keep the dedicated key in the deployment secret store;
protect database connections/backups with the deployment's normal encryption and
access controls. There is no keyring migration in v1: retain the key through the
retention/backup window, or deliberately discard old history before rotating it.
A wrong or missing key fails closed. Audit events keep only operator/client/target,
tool, outcome, conversation and run references; their append-only retention remains
unchanged. SQL parameter logging is suppressed, including in debug mode.

## Failure, cancellation and interpretation

The dashboard uses authenticated, same-origin Next.js routes and the existing
server-managed operator session. Client or endpoint permissions, token generation,
disabled accounts, pilot membership and history ownership are rechecked on every
read, every provider round trip and every tool execution. Moving or revoking a
referenced endpoint restricts the entire associated historical answer, including
follow-ups that inherited its context. Already-displayed browser data cannot be
retroactively erased by the server.

Credentials, logged-in users, serial numbers, IP/MAC addresses, inventory error
text, raw logs and command output are omitted. Disclosed strings are bounded and
scrubbed for configured credentials and common secret shapes. Free text can still
contain undiscoverable sensitive information: the UI asks operators not to enter
secrets or personal information. Tool output is untrusted evidence, never authority.
Unknown tools and malformed arguments abort the run before adapter execution.

Failures return fixed safe messages rather than provider error bodies. The server
suppresses model claims if no evidence was collected or a tool failed. Missing
sections, missing comparison snapshots, stale telemetry and unknown/exempt patch
states remain explicit in the evidence. Model prose can still be wrong: device
links and observed data are assembled by the server, and hypotheses should be
verified against those observations. Only server-generated device links are clickable;
model text is rendered as plain React text, without HTML or external links.

Responses are bounded JSON, not streamed. The Next.js route allows 60 seconds and
its backend fetch allows 55 seconds; configure the deployment proxy timeout to
accommodate that window. Cancel records a terminal database state across workers.
An already in-flight provider HTTP request may finish (and incur usage), but no
further tools or answer publication are allowed. A server restart leaves a run
visibly interrupted after its deadline. Refresh history after a transport failure;
reusing the request UUID returns the existing run without starting another one.

## Pilot verification and rollout

1. Keep the flag off, apply migration 0042, and verify ordinary endpoint operations.
2. Configure the dedicated secrets, model and explicit pilot operator IDs through
   the deployment's secret/configuration system. Do not paste credentials into chat.
3. Enable the pilot. Compare offline results, timestamps, missing inventory, alert
   thresholds and patch page summaries against the native dashboard views.
4. Test removal of client membership and endpoint movement between turns, cancellation,
   provider failure, history expiry and the disabled state. Monitor metadata-only
   `assistant.activity` events and provider-side spend/rate limits.
5. Expand the operator allowlist only after a real-provider smoke test confirms
   tool-schema compatibility and answer quality for the chosen model.

Automated tests use a deterministic provider plus HTTP transport fakes and isolated
SQLite fixtures. They do not incur provider usage. Run `pytest tests/test_assistant.py`
and the existing migration, redaction and retention suites from `server/`; from
`dashboard/`, run `npm test`, `npm run lint`, `npm run typecheck`, `npm run build`.
PostgreSQL-specific worker contention and a real-provider smoke test remain pilot
environment checks unless explicitly reported as verified in the implementation report.

The local verification record is in
[`tasks/todo-dashboard-assistant.md`](../tasks/todo-dashboard-assistant.md).
