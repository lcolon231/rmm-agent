# Dashboard AI assistant — release 1

Authenticated operators can investigate one selected client in a private conversation.
The first acceptance flow asks “Which endpoints are offline?” and returns authorized
endpoint facts, device links, last-seen times, and explicit pagination. Further tools
cover detail/telemetry, hardware/software inventory, retained history and changes,
active monitoring alerts, and patch compliance. No endpoint mutation tools exist.

The dashboard uses its server-managed session through same-origin Next.js routes.
FastAPI owns authorization, encrypted history, admission limits, cancellation, audit,
and an OpenAI Responses provider behind a small replaceable interface. Model and
credentials are deployment configuration; absent configuration fails unavailable.
The feature defaults off and an optional operator ID allowlist narrows pilot access.

Every read, model round trip, and tool execution rechecks the current operator,
token generation, client membership, ownership, and referenced endpoint scope.
Tool arguments are strict schemas. Data is projected onto reviewed fields, scrubbed,
bounded and explicitly treated as untrusted evidence. Tool errors are structured;
answers without successful evidence never become success claims. Source records
are assembled by the server, never trusted from model-generated URLs.

Limits: 4,000 characters per question; 20 conversations per operator; 20 runs per
conversation; one active run per operator; 100 runs/operator/day; six tools/run;
45 seconds/run; 64 KiB provider input; 128 KiB provider response; 12 KiB/tool result;
2,048 output tokens/request; 40,000 reported tokens/run. Fixed 30-day expiry from
conversation creation, with daily deletion by the existing retention sweeper.
History bodies use a dedicated AES-GCM key and identity-bound authenticated data.
Audit retains metadata only and follows existing append-only retention.

UI states: disabled/unconfigured, client selection, private history, loading,
observed evidence, model interpretation, missing/stale data, error, cancel and retry.
Use bounded JSON responses for the initial deployment; cancellation is authoritative
in the database, including across workers. Interrupted runs expire by deadline.
No streaming dependency or persistent in-process job queue is required.

Not included: support chat, endpoint actions, deployment, automatic merge, attachments,
arbitrary SQL/HTTP/shell, arbitrary external providers, or provider-managed history.
