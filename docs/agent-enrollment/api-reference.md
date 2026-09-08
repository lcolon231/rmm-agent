# Agent enrollment API reference

All application routes use `/api/v1`. Examples contain placeholders only.
Production requests must use HTTPS and JSON request bodies. Enrollment tokens
must never be sent in a query string.

## Authentication and authorization

- Management: `Authorization: Bearer <OPERATOR_JWT>`
- Agent after enrollment: `Authorization: Bearer <AGENT_CREDENTIAL>`
- Enrollment: temporary token in JSON body

Role mapping:

- `admin`: all listed operations;
- `operator`: token create/revoke plus reads;
- `readonly`: reads only.

Roles are currently global. `401` means authentication failed; `403` means the
authenticated role or enrollment credential is not accepted.

## Enrollment tokens

### `POST /api/v1/enrollment-tokens`

Minimum role: `operator`.

```json
{
  "site_id": "<SITE_ID>",
  "name": "Tampa rollout",
  "description": "One endpoint installation",
  "assigned_user_id": null,
  "environment": "production",
  "hostname_restriction": "server01.example.local",
  "agent_name_restriction": "server-agent-01",
  "labels": ["windows", "tier-1"],
  "expires_at": "2026-07-28T12:00:00Z",
  "max_uses": 1,
  "notes": "Internal placeholder note"
}
```

`expires_at` defaults to 24 hours when omitted by an API client, but the
dashboard requires an explicit selection. Maximum expiry is 30 days; maximum
uses is 100.

Creation response includes metadata plus:

```json
{
  "id": "<TOKEN_ID>",
  "token": "<PLAINTEXT_RETURNED_ONCE>",
  "masked_token": "nlenr_abcd••••••••",
  "status": "active",
  "use_count": 0
}
```

No other endpoint returns `token`.

### `GET /api/v1/enrollment-tokens`

Minimum role: `readonly`.

Query:

- `page` (default 1), `page_size` (1–100);
- `search`;
- `status`: `active`, `used`, `expired`, `revoked`;
- `organization_id`, `site_id`;
- `sort`: `created_at`, `expires_at`, `name`, `status`, `use_count`;
- `direction`: `asc`, `desc`.

Response:

```json
{
  "items": [
    {
      "id": "<TOKEN_ID>",
      "masked_token": "nlenr_abcd••••••••",
      "name": "Tampa rollout",
      "organization_id": "<ORGANIZATION_ID>",
      "organization_name": "Example Organization",
      "site_id": "<SITE_ID>",
      "site_name": "Tampa",
      "max_uses": 1,
      "use_count": 0,
      "status": "active",
      "expires_at": "2026-07-28T12:00:00Z"
    }
  ],
  "page": 1,
  "page_size": 25,
  "total": 1
}
```

### `GET /api/v1/enrollment-tokens/{id}`

Minimum role: `readonly`. Returns safe metadata, never plaintext/digest.

### `POST /api/v1/enrollment-tokens/{id}/revoke`

Minimum role: `operator`.

```json
{"reason": "Installer access window closed"}
```

Revocation is idempotent. Permanent deletion is intentionally not available.

## Agent enrollment

### `POST /api/v1/agents/enroll`

Alias retained for existing agents: `POST /api/v1/enroll`.

Rate limit: default 10 attempts per source IP per 60 seconds. A block returns
`429` and `Retry-After`.

```json
{
  "enrollment_token": "<TEMPORARY_TOKEN>",
  "agent_name": "server-agent-01",
  "hostname": "server01.example.local",
  "agent_version": "1.0.0",
  "operating_system": "Windows",
  "os_version": "Server 2025",
  "architecture": "x86_64",
  "environment": "production",
  "site": "Tampa",
  "public_key": null,
  "supported_command_envelope_versions": ["command-v3"]
}
```

`os` remains accepted for old clients. `public_key` is accepted as a bounded
future-compatibility field but is not yet used to issue a certificate.

Success:

```json
{
  "agent_id": "<AGENT_ID>",
  "agent_token": "<AGENT_CREDENTIAL_RETURNED_ONCE>",
  "credential_expires_at": null,
  "heartbeat_interval_seconds": 60,
  "api_base_url": "https://management.example.com",
  "configuration_metadata": {
    "organization_id": "<ORGANIZATION_ID>",
    "site": "Tampa",
    "environment": "production",
    "labels": ["windows", "tier-1"]
  },
  "command_envelope_version": "command-v3",
  "command_signing_key_id": "default",
  "command_public_key": "<PUBLIC_KEY_PEM>",
  "command_public_keys": {}
}
```

The current compatibility credential is a per-agent bearer. It is not a shared
secret. The target signed credential design remains open.

Failures deliberately avoid sensitive detail:

| Status | Code | Meaning |
|---|---|---|
| `403` | `enrollment_rejected` | Invalid, expired, revoked, exhausted, restricted, or raced token |
| `409` | `no_common_command_envelope_version` | Agent/server command contract incompatible |
| `422` | FastAPI validation | Bounded request schema invalid |
| `429` | `enrollment_rate_limited` | Source exceeded window |

### `POST /api/v1/agents/credentials/renew`

Authentication: current agent credential. Rotates the per-agent bearer and
returns the new plaintext once. The previous value remains valid only through
the configured short overlap, allowing a lost response to retry.

```json
{
  "agent_id": "<AGENT_ID>",
  "agent_token": "<NEW_AGENT_CREDENTIAL>",
  "credential_expires_at": "2026-09-02T20:00:00Z",
  "overlap_expires_at": "2026-09-01T20:10:00Z",
  "credential_generation": 2
}
```

The agent automatically renews at the credential lifetime midpoint and saves
the response before adopting it in memory.

### `POST /api/v1/agents/credentials/reattach`

Authentication: the still-current bearer after its normal lifetime expired.
Only an `active` agent within `AGENT_CREDENTIAL_REATTACH_WINDOW_SECONDS` may
exchange it; ordinary agent APIs still reject it. The request and successful
response have the same shape as renewal. The operation rotates immediately and
is audited as `agent.credential_reattached`.

Unknown, outside-window, quarantined, revoked, and overlapped-out credentials
all receive the same `401 Invalid agent token`. The short previous-token overlap
is accepted only so a lost reattach response can be retried safely.

### `POST /api/v1/heartbeat` — reported agent version

Authentication: current agent credential. Every beat may carry the running
build so an in-place upgrade refreshes the stored version on the next
successful check-in — no re-enrollment, no new token, and no inventory upload.

```json
{
  "agent_version": "0.1.4",
  "cpu_percent": 4.5,
  "supported_command_envelope_versions": ["command-v3"]
}
```

The server updates `Agent.agent_version` only when the reported value differs
from the stored one, and records a single `agent.version_changed` audit event
carrying `previous` and `current`. A lower version is recorded exactly like a
higher one: a rollback is fleet state an operator needs to see, not an anomaly
to hide. Steady-state beats that repeat the same version write nothing.

Compatibility policy for the field:

| Reported value | Behavior |
|---|---|
| Absent | Accepted; the stored version is left untouched (agents built before the field existed keep beating normally) |
| Present and well formed | Stored when changed; ignored when identical |
| Empty or whitespace | `422` — a build that reports nothing is a defect, not a silent no-op |
| Longer than 50 characters | `422` — the value is bounded to the stored column width |
| Malformed (anything outside `^[0-9A-Za-z][0-9A-Za-z.+_-]*$`) | `422` |

A rejected beat changes no stored state. Quarantined agents perform a minimal
check-in only, so they cannot move the recorded version; a revoked credential
fails authentication with `401` before the body is considered.

## Agents

### `GET /api/v1/agents`

Minimum role: `readonly`. Returns enrolled agent metadata, trust/runtime state,
assignment, enrollment token ID, fingerprint, and credential lifecycle fields.
Never returns the credential verifier.

### `GET /api/v1/agents/{id}`

Minimum role: `readonly`. Returns one agent record.

### `POST /api/v1/agents/{id}/revoke`

Minimum role: `admin`.

```json
{"reason": "Device retired"}
```

Revocation is terminal and also expires outstanding work.

## Dashboard summary and audit

### `GET /api/v1/enrollment-dashboard`

Minimum role: `readonly`. Returns total/active/offline/revoked agent counts,
active/expired token counts, recent agents, and failed enrollments in the last
24 hours.

### `GET /api/v1/audit/events`

Minimum role: `readonly`.

Filters:

- `event_type`;
- `actor`;
- `agent_id`;
- `organization_id`;
- `date_from`, `date_to`;
- `page`, `page_size`.

Responses exclude event hashes and secrets but include sequence, references,
source IP, and hash-bound safe detail.

## Health and metrics

- `GET /healthz`: process liveness.
- `GET /readyz`: database connectivity readiness.
- `GET /metrics`: Prometheus text with process-local counters for enrollment
  success/failure, token create/revoke, credential renewal, and agent revoke,
  plus database-backed current agent-status gauges.

Metrics contain no IDs or secrets.

## Common error behavior

```json
{"detail": {"code": "enrollment_rejected", "message": "Enrollment failed"}}
```

Administrative validation may return a short policy message. Internal
exceptions and sensitive request bodies are not returned. Dashboard
same-origin handlers further translate errors into user-safe feedback.

## Example placeholder workflow

```bash
# Administrator obtains <TEMPORARY_TOKEN> from the one-time creation response.
# A secret manager supplies the environment variable without shell history.
rmm-agent enroll \
  --server "https://management.example.com" \
  --token-env "AGENT_ENROLLMENT_TOKEN" \
  --non-interactive
```

Then verify `<AGENT_ID>` in inventory and revoke the unused token window.
