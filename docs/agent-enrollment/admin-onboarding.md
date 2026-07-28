# Administrator onboarding

## Required role

NodeLink retains its existing role names:

| UI capability | API role | Enrollment access |
|---|---|---|
| Super Administrator | `admin` | Create/revoke all tokens, view/revoke all agents, view audit |
| Administrator | `operator` | Create/revoke tokens, view agents and audit |
| Viewer | `readonly` | View tokens, agents, and audit; no changes |

Roles are currently deployment-wide. `Client` and `Site` organize assignments
but are not security tenants. Do not grant `operator` to a customer-specific
administrator until operator-to-client membership and server-side tenant
scoping are implemented.

## Sign in

1. Open the NodeLink dashboard over HTTPS.
2. Sign in with an operator account.
3. Open **Administration**, then **Agent enrollment**.
4. Verify the role shown in the upper-right corner.

The dashboard keeps the operator JWT in an HTTP-only, same-site cookie. It does
not use local storage. If the session cannot be verified, protected enrollment
data is not loaded.

## Create and assign a token

1. Select **Enrollment tokens** and **Create token**.
2. Enter a clear name and optional purpose.
3. Select the organization/site. This assignment is mandatory.
4. Optionally provide:
   - an assigned operator ID;
   - environment;
   - exact hostname restriction;
   - exact agent-name restriction;
   - up to 20 labels;
   - internal notes.
5. Select an expiration. The server requires a future time and caps it at 30
   days. Prefer 24 hours or less.
6. Select maximum uses. The default is one. Use a reusable token only for a
   controlled automated rollout; the deployment cap is 100.
7. Select **Create enrollment token**.

Hostname, agent name, and environment restrictions compare without letter-case
sensitivity. Hostname is a claim supplied by the installer, not a
cryptographic identity proof.

## Copy and distribute the token

The success view is the only place the plaintext appears.

1. Select **Copy token**.
2. Put it directly into an approved secret manager or protected delivery
   channel.
3. Select **Done — hide token** when finished.

Do not send the token through ordinary email/chat, place it in tickets, commit
it, put it in a URL, paste it into a shell command, or store it in browser
storage. If the value is lost, revoke the record and create a replacement.

The displayed install command uses `--token-env` and never embeds the token.

## Revoke a token

1. Open **Enrollment tokens**.
2. Locate the active token by name, assignment, or masked prefix.
3. Select **Revoke token**.
4. Enter an incident/change reason and confirm.

Revocation is immediate for subsequent online redemption. Existing agents
enrolled by that token keep their separate credentials. Revoke those agents
individually when appropriate.

NodeLink does not permanently delete tokens; durable history is required for
audit and incident investigation.

## View and revoke agents

The **Agent inventory** shows identity, hostname, assignment metadata, platform,
runtime/trust state, last heartbeat, and credential fingerprint.

Open an agent to review:

- assigned metadata and labels;
- enrollment token ID;
- credential fingerprint and issuance time;
- heartbeat and trust state;
- agent-specific audit events.

Only `admin` can permanently revoke an agent credential:

1. Open the agent.
2. Select **Revoke agent**.
3. Enter a reason and confirm.

The bearer credential immediately stops authenticating. Outstanding commands
are expired. Revocation is terminal; re-enrollment creates a new identity.

## Review audit logs

Open **Audit log** and filter by:

- token creation or revocation;
- successful or failed enrollment;
- agent credential renewal;
- agent revocation.

Events include non-secret IDs, actor, source IP when available, timestamp, and
hash-chain sequence. Token plaintext, token hashes, agent credentials, private
keys, notes, and request bodies are excluded.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Create button unavailable | Viewer role | Ask an administrator to perform the change |
| Site list empty | No Client/Site records | Create the organization and site first |
| Expiration rejected | Past time or more than 30 days | Choose a future time inside policy |
| Enrollment rejected | Invalid, expired, revoked, exhausted, or restricted token | Check masked token metadata and agent claims; create a replacement if needed |
| `429` response | Source exceeded enrollment limit | Wait for `Retry-After`; investigate repeated failures |
| Agent never appears | Installer could not reach API or response was lost | Review failure audit, endpoint logs, proxy/TLS, then issue a new token |
| Agent shows pending | Enrollment succeeded but no heartbeat arrived | Check service status, credential access, egress, and server URL |
| Revoke fails | Role is insufficient or state already changed | Verify `admin` role and refresh the record |

Never ask an installer to paste the token into a support transcript. Use the
token ID or masked prefix.
