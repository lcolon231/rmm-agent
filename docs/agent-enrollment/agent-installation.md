# Agent installation and enrollment

## Support boundary

Windows is the primary supported platform. Linux and macOS binaries are
development/portability artifacts and do not yet have a supported native
credential keychain integration.

## Requirements

- A release-matched NodeLink agent binary.
- Windows Administrator privileges for service installation.
- A unique temporary enrollment token.
- System time synchronized closely enough for HTTPS and signed-command checks.
- Write access to the chosen configuration directory.

## Network requirements

The agent initiates outbound HTTPS connections to the management origin:

- `POST /api/v1/agents/enroll` (or legacy `/api/v1/enroll`);
- `POST /api/v1/heartbeat`;
- command result and future credential endpoints under `/api/v1`.

Trust the deployment's TLS CA. Never disable TLS verification. HTTP is accepted
by the explicit CLI only for loopback development URLs. Proxy operation through
`HTTPS_PROXY`/`NO_PROXY` needs deployment-specific testing.

## Preferred enrollment methods

The CLI does not accept a plaintext `--token` argument.

### Environment variable

Populate the environment through a secret manager, not interactive shell
history:

```powershell
rmm-agent.exe enroll `
  --server "https://management.example.com" `
  --token-env "AGENT_ENROLLMENT_TOKEN" `
  --config "C:\ProgramData\NodeLink\config.json" `
  --non-interactive
```

On Unix:

```bash
rmm-agent enroll \
  --server "https://management.example.com" \
  --token-env "AGENT_ENROLLMENT_TOKEN" \
  --config "/etc/nodelink/config.json" \
  --non-interactive
```

Unset the variable after the process exits when the deployment platform does
not manage its lifetime automatically.

### Interactive hidden input

```powershell
rmm-agent.exe enroll --server "https://management.example.com"
```

The prompt disables terminal echo. If secure terminal control is unavailable,
the command fails and directs the user to an environment variable, secret file,
or stdin.

### Restricted secret file

```bash
chmod 600 /run/secrets/nodelink-enrollment
rmm-agent enroll \
  --server "https://management.example.com" \
  --token-file /run/secrets/nodelink-enrollment \
  --non-interactive
```

Non-Windows agents reject files accessible by group or other users. Delete the
secret file after enrollment if the secret platform does not mount it
ephemerally.

### Standard input

```bash
secret-manager read nodelink/enrollment | \
  rmm-agent enroll \
    --server "https://management.example.com" \
    --token-stdin \
    --non-interactive
```

Confirm the upstream command does not log output.

## What enrollment writes

Explicit enrollment writes:

- `config.json`: token-free server configuration, mode `0600`;
- `identity.json`: agent ID, per-agent credential, polling policy, and command
  verification keys in the protected identity envelope.

On Windows, `identity.json` is DPAPI protected and its DACL permits only SYSTEM
and Administrators. DPAPI is user-scope: an identity enrolled as an interactive
user cannot be decrypted by a LocalSystem service. For Windows service
deployment, let the installed service perform first enrollment as LocalSystem,
or invoke explicit enrollment in the same service account context.

On Linux/macOS, the identity envelope declares protection `none` and relies on
mode `0600`. This is not a native keychain and remains an accepted development
limitation.

The legacy configuration-based path remains compatible:

```json
{
  "server_url": "https://management.example.com",
  "enrollment_token": "<TEMPORARY_PLACEHOLDER>"
}
```

After successful enrollment, the agent atomically rewrites that file without
the consumed token. Prefer the explicit CLI so plaintext never needs to be
written there.

## Install the Windows service

Use an elevated terminal:

```powershell
rmm-agent.exe install -config "C:\path\to\config.json"
rmm-agent.exe start
```

The graphical installer can collect a one-time token and lets the LocalSystem
service enroll. Installer prompts and silent-install secret-manager integration
remain limited; do not automate GUI fields through logged command lines.

## Verify

```powershell
rmm-agent.exe run -config "C:\ProgramData\NodeLink\config.json" -once
```

Also verify:

- the service is running;
- the agent appears in **Agent inventory**;
- the first heartbeat changes it from pending;
- hostname, environment, site, and labels match the assignment;
- the original token reports the expected use count/status.

Do not print `identity.json`. Use the agent ID and server-displayed fingerprint
for support.

## Retry behavior

Runtime network failures use capped exponential backoff. The explicit `enroll`
command performs one attempt only. If a single-use token was consumed but the
response was lost, inspect inventory/audit and issue a replacement rather than
blindly retrying and creating ambiguous identity.

## Credential renewal and revocation

The server provides an authenticated rotation endpoint and records renewal
events. Automatic, loss-safe renewal is not yet enabled in the Go runtime
because the current bearer protocol cannot recover safely when a rotation
response is lost. Existing credentials therefore have no configured expiry.
Track ENR-001 through ENR-004 before enabling expiry in production.

When the server revokes an agent, heartbeat authentication returns a generic
unauthorized response. The agent retains its protected identity for incident
investigation and retries at capped backoff. Re-enrollment requires removing
the old identity only after the server record is reviewed/revoked.

## Upgrade

1. Verify release checksums and provenance.
2. Stop the service.
3. Replace the binary while preserving config, identity, and replay state.
4. Start the service.
5. Confirm version and heartbeat in the dashboard.

Agents and installers are not yet Authenticode signed. Do not bypass enterprise
execution controls without an approved exception.

## Uninstall

On Windows:

```powershell
rmm-agent.exe stop
rmm-agent.exe uninstall
```

Revoke the server-side agent first. Remove identity/replay files according to
incident-retention policy; uninstalling software alone does not revoke the
credential.

## Troubleshooting

| Error | Action |
|---|---|
| Server URL must use HTTPS | Use the production HTTPS origin; HTTP is loopback-only |
| No token source available | Populate the named environment variable, use a protected file/stdin, or omit `--non-interactive` |
| Token file permissions too broad | Set mode `0600` |
| Enrollment failed / forbidden | Token may be invalid, expired, revoked, exhausted, or claim-restricted |
| Rate limited | Wait for the server `Retry-After` interval |
| Identity already exists | Do not overwrite; review/revoke the existing server identity first |
| DPAPI unprotect failure | Run under the enrolling Windows account or revoke/delete/re-enroll under the service account |
| Repeated unauthorized heartbeat | Agent may be revoked or restored DB state may not contain its credential |

## Security recommendations

- Use single-use tokens expiring within 24 hours.
- Deliver tokens with a secret manager.
- Pre-bind hostname/name/environment when known.
- Never place tokens in URLs, arguments, logs, tickets, or source control.
- Restrict service directories and protect backups.
- Revoke unused tokens immediately after rollout.
- Review failed-enrollment audit events during deployments.
