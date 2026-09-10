# Operator scripts

Operator-side PowerShell that talks to the management API. These are **not**
script-library entries: nothing here is dispatched to an endpoint. They exist
because parts of the monitoring contract are API-only — the dashboard states
outright that "an operator can create the first policy through the API".

Both take an optional `-BaseUrl` and default to the current deployment:

```powershell
.\assign-offline-policy.ps1 -BaseUrl https://your-backend.example.com
```

## Authentication

Both sign in with email + password and, when a second factor applies, complete
it with a **single-use recovery code**. WebAuthn needs a browser and an
authenticator, so it cannot be driven from a script.

`deep-diagnose.ps1` caches the resulting bearer at
`%LOCALAPPDATA%\NodeLink\operator-token.txt` so repeated runs do not spend a
recovery code each time. That path is deliberately outside the repository: it
holds a live operator credential. Delete it when you are done.

If scripted access becomes routine, set `MFA_EMAIL_CODE_POLICY=fallback_only`
and enrol the email factor, so these flows cost a mailed code rather than a
recovery code.

## assign-offline-policy.ps1

Creates a global-scoped monitoring policy carrying one `offline` check.

Offline alerting has **two independent gates**, and both must be satisfied
before anyone is told an endpoint has stopped reporting:

1. An alert delivery provider is configured (`EMAIL_ALERT_PROVIDER`). With it
   disabled, `_sweep_once` still flips endpoint status and writes an
   `agent.offline` audit event, but nothing is delivered.
2. An `offline` check is assigned. `evaluate_offline_checks` skips every check
   whose type is not `offline`, so an endpoint with no such check produces no
   alert even when the server already knows it is offline.

A deployment satisfying neither ran for 27 days with an endpoint dark and no
one aware of it.

The script refuses to create a second global offline policy if one exists.

Defaults: warn above 600s since last heartbeat, critical above 1800s, evaluated
every 300s, with `raise_samples: 2` so a reboot does not page anyone. That
debounce means a real alarm lands roughly 15 minutes after an endpoint goes
quiet, not immediately.

## deep-diagnose.ps1

Answers why an alert did not arrive, by checking each link rather than guessing
at one. Per active agent it reads `/monitoring/effective-policy` and
`/monitoring/results`.

| Output | Diagnosis |
| --- | --- |
| no offline check resolves | policy is not reaching the agent |
| check resolves, no results | sweeper not running or not evaluating |
| results exist, status `ok` | threshold wrong; value under the critical bound |
| results `critical`, no alert | alert creation is the broken link |

Two things worth knowing when reading the output:

- `_sweep_once` evaluates offline checks only for agents whose `trust_state` is
  `active`. A revoked or quarantined agent is skipped entirely and can never
  alert. Revocation is terminal — the endpoint must re-enrol.
- A maintenance window suppresses `opened` and `reopened` events, so an alert
  can be raised and still send no mail.

## Enumerating stranded endpoints

Sort by `last_seen_at`, never by reported agent version. Per #179 a version only
refreshes on a successful authenticated heartbeat, so a stranded endpoint keeps
displaying the last version it managed to report. A version-based sweep is
stale precisely on the endpoints you are looking for, and the fleet looks more
current than it is.
