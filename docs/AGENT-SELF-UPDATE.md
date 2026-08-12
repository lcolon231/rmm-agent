# Signed, staged agent self-update and rollback

Issue #63. This document is the contract: what an operator can publish, which
endpoints a release can reach, what the endpoint does with it, every state the
capability can be in, what happens when each step fails, and the evidence an
operator or auditor can read afterwards.

The short version: a release is signed metadata plus a digest-pinned artifact. A
rollout is staged and stops itself when endpoints fail. An endpoint that
installs a new build proves it works before keeping it, and restores the
previous build on its own when it does not.

## Contents

- [Trust model](#trust-model)
- [Publishing a release](#publishing-a-release)
- [Staged rollout](#staged-rollout)
- [What the endpoint does](#what-the-endpoint-does)
- [Anti-rollback policy](#anti-rollback-policy)
- [Automatic rollback and the canary halt](#automatic-rollback-and-the-canary-halt)
- [Operator-triggered rollback](#operator-triggered-rollback)
- [States and failure behavior](#states-and-failure-behavior)
- [Authorization](#authorization)
- [Audit and operator-visible evidence](#audit-and-operator-visible-evidence)
- [Compatibility and mixed-version fleets](#compatibility-and-mixed-version-fleets)
- [API reference](#api-reference)
- [Recovery runbook](#recovery-runbook)
- [Limits](#limits)
- [Verification](#verification)

## Trust model

Two independent things must be authentic before an endpoint replaces itself:

1. **The instruction and its metadata.** The `agent_self_update` command rides
   the ordinary Ed25519-signed `command-v3` envelope. The signature covers the
   version, channel, platform, artifact URL, artifact digest, artifact size, and
   the anti-rollback floor. The agent verifies that signature — against a key ID
   it already pins — before this feature is entered at all, exactly as it does
   for every other command. There is no separate, weaker path for updates.
2. **The artifact bytes.** The signed metadata pins a SHA-256 digest and an
   exact byte count. The agent streams the download, computes the digest, and
   refuses anything that does not match both. On Windows a release may
   additionally pin an Authenticode signer thumbprint, checked *on top of* the
   digest, never instead of it.

Separately from the wire, publishing produces a **signed manifest**: the same
metadata canonicalized (sorted keys, no whitespace), domain-separated with the
prefix `nodelink-agent-update-manifest:v1:`, and signed with the active Ed25519
signing key. This is the durable publication record. It is stored with its
digest, its signature, and the key ID that produced it, and re-verified on every
release read, so `signature_valid: false` surfaces a key or storage problem
instead of hiding it. The domain separator is what prevents a manifest signature
from ever being replayed as a command signature, or the reverse.

A release is immutable. Version, channel, and platform together are its
identity; republishing that identity is a `409`. To change any signed field, you
publish a new release.

## Publishing a release

`POST /api/v1/agent-updates/releases` (administrator only).

```json
{
  "version": "0.2.0",
  "channel": "stable",
  "platform": "windows/amd64",
  "artifact_url": "https://releases.example/rmm-agent-0.2.0.exe",
  "artifact_sha256": "<64 lowercase hex>",
  "artifact_size_bytes": 12345678,
  "signer_thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
  "min_supported_version": "0.1.0",
  "failure_threshold_percent": 20,
  "min_attempts_before_halt": 5,
  "health_timeout_seconds": 600
}
```

| Field | Meaning |
| --- | --- |
| `version` | `MAJOR.MINOR.PATCH[-prerelease]`. Build metadata (`+build7`) is rejected: two artifacts differing only in build metadata would compare equal, which is not a safe basis for an anti-rollback decision. |
| `channel` | `stable`, `beta`, or `canary`. An endpoint accepts a release only for the channel it locally follows. |
| `platform` | Artifact selector, e.g. `windows/amd64`. One release row describes one platform artifact, so a digest is never ambiguous. |
| `artifact_url` | HTTPS only. Redirects that leave HTTPS are refused at the endpoint. |
| `artifact_sha256` / `artifact_size_bytes` | Both mandatory and both enforced. |
| `signer_thumbprint` | Optional pinned Authenticode signer (Windows). |
| `min_supported_version` | Anti-rollback floor; must not exceed `version`. |
| `failure_threshold_percent` / `min_attempts_before_halt` | The canary halt rule for this release. |
| `health_timeout_seconds` | How long the endpoint gives the new build to report healthy before rolling itself back (60–3600). |

**Publishing targets no endpoint.** A new release is `published` at
`rollout_percent: 0`. Reaching endpoints is a separate, separately audited
decision, so publishing can never be an accidental fleet-wide deployment.

If the signing key is unavailable, publication fails with `503`
`agent_update_signing_unavailable` and nothing is stored. Storing unsigned
metadata and signing later would create a window in which a release exists
without a verifiable publication record.

## Staged rollout

`POST /api/v1/agent-updates/releases/{id}/rollout` with
`{"rollout_percent": 10, "max_dispatch": 200}`.

Each endpoint occupies a **stable bucket** 0–99 derived from
`SHA-256(release_id + ":" + agent_id)`. A stage of *N*% targets buckets `< N`.
Two consequences matter:

- **Widening only ever adds.** An endpoint admitted at 10% keeps the bucket that
  admitted it, so raising to 50% never reshuffles or re-dispatches to endpoints
  that already have an attempt.
- **The canary group differs per release.** An endpoint unlucky enough to be in
  the first wave once is not permanently the fleet's canary.

`rollout_percent` may only increase; lowering it is a `409`
`agent_update_rollout_cannot_shrink`, because buckets are stable and lowering
could not recall an endpoint that already updated.

`max_dispatch` bounds one call, so a jump to 100% on a large fleet is paged
rather than issued as one unbounded burst. The response reports `truncated: true`
when it stopped early; call again to continue.

Before widening, the halt rule is re-evaluated against evidence that arrived
since the last advance. Widening a failing release is exactly what the canary
halt exists to prevent.

### Who is skipped, and why

Every endpoint the stage did not reach is reported as a coded reason with a
count. No hostname or endpoint identifier appears in that histogram.

| Reason | Meaning |
| --- | --- |
| `agent_not_trusted` | Quarantined or revoked. |
| `capability_unsupported` | Has not advertised `agent-self-update-v1`. |
| `platform_unknown` | Never reported an OS/architecture the server can match. |
| `platform_mismatch` | Reported a platform other than the release's. |
| `channel_mismatch` | Follows a different channel. |
| `agent_version_unknown` / `agent_version_uncomparable` | No comparable running build, so the anti-rollback rule cannot be applied. |
| `already_current` | Already running this version. |
| `downgrade_refused` | Running a newer build than the release. |
| `below_min_supported_version` | The release is below its own floor. |
| `envelope_unsupported` | Cannot negotiate `command-v3`, so the metadata could not carry a key-identified signature. |
| `outside_rollout_stage` | Bucket is at or above the current stage. |
| `already_attempted` | Has an attempt row for this release. |

Every one of these is a refusal to act. There is no "assume it is fine" branch.

## What the endpoint does

On receiving a verified `agent_self_update`, the agent
(`agent/internal/selfupdate`):

1. **Re-validates the payload structurally** and fails closed. The server
   validated it before signing; this is the endpoint's independent check, so a
   compromised or buggy server cannot widen the contract.
2. **Enforces platform, channel, and anti-rollback** against the running build.
3. **Downloads** to `<agent dir>/.nodelink-update/staging/`, bounded by the
   signed size (hard ceiling 256 MiB) with at most 5 redirects, none of which may
   leave HTTPS.
4. **Verifies** the SHA-256 and the byte count, then the pinned Authenticode
   signer if the release declares one.
5. **Journals** the attempt (`update-journal.json`, written atomically and
   fsynced), **backs up** the running binary to `.nodelink-update/backup/`,
   digests the backup, and records that digest.
6. **Replaces the binary atomically.** On Windows the running image cannot be
   overwritten but can be renamed, so it is displaced to a `.old-<ts>` name and
   the new binary is renamed into the vacated path. A failure after the
   displacement puts the original back — the executable path is never left
   missing.
7. **Requests a service restart** through a detached helper (this process *is*
   the service, so it cannot stop and start itself inline). The command result
   returns `staged_restart_pending`: the outcome is not yet decided.
8. **On the next start**, before the first check-in, resolves the journal:
   health-check the new build, then either commit it or restore the previous one.

The journal is written *before* every action it authorizes, so an interrupted
download, a crash between staging and the swap, a failed restart, or a build
that never becomes healthy all resolve to either the new build or the previous
known-good build — never to no agent at all.

### The health check

Health is a **completed authenticated check-in**: the new build started, read its
config and protected identity, and the server accepted its credentials. Anything
less is not a working agent. The check must pass within
`health_timeout_seconds`, and at most three starts may observe an
installed-but-unconfirmed build before the attempt is rolled back
unconditionally — a build that crashes before it can report is exactly the case
that bound exists for.

## Anti-rollback policy

The update path only ever moves forward:

- target **equal** to the running build → no-op (`already_current`), success;
- target **older** than the running build → refused (`downgrade_refused`);
- target below the release's own `min_supported_version` → refused
  (`below_min_supported_version`).

Both ends enforce this independently, with parsers that must agree:
`server/app/core/agent_updates.py` and `agent/internal/selfupdate/version.go`.
A replayed release, a resurrected withdrawn build, and a downgrade-shaped
release are all refused by the same rule.

Going *back* to an older build is possible only through the explicit rollback
path below, which restores a binary the endpoint itself retained and digested —
it never downloads an older artifact.

## Automatic rollback and the canary halt

**At the endpoint**, the attempt rolls back automatically when the new build:

| Reason | Trigger |
| --- | --- |
| `health_check_failed` | The check-in did not succeed. |
| `health_check_deadline_exceeded` | `health_timeout_seconds` elapsed first. |
| `health_check_attempts_exhausted` | Three starts without a confirmation. |
| `version_mismatch_after_restart` | The process that came back up is not the new version. |
| `installation_path_changed` | The installation moved under the attempt. |
| `health_check_unavailable` | No health check could be run — fail closed. |
| `restart_request_failed` | The service restart could not even be requested, so the new build would never start. |

A restore refuses a backup whose digest no longer matches what was recorded, so
a tampered retained build is never installed. If the restore itself fails, the
journal goes terminal (`<reason>+restore_failed`) rather than looping.

**At the server**, each resolved outcome is reported to
`POST /api/v1/agents/me/self-update/report` and feeds the halt rule:

> Once at least `min_attempts_before_halt` attempts have **resolved**, halt the
> release if `failed × 100 ≥ failure_threshold_percent × resolved`.

Only resolved attempts count. `rolled_back` and `failed` are failures;
`succeeded` is a success; a dispatched-but-unreported attempt is not evidence
either way, so a slow fleet can neither mask a bad release nor halt a good one.

A halt is **terminal**. It cannot be resumed, because resuming would re-dispatch
the build that caused the failures. Publish a fixed release instead.

## Operator-triggered rollback

`POST /api/v1/agents/{agent_id}/commands` with:

```json
{
  "kind": "agent_update_rollback",
  "payload": {
    "reason": "0.2.0 crashes on start for terminal-server hosts",
    "confirm": true,
    "expected_current_version": "0.2.0"
  }
}
```

`confirm: true` and a 10–256 byte printable reason are mandatory. The optional
`expected_current_version` is a precondition: the endpoint refuses if it is not
running that build, so a rollback issued against a stale view of the fleet does
not fire on the wrong machine.

The endpoint restores the build it retained after its last successful update
(`.nodelink-update/previous.json` names it and its digest), verifies that digest,
installs it atomically, and restarts. With nothing retained, it reports
`no_previous_build` and changes nothing.

`agent_update_rollback` stays dispatchable even for a halted release. Recovery
must work when the rollout has already been condemned — that is when it is
needed most.

By contrast, `agent_self_update` **cannot** be dispatched through the generic
command endpoint. It returns `409 agent_self_update_requires_release`, because
an update must be attributable to a published, signed release and countable by
that release's halt rule; a hand-rolled one would be neither.

## States and failure behavior

### Release states

| State | Meaning | Dispatches? |
| --- | --- | --- |
| `published` | Signed metadata exists; no endpoint targeted yet | No (until a rollout advance) |
| `rolling` | Staged rollout active at `rollout_percent` | Yes |
| `paused` | Operator paused; in-flight attempts still report | No |
| `halted` | Operator or canary halt; terminal | No, ever |
| `completed` | Rollout finished | No |

### Attempt states

`dispatched` → `staged` → (`succeeded` | `rolled_back` | `failed`).

### Endpoint result statuses

Returned as JSON evidence in the command's stdout:

`invalid`, `already_current`, `downgrade_refused`, `channel_mismatch`,
`platform_mismatch`, `update_in_progress`, `download_failed`, `tampered`,
`signature_mismatch`, `stage_failed`, `install_failed`,
`staged_restart_pending`, `restart_failed`, `rolled_back`, `succeeded`,
`failed`, `unsupported`, `no_previous_build`.

Nothing in this evidence carries the artifact URL, a credential, or endpoint
prose — only versions, digests, a coded status, and a coded reason.

### Every failure, and what it leaves behind

| Failure | Result | Endpoint left running |
| --- | --- | --- |
| Payload malformed or unknown field | `invalid` | Current build, untouched |
| Wrong channel or platform | `channel_mismatch` / `platform_mismatch` | Current build, untouched |
| Downgrade or below floor | `downgrade_refused` | Current build, untouched |
| Download interrupted or truncated | `download_failed` | Current build; partial file removed |
| Digest or size mismatch | `tampered` | Current build; artifact removed |
| Authenticode mismatch | `signature_mismatch` | Current build; artifact removed |
| Another attempt in flight | `update_in_progress` | Current build, untouched |
| Backup or journal write failed | `install_failed` | Current build (restored if needed) |
| Atomic replace failed | `install_failed` | Current build, restored |
| Restart could not be requested | `restart_failed` | Previous build, restored |
| New build unhealthy after restart | `rolled_back` | Previous build, restored |
| Restore itself failed | `failed` | Whatever is on disk; reported loudly, no loop |

## Authorization

Publishing, staging, pausing, halting, reading releases and attempts, and
dispatching a rollback are all **administrator-only**. Replacing the code running
on every managed endpoint is the broadest trust boundary in the product, and
`operator` is not sufficient for any part of it. The per-request role check
enforces this (`require_role(OperatorRole.admin)`), not the route path.

Beyond the role check, dispatch additionally requires:

- the agent advertises `agent-self-update-v1` (only Windows builds do, because
  committing an update needs the managed service restart the SCM provides);
- the agent's trust state is `active`;
- the agent negotiated `command-v3`.

The outcome-report endpoint is authenticated as the **agent**, not an operator.

## Audit and operator-visible evidence

| Action | When |
| --- | --- |
| `agent_update.release_published` | A signed release is published |
| `agent_update.rollout_advanced` | A stage is widened |
| `agent_update.dispatched` | One endpoint is targeted |
| `agent_update.rollout_paused` / `.rollout_resumed` | Operator pause/resume |
| `agent_update.rollout_halted` | Operator or canary halt |
| `agent_update.halt_reason_recorded` | The operator's halt justification |
| `agent_update.rollback_dispatched` | An operator-requested rollback |
| `agent_update.outcome_reported` | An endpoint's post-restart resolution |

Field-level schemas are in [`AUDIT-EVENTS.md`](AUDIT-EVENTS.md) and enforced by
the fail-closed redaction boundary. Every stored field is a bounded, non-secret
build or policy identifier — versions, digests, coded reasons, counts — which is
exactly what makes an unexpected update or an unexplained rollback auditable.
The artifact source URL is operator prose, so only its SHA-256 is recorded;
operator halt and rollback reasons are prose too and are stored digest-only.

`GET /agent-updates/releases/{id}` returns live counters (`dispatched`,
`staged`, `succeeded`, `rolled_back`, `failed`, `resolved`, `failure_percent`),
and `.../attempts` returns the per-endpoint record including the coded failure
reason and the health-check attempt count.

## Compatibility and mixed-version fleets

- **Server ← agent.** The endpoint reports `update_channel` on enroll and every
  heartbeat. An absent value leaves the stored channel untouched, so an older
  agent is never silently moved between channels; `NULL` is treated as `stable`.
- **Agent ← server.** An agent that has not advertised `agent-self-update-v1` is
  never targeted, and there is no fallback path that would reach it anyway.
- **Database.** Alembic revision `0035` is additive: two new tables, one nullable
  column, and new enum values. An older application ignores all of it and never
  dispatches the new kinds, so a mixed-version deployment degrades to
  "self-update unavailable" rather than misbehaving. PostgreSQL enum values
  cannot be removed in place; see [`ROLLBACK.md`](ROLLBACK.md).
- **Non-Windows agents** do not advertise the capability at all, so the server
  keeps failing closed rather than dispatching an update that cannot commit.

## API reference

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/agent-updates/releases` | admin | Publish a signed release |
| `GET` | `/api/v1/agent-updates/releases` | admin | List releases (optionally by channel) |
| `GET` | `/api/v1/agent-updates/releases/{id}` | admin | Release detail, manifest, signature validity, stats |
| `GET` | `/api/v1/agent-updates/releases/{id}/attempts` | admin | Per-endpoint evidence |
| `POST` | `/api/v1/agent-updates/releases/{id}/rollout` | admin | Advance the stage and dispatch |
| `POST` | `/api/v1/agent-updates/releases/{id}/pause` | admin | Stop targeting new endpoints |
| `POST` | `/api/v1/agent-updates/releases/{id}/resume` | admin | Resume a paused release |
| `POST` | `/api/v1/agent-updates/releases/{id}/halt` | admin | Halt permanently |
| `POST` | `/api/v1/agents/me/self-update/report` | agent | Report a post-restart outcome |
| `POST` | `/api/v1/agents/{id}/commands` (`agent_update_rollback`) | admin | Roll one endpoint back |

## Recovery runbook

**A release is failing across the fleet.**

1. `POST .../halt` with a reason (the canary rule may already have halted it).
2. `GET .../attempts` to see which endpoints failed and why.
3. Endpoints that rolled back are already on their previous build — confirm via
   `observed_version` on the attempt row and the endpoint's reported version.
4. Endpoints still on the bad build: dispatch `agent_update_rollback` to each.
5. Publish a fixed release. Halted releases are never resumed.

**An endpoint is stuck on a bad build and cannot check in.** Self-update cannot
help — it needs a working check-in to be dispatched or to health-check. Use the
installer upgrade path documented in
[`INSTALLER-E2E-WINDOWS.md`](INSTALLER-E2E-WINDOWS.md). The retained previous
build is on disk under `.nodelink-update/backup/` with its digest in
`.nodelink-update/previous.json`.

**The stored manifest no longer verifies** (`signature_valid: false`). The
signing key that produced it is missing or retired from the keyring, or the row
was altered. Check [`KEY-ROTATION.md`](KEY-ROTATION.md); do not roll the release
out further until it is explained.

## Limits

| Bound | Value |
| --- | --- |
| Artifact size | Signed `size_bytes`, hard ceiling 256 MiB |
| Download redirects | 5, HTTPS only |
| Download timeout | 30 minutes |
| Health-check timeout | 60–3600 s (default 600) |
| Health-check starts before forced rollback | 3 |
| Update command lifetime | 6 hours |
| Endpoints dispatched per rollout call | 1–1000 (default 200) |
| Failure threshold | 1–100 % (default 20) |
| Concurrent attempts per endpoint | 1 |

## Verification

- `agent/internal/selfupdate/selfupdate_test.go` — payload validation, version
  ordering, anti-rollback, channel/platform refusal, tampered artifact,
  interrupted download, oversize body, staging and atomic replace, the in-flight
  guard, restart failure, health-check commit and every rollback trigger, the
  interrupted-before-install path, and operator rollback including the
  tampered-backup refusal.
- `agent/internal/selfupdate/selfupdate_windows_test.go` — the Windows displace/
  rename swap against a held image, restore-on-failure, and pruning.
- `agent/internal/protocol/command_test.go` — the capability is advertised only
  on Windows.
- `server/tests/test_agent_self_update.py` — manifest signing and tamper
  detection, admin-only authorization, release immutability, metadata
  validation, targeting and skip reasons, deterministic bucket staging, paging,
  quarantine, refusal of out-of-band dispatch, rollback validation, the outcome
  report, and the automatic canary halt.
- `server/tests/test_redaction.py` — every audit action has an exact schema, is
  documented, and cannot persist a secret.
- `server/tests/test_migrations.py` — revision `0035` upgrades cleanly and stays
  forward-only.
