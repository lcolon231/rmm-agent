# Administrative sessions and break-glass access

Issue #69. Server-side operator sessions with inventory, individual revocation,
idle and absolute lifetimes, and device context — plus pre-provisioned
break-glass credentials for the case where the authentication controls fail
closed on the operator.

**What this is not.** A control and evidence capability. It is not a compliance
claim. Nothing here applies to *agent* authentication, which uses the separate
bearer-credential mechanism in `docs/agent-enrollment/`.

---

## 1. Why sessions became rows

Before this, an operator session was a pure JWT: stateless, cheap, and opaque.
The only revocation lever was `Operator.token_generation`, which ends **every**
session that operator has. That is enough to stop an incident and useless for
investigating one — you could not answer "where is this account signed in from",
and you could not close one suspicious session without signing the person out of
everything, including the session they were using to investigate.

`operator_sessions` makes each session a row. The token carries its id in a
signed `sid` claim, and every authenticated request re-checks the row.

**The cost is honest:** one indexed primary-key read on every authenticated
request, plus a bounded write to keep `last_seen_at` fresh. The write is skipped
unless the stored value is already stale, so a busy session does not generate a
database write per request. See
`ADMIN_SESSION_LAST_SEEN_WRITE_INTERVAL_SECONDS`.

---

## 2. Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ADMIN_SESSION_ABSOLUTE_LIFETIME_SECONDS` | `28800` (8h) | Hard wall set at sign-in. Refresh can never move it. |
| `ADMIN_SESSION_IDLE_TIMEOUT_SECONDS` | `1800` (30m) | Ends a session that stops being used. |
| `ADMIN_SESSION_LAST_SEEN_WRITE_INTERVAL_SECONDS` | `60` | How stale `last_seen_at` may get before a write. Keep well below the idle timeout. |
| `ADMIN_SESSION_MAX_CONCURRENT` | `10` | Live sessions per operator. Reaching it ends the **oldest**. |
| `ADMIN_SESSION_ACCEPT_LEGACY_TOKENS` | `true` | Accept pre-#69 tokens with no `sid` until they expire. |
| `BREAK_GLASS_ENABLED` | `true` | Master switch for emergency access. |
| `BREAK_GLASS_SESSION_LIFETIME_SECONDS` | `3600` (1h) | Absolute lifetime for an emergency session. |
| `BREAK_GLASS_MAX_ATTEMPTS` / `BREAK_GLASS_WINDOW_SECONDS` | `5` / `900` | Per-IP activation rate limit. |

### Two ceilings, not one

A session ends at whichever comes first:

- **Absolute** (`absolute_expires_at`) is stamped at sign-in. Refresh moves the
  *token's* expiry, never this, so a session cannot be renewed indefinitely.
- **Idle** is evaluated against `last_seen_at`. This is what limits an
  unattended logged-in browser.

The `last_seen_at` write interval introduces bounded skew, always in the
operator's favour — a session may live slightly longer than the idle timeout,
never shorter. That is why the interval must stay well below the timeout.

### Expiry is decided on read

A lapsed session is refused by the request that presents it, whether or not any
background job has noticed. The retention sweeper only tidies rows and writes
the terminal reason. A capability that depended on a timer to *become* safe
would be unsafe whenever the timer was late.

---

## 3. The session contract

| Endpoint | Who | Purpose |
| --- | --- | --- |
| `GET /auth/sessions` | self | Inventory, with device context and `is_current`. |
| `POST /auth/sessions/{id}/revoke` | self | End one of your own. |
| `POST /auth/sessions/revoke-others` | self | End everything except the current session. |
| `POST /auth/session/refresh` | self | New token for the same session, within the absolute ceiling. |
| `GET /auth/operators/{id}/sessions` | platform admin | Inspect another operator's sessions. |
| `POST /auth/operators/{id}/sessions/revoke` | platform admin **+ step-up** | End all of another operator's sessions. |

Self-revocation is deliberately **not** step-up gated: ending your own session
only ever reduces access, and someone who suspects a compromise must be able to
act immediately rather than first find their security key. Administrative
revocation *is* gated, because mass revocation is a denial-of-service lever
against the people best placed to notice an intrusion.

`POST /auth/operators/{id}/sessions/revoke` leaves `token_generation` alone —
it ends the sessions this deployment can see without invalidating credentials
the operator may still need. Use `/auth/operators/{id}/revoke-tokens` for the
bigger hammer; that bumps the generation *and* closes the tracked rows in the
same transaction, so the inventory never shows a live session that cannot be
used.

### Legacy, unmanaged sessions

Tokens minted before this revision carry no `sid`. With
`ADMIN_SESSION_ACCEPT_LEGACY_TOKENS=true` (the default) they keep working until
they expire, so deploying does not sign an entire fleet out mid-shift. Such a
session is **unmanaged**: absent from the inventory, not individually revocable,
and not refreshable (`409 session_not_managed`). It is still bounded by the
access-token lifetime and still killed by a generation bump. Set the flag
`false` to refuse them outright and force re-authentication.

---

## 4. Break-glass

Every other authentication control here fails closed. That is correct, and it
creates the problem break-glass solves: the controls can fail closed **on the
operator**. An administrator whose only authenticator is lost, or a federation
outage, would otherwise leave a deployment that manages an entire fleet with
nobody able to sign in and fix it.

A break-glass credential is a single high-entropy secret that works with nothing
else — no second factor, no email, no hardware. That is exactly what makes it
useful in an emergency and exactly what makes it dangerous. It is not bounded by
another factor, because that would reintroduce the failure it exists to survive.
It is bounded three other ways:

- **By time.** An activation opens a session with a one-hour absolute lifetime
  rather than eight.
- **By noise.** Activation writes an audit event, marks the session, and opens a
  review row that stays open until a human closes it.
- **By provisioning.** Credentials are minted deliberately by a platform admin,
  shown once, and bound to a dedicated operator row whose password hash is
  unusable — so the identity can never be reached by ordinary password login,
  and disabling break-glass never disturbs a real person's account.

### Break-glass cannot entrench itself

An emergency session is allowed to *act* — that is the point — but it cannot
create, rotate, or re-enable break-glass credentials (`403
break_glass_cannot_provision`). Without that rule, one stolen envelope could
quietly become a permanent, self-renewing foothold outliving both the incident
and the credential that started it.

The ordinary step-up gate cannot express this: step-up is vacuous for an
operator holding no authenticator, and a break-glass identity holds none by
construction. So the rule is stated directly and fails closed on the signed
`amr` claim.

### Endpoints

| Endpoint | Who | Purpose |
| --- | --- | --- |
| `GET /auth/break-glass` | platform admin | List accounts and fingerprints. |
| `GET /auth/break-glass/status` | platform admin | Counts, including open reviews. |
| `POST /auth/break-glass` | platform admin **+ step-up** | Provision; returns the credential **once**. |
| `POST /auth/break-glass/{id}/rotate` | platform admin **+ step-up** | New credential; the old one dies immediately. |
| `PUT /auth/break-glass/{id}/disabled` | platform admin **+ step-up** | Disable/re-enable without losing history. |
| `POST /auth/break-glass/activate` | **unauthenticated** | Exchange a credential for a short session. |
| `GET /auth/break-glass/activations` | platform admin | History and review queue. |
| `POST /auth/break-glass/activations/{id}/review` | platform admin | Sign off one activation. |

Activation is unauthenticated by necessity: requiring a session to reach the
escape hatch for "nobody can obtain a session" would be circular. An unknown
credential, a disabled account, and a malformed value are indistinguishable and
equally rate-limited, so the endpoint is not an oracle for guessing which
envelopes exist. Every refused attempt is audited, so probing leaves a trail.

Review is **not** step-up gated: it records an opinion and grants nothing.
Making the accountable act harder than the privileged one would only discourage
the review from happening. A reviewed activation cannot be re-reviewed (`409`) —
the first sign-off is the accountable one.

### Operating it

1. Provision at least one credential. With none, a total authenticator loss
   locks everyone out permanently; the dashboard warns when none exists.
2. Print it, seal it, store it somewhere physical, and record the fingerprint
   against the envelope. The fingerprint is non-authenticating and is how you
   tell two envelopes apart without opening either.
3. Rotate after any use, and after any suspicion the seal was broken.
4. Review every activation. An unreviewed activation is an open incident.

**The trade-off, stated plainly:** a stolen sealed envelope is a full compromise
of the deployment. Rotation, disablement, the short session lifetime, and the
review queue are the operational answers. There is no cryptographic one, because
a second factor is precisely what this path exists to survive.

---

## 5. Rollout and rollback

Every schema change in `0039` is additive and introduces no new non-nullable
column on an existing table, so an older application binary running against this
schema simply never reads the new tables. The migration can be applied well
ahead of the build that uses it.

**Rollback is configuration, not schema.** `BREAK_GLASS_ENABLED=false` refuses
provisioning and activation while retaining existing accounts and history.
`ADMIN_SESSION_ACCEPT_LEGACY_TOKENS` controls whether pre-#69 tokens survive an
upgrade. Migrations remain forward-only; crossing back below `0039` requires the
exact-revision restore procedure in [`ROLLBACK.md`](ROLLBACK.md).

**Mixed versions.** Session enforcement is decided by the server that owns the
request, so a fleet mid-upgrade degrades to "sessions not tracked" on old
servers, never to "sessions not enforced" on new ones.

---

## 6. Evidence

### Audit events

`operator.session_started`, `operator.session_revoked`,
`break_glass.account_created`, `break_glass.credential_rotated`,
`break_glass.account_state_changed`, `break_glass.activated`,
`break_glass.activation_failed`, `break_glass.activation_reviewed`. Field-level
schemas are in [`AUDIT-EVENTS.md`](AUDIT-EVENTS.md) and enforced fail-closed by
`app/core/redaction.py`.

Break-glass credentials appear nowhere, in any form — only the
domain-separated, non-authenticating fingerprint, which lets a reviewer match an
event to a sealed envelope without the event carrying anything that could open
it. Labels, reasons, and review notes are operator prose and are digested.

### Storage

`operator_sessions` rows are operational inventory, not accountability evidence
— the audit chain already records sign-in, revocation, and activation — so
unlike audit data they are eventually deleted by the retention sweeper.
`break_glass_activations` are **not** pruned: they are the incident record.

### Tests

`server/tests/test_admin_sessions_break_glass.py` (33 tests) covers revocation
taking effect on the next request, both ceilings including the "active but past
the wall" case, the bounded `last_seen_at` write, refresh not moving the
ceiling, refresh not resurrecting a revoked session, the concurrency ceiling
closing the oldest, cross-operator isolation, forged and unknown `sid` values,
legacy-token acceptance and refusal, credential rotation and disablement,
one-time credential display, activation rate limiting and audit, the
cannot-entrench rule, and review-exactly-once.

`dashboard/test/admin-sessions-core.test.ts` covers presentation, error-code
mapping, input bounds, origin enforcement, credential handling, and the
activation cookie flow.

### Recovering a password on an older schema

`scripts/reset_password.py` works against a database that has not reached
revision `0039`. It probes for the tracked-session table first rather than
reaching for it and catching the failure -- on PostgreSQL a failed statement
poisons the surrounding transaction, so there would be nothing useful left to
catch, and the reset meant to rescue a locked-out administrator would fail
precisely when it is needed.

On such a database the reset is still complete: bumping `token_generation`
invalidates every outstanding token regardless of schema. Only the cosmetic
row-closing is skipped, and the CLI says so rather than reporting a revocation
count that did not happen.

### Known limitations

- **The activation rate limiter is process-local**, the same multi-worker caveat
  that applies to login, enrolment, and MFA (`app/core/ratelimit.py`).
- **Session validation adds a database read per authenticated request.** Bounded
  and indexed, but it is a real change to the hot path.
- **No geolocation or device fingerprinting.** Context is the source IP and
  user-agent the client sent; both are attacker-influenced and are presented as
  recognition aids, not as identity.
- **Break-glass activation does not notify out-of-band.** It writes audit
  evidence and surfaces a dashboard banner; wiring it to the alerting pipeline
  is follow-up work.
