# Multi-factor authentication (WebAuthn)

Issue #67, extended by issue #226. Phishing-resistant second-factor authentication for dashboard
operators, with enrolment, single-use challenges, device naming and revocation,
step-up for sensitive operations, and audited recovery. An optional email
one-time-code factor exists as a *fallback* for operators who hold no
authenticator; it is off by default and deliberately weaker — see
[Email one-time codes](#10-email-one-time-codes-optional-fallback).

**What this is not.** This is a strong authentication control. It is not a
compliance claim, and it does not verify authenticator provenance — see
[Attestation](#attestation-what-is-and-is-not-verified). Nothing here applies to
*agent* authentication, which uses the separate bearer-credential mechanism in
`docs/agent-enrollment/`.

---

## 1. Why WebAuthn and not TOTP

A TOTP code can be read aloud, typed into a look-alike page, and replayed by an
attacker within its window. That is the dominant real-world compromise path for
an RMM console, whose operator accounts can reach every managed endpoint.

A WebAuthn credential cannot be phished in that way. The private key never
leaves the authenticator, and the authenticator will only sign for the origin
and relying-party ID the credential was created under. An operator who is
successfully lured to `rmm.example.com.evil.test` cannot produce a signature
that this server will accept, no matter how convincing the page is or how
willing the operator is to help.

The trade-off is device loss, which is what [recovery codes](#5-recovery) and
the [administrative reset](#6-administrative-reset-device-loss) exist to handle.

---

## 2. Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `MFA_ENFORCEMENT` | `optional` | `off` \| `optional` \| `required`. See [Rollout](#7-rollout-and-rollback). |
| `MFA_REQUIRED_MINIMUM_ROLE` | `admin` | Privilege floor the `required` mode applies to. |
| `MFA_RP_ID` | derived | Relying-party ID. Unset derives the host from `PUBLIC_BASE_URL`. |
| `MFA_RP_NAME` | `APP_NAME` | Name shown in the browser's authenticator prompt. |
| `MFA_ALLOWED_ORIGINS` | derived | Comma-separated exact origins. Unset derives one from `PUBLIC_BASE_URL`. |
| `MFA_CHALLENGE_TTL_SECONDS` | `300` | Challenge lifetime. |
| `MFA_PENDING_TOKEN_TTL_SECONDS` | `600` | Lifetime of the post-password restricted token. |
| `MFA_STEP_UP_MAX_AGE_SECONDS` | `900` | How recently a session must have asserted to pass step-up. |
| `MFA_RECOVERY_CODE_COUNT` | `10` | Codes minted per batch. |
| `MFA_MAX_CREDENTIALS_PER_OPERATOR` | `10` | Ceiling on registered authenticators. |
| `MFA_MAX_FAILURES` / `MFA_WINDOW_SECONDS` | `5` / `300` | Second-factor rate limit per (client IP, operator). |
| `MFA_REQUIRE_USER_VERIFICATION` | `true` | Require PIN/biometric, not merely presence. |
| `MFA_EMAIL_CODE_POLICY` | `off` | `off` \| `fallback_only` \| `always`. See [Email one-time codes](#10-email-one-time-codes-optional-fallback). |
| `MFA_EMAIL_CODE_LENGTH` | `6` | Digits per emailed code. |
| `MFA_EMAIL_CODE_TTL_SECONDS` | `600` | Code lifetime. |
| `MFA_EMAIL_CODE_MAX_ATTEMPTS` | `5` | Verification attempts before a code is burned. |
| `MFA_EMAIL_SEND_MAX_PER_WINDOW` / `MFA_EMAIL_SEND_WINDOW_SECONDS` | `3` / `900` | Send limit, per operator and per source IP. |

### The relying-party ID is effectively immutable

Credentials are cryptographically scoped to the RP ID they were created under.
Changing `MFA_RP_ID` (or moving the deployment to a different host when the ID
is derived from `PUBLIC_BASE_URL`) **silently invalidates every registered
credential** — authenticators will simply decline to sign, and every operator
will need an administrative reset. Treat it as a one-time decision. If the
deployment might later move between subdomains, set `MFA_RP_ID` explicitly to
the registrable parent domain before anyone enrols.

An unresolvable relying party fails closed twice over. In production,
`ensure_safe_production_config` refuses to start when enforcement is not `off`
and the relying party cannot be resolved, or when any accepted origin is not
`https://` — catching the misconfiguration at boot rather than the first time an
operator reaches for their security key, and well before any credential could be
registered under a guessed scope. Outside production, and for any configuration
that changes after startup, every ceremony returns
`503 {"code": "mfa_not_configured"}`.

### When the dashboard and the API are on different domains

This is the case that bites first, and the defaults do not cover it. A WebAuthn
ceremony happens in the **browser**, at the dashboard's origin -- not at the
API's. The browser refuses any relying-party ID that is not the page's own
domain or a registrable suffix of it.

So a split deployment (dashboard on one host, API on another) **must** set both
values explicitly to the *dashboard's* domain:

```
MFA_RP_ID           = dashboard.example.com
MFA_ALLOWED_ORIGINS = https://dashboard.example.com
```

Left unset, both derive from `PUBLIC_BASE_URL`, which on such a deployment is
the API's own host. Registration then fails in the browser before anything
reaches the server, with a `SecurityError` the dashboard reports as *"This site
is not configured for security keys"*.

Use a **stable** domain, never a per-deployment preview URL: credentials are
bound to the relying-party ID, so changing it invalidates every registered key
and forces an administrative reset for every operator.

### Origins are an exact-match allow-list

`MFA_ALLOWED_ORIGINS` is the phishing-resistance boundary. There are no
wildcards. Every entry is a site permitted to complete a ceremony, so a
deployment served from more than one origin must list each one, and a deployment
served from one should list exactly one.

---

## 3. The login contract

`POST /api/v1/auth/login` returns one of two shapes. When no second factor
applies the body is byte-compatible with the pre-MFA response, so an older
dashboard build and a deployment with `MFA_ENFORCEMENT=off` are unaffected.

```jsonc
// No second factor owed
{ "access_token": "<jwt>", "token_type": "bearer", "mfa_required": false }

// Second factor owed
{
  "access_token": null,
  "token_type": "bearer",
  "mfa_required": true,
  "mfa_token": "<restricted jwt>",
  "mfa_enrollment_required": false,
  "mfa_methods": ["webauthn", "recovery_code"]
}
```

`mfa_token` is **not a session.** It carries a `typ` of `mfa_pending` and is
accepted only by the MFA completion endpoints. Every other operator-facing route
in the application resolves identity through one dependency
(`get_current_operator`), which refuses that type — so a correct password with no
second factor buys access to nothing.

### Endpoints

| Endpoint | Credential | Purpose |
| --- | --- | --- |
| `POST /auth/mfa/login/options` | `mfa_pending` | Assertion options for login. |
| `POST /auth/mfa/login/verify` | `mfa_pending` | Complete login with an authenticator. |
| `POST /auth/mfa/login/recovery-code` | `mfa_pending` | Complete login with a recovery code. |
| `POST /auth/mfa/credentials/options` | session, or `mfa_pending` when enrolment is required | Registration options. |
| `POST /auth/mfa/credentials` | same | Complete registration. |
| `GET /auth/mfa/credentials` | session | List the caller's own devices. |
| `GET /auth/mfa/status` | session | Enrolment state and this session's capability. |
| `PUT /auth/mfa/credentials/{id}` | session **+ step-up** | Rename a device. |
| `POST /auth/mfa/credentials/{id}/revoke` | session **+ step-up** | Revoke a device. |
| `POST /auth/mfa/recovery-codes` | session **+ step-up** | Mint a recovery batch. |
| `POST /auth/mfa/step-up/options` / `/verify` | session | Re-assert to satisfy step-up. |
| `POST /auth/operators/{id}/mfa/reset` | admin **+ step-up** | Administrative reset. |

### Failure behaviour

Every refused ceremony returns the same body:

```json
{"detail": "Multi-factor authentication failed"}
```

An unknown credential, a bad signature, a wrong origin, a replayed challenge, and
a regressed signature counter are indistinguishable to the caller. The coded
reason (`origin_mismatch`, `sign_count_regressed`, `challenge_not_found`, …) goes
to the audit chain under `mfa.authentication_failed`, where a reviewer can see it
and an attacker cannot.

Distinct, non-secret codes *are* returned where they describe a state the
operator must act on rather than a ceremony outcome: `step_up_required`,
`mfa_verification_required`, `enrollment_required`, `credential_limit_reached`,
`last_mfa_credential_required`, `credential_already_registered`, `mfa_disabled`,
`mfa_not_configured`.

---

## 4. Session strength and step-up

A session's JWT carries signed claims describing *how* it authenticated: `amr`
(the methods used) and `sua` (when it last proved possession of a registered
authenticator). The server decides both at mint time from a verified ceremony, so
a client cannot assert a stronger state than it reached.

| How the session was obtained | `amr` | Satisfies step-up? |
| --- | --- | --- |
| Password only (nobody enrolled) | `pwd` | n/a — the gate is vacuous |
| Password + WebAuthn | `pwd`, `webauthn` | Yes, for `MFA_STEP_UP_MAX_AGE_SECONDS` |
| Password + recovery code | `pwd`, `recovery_code` | **No, ever** |

### What step-up gates

- Renaming or revoking one of your own authenticators
- Minting recovery codes
- Changing another operator's role or disabled state
- Revoking another operator's sessions
- Resetting another operator's MFA
- Granting or revoking an operator's tenant membership, and toggling
  platform-admin (issue #66) — the same "grant or widen access" class

The gate is **vacuous for an operator who holds no active credential.** This is
the compatibility contract, not a loophole: a deployment that has not adopted MFA
behaves exactly as it did before, and an operator part way through enrolment is
never locked out of account management they already had. The moment an operator
holds an active credential the gate becomes real for them, with no configuration
change. It is also vacuous under `MFA_ENFORCEMENT=off`, because no ceremony can
be started in that mode and an unsatisfiable gate would lock everyone out.

---

## 5. Recovery

Recovery codes are the deliberate weak point of any MFA design — they are bearer
secrets a human writes down — so they are constrained accordingly:

- **20 characters from a 32-symbol unambiguous alphabet** (no `0`/`O`, no
  `1`/`I`/`L`), formatted in four groups. Case and separators are forgiven on
  entry.
- **Stored as bcrypt hashes**, like passwords, not as the single SHA-256 used for
  high-entropy machine tokens.
- **Single use**, claimed with a conditional UPDATE so two concurrent
  presentations of one code cannot both win.
- **Minting a batch destroys the previous batch.** An unused code from a retired
  batch is a live credential; the only safe state for it is gone.
- **Shown exactly once**, in the response body. They are never logged, never
  audited (not even as a digest — a digest of a human-scale secret is itself an
  offline attack surface), and cannot be retrieved again.
- **Requires an authenticator to exist first.** Codes recover *from* something.

### Recovery gets you in, not up

A recovery-code session is a real session for ordinary work and **can register a
replacement authenticator** — that is the whole point. It can never satisfy
step-up, so it cannot revoke devices, mint new recovery codes, or touch another
operator's account. An attacker who steals the printed codes gets the account's
ordinary surface; they do not get the ability to lock the real owner out of it.

The device-loss path is therefore: sign in with a recovery code → register a
replacement key → assert the new key to gain step-up → revoke the lost one.

---

## 6. Administrative reset (device loss)

`POST /api/v1/auth/operators/{id}/mfa/reset` is the escape hatch when an operator
has lost both their devices and their codes. It demotes an account to
password-only, so it carries the most conditions in the module: admin role,
step-up on the *administrator's own* session, a mandatory reason, and an audit
event naming who did it to whom.

It revokes every credential (as tombstones, so the audit trail still points at
real rows), deletes every recovery code, deletes outstanding challenges, and
bumps the target's token generation to revoke their existing sessions —
because the point of a reset is to establish a known state, and a session minted
before it is not part of that state.

---

## 7. Rollout and rollback

The three enforcement positions exist to make this deployable without locking
anyone out. Migrate the schema first; it is additive and safe to apply well
ahead of turning enforcement up.

1. **`off`** — MFA endpoints refuse (`503 mfa_disabled`); login is password-only.
   Start here on an existing deployment, and return here to roll back.
2. **`optional`** — the staging position, and the default. Operators may enrol,
   and **anyone who has a credential must use it**. Enrolment happens under real
   enforcement for the enrolled, with no lockout risk for the not-yet-enrolled.
   Leave the fleet here until enrolment is complete; `GET /auth/mfa/status` and
   the `mfa.credential_registered` audit events show progress.
3. **`required`** — operators at or above `MFA_REQUIRED_MINIMUM_ROLE` must hold a
   credential. An unenrolled operator can still authenticate with their password
   but receives a restricted session that can *only* enrol, so the requirement
   cannot strand them.

**Rollback is a configuration change, not a schema change.** Set
`MFA_ENFORCEMENT=off` and restart: enrolled operators log in with a password
again, step-up gates go vacuous, registered credentials are retained untouched,
and moving back to `optional` restores enforcement with no re-enrolment. No
migration is reversed and no credential is deleted. Migrations remain
forward-only; crossing back below revision `0036` requires the exact-revision
restore procedure in [`ROLLBACK.md`](ROLLBACK.md).

**Mixed versions.** Enforcement is decided by the server that owns the login
endpoint, so a fleet mid-upgrade degrades to "MFA unavailable" on old servers,
never to "MFA bypassed" on new ones. An older *dashboard* against a newer server
sees the unchanged password-only response shape until enforcement is raised.

### Configuration is fail-closed on unreadable values

An unrecognised `MFA_ENFORCEMENT` resolves to `optional`, not `off`, and an
unrecognised `MFA_REQUIRED_MINIMUM_ROLE` resolves to `admin`. A typo in a
deployment variable must not silently disable a security control for operators
who have already enrolled. Turning MFA off requires spelling `off` correctly.

---

## 8. Verification internals

### Replay protection is a database decision

A signed assertion is valid forever unless something remembers it was spent.
Challenges are single-use rows, bound to one operator *and one purpose*
(`registration`, `authentication`, `step_up`), claimed by a conditional UPDATE so
exactly one of two concurrent replays wins. Purpose binding means a challenge
issued to add a device can never be spent to complete a login: without it, the
three ceremonies would share one replay pool and the weakest entry point would
set the bar for all of them.

The consumption is committed even when verification then fails — otherwise the
transaction rollback would un-spend the challenge and hand a replay a second try.

### Signature counter

An authenticator that implements a counter must strictly increase it. One that
does not (many platform authenticators, and all synced passkeys) reports `0`
forever. So a reported `0` means "no counter, nothing to check", and any non-zero
value must beat the stored one. A stale or equal non-zero counter is evidence of
a cloned credential and fails closed.

### Attestation: what is and is not verified

Registration options request `attestation: "none"`, so conforming browsers strip
the statement. The server accepts the `none` format, and `packed`
self-attestation whose signature it *does* verify against the credential key
being registered. Every other format — including `packed` with an `x5c` chain —
is refused, because evaluating a chain would require a trusted attestation root
this project does not operate, and accepting an unevaluated chain would be worse
than refusing it.

**This binds the credential to the ceremony. It does not establish authenticator
make, model, or certification.** No hardware-provenance claim may be built on it.

### Supported algorithms

ES256 (P-256), EdDSA (Ed25519), and RS256 (≥2048-bit). Anything else is refused
at registration, so a key the server cannot verify can never be stored.

### Why the WebAuthn stack is in-tree

`app/core/webauthn.py` and `app/core/cbor.py` implement verification directly on
the already-pinned `cryptography` package. The available CBOR-carrying WebAuthn
libraries pull a newer `cryptography` plus `pyOpenSSL` into a lock set whose
Ed25519 command signing is qualified at the pinned version; decoding a handful of
well-specified CBOR major types is a smaller and more reviewable change than
moving that signing dependency. The CBOR decoder implements a strict subset and
rejects everything else: definite lengths only, bounded depth and size, no
duplicate map keys, no trailing data, no tags.

---

## 9. Evidence

### Schema

Revision `0036` adds `webauthn_credentials`, `webauthn_challenges`,
`mfa_recovery_codes`, and one nullable `operators.mfa_recovery_codes_generated_at`
column. Every change is additive.

Revision `0040` adds `mfa_email_factors` and `mfa_email_codes` for the email
fallback. Also additive: a deployment that leaves `MFA_EMAIL_CODE_POLICY` at
`off` gets two unused tables and no behavioural change.

Nothing stored is a secret that could be replayed as a login: a WebAuthn
credential is a public key, and recovery codes are bcrypt hashes. A database
disclosure does not yield a usable second factor.

### Audit events

`mfa.second_factor_required`, `mfa.credential_registered`,
`mfa.credential_renamed`, `mfa.credential_revoked`,
`mfa.authentication_succeeded`, `mfa.authentication_failed`,
`mfa.step_up_succeeded`, `mfa.recovery_codes_generated`,
`mfa.recovery_code_used`, `mfa.reset`, `mfa.email_code_sent`,
`mfa.email_code_send_failed`, `mfa.email_factor_verified`,
`mfa.email_factor_removed`. Field-level schemas are in
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md) and enforced fail-closed by
`app/core/redaction.py`.

Device names and revocation reasons are operator-controlled prose and are stored
as digests plus byte counts. `credential_id` throughout is the credential *row*
id, never the WebAuthn credential identifier. Recovery codes appear nowhere, and
`mfa.recovery_code_used` deliberately does not record *which* code was spent —
that would narrow the search space for the remaining ones if the log were
disclosed.

Emailed codes get the same treatment as recovery codes: never recorded, not even
as a digest. What the chain carries is the *masked* destination — enough to
review where a code went, not enough to be a mailing list if the log is
disclosed.

### Tests

`server/tests/test_mfa_webauthn.py` (52 tests). Every ceremony is produced by a
software authenticator (`server/tests/webauthn_authenticator.py`) signing real
bytes with a real key, so a negative test fails because the cryptography or the
state check actually refuses it. Covered: challenge replay and expiry, origin and
RP-ID mismatch, cross-origin, signature corruption, user-verification and
user-presence flags, ceremony-type substitution, signature-counter regression,
cross-operator credential use, duplicate credential binding, disabled operators,
session revocation mid-login, rate limiting, credential limits, all three
enforcement positions, the last-credential guard, recovery issuance/use/
regeneration, the full device-loss path, administrative reset, and audit
completeness with secret absence.

`server/tests/test_mfa_email_code.py` (21 tests) covers the email factor:
each policy position, the fallback-only downgrade guard, code expiry, the
attempt ceiling, send limiting per operator and per IP, purpose binding between
enrolment and login codes, invalidation on delivery failure, refusal to satisfy
step-up, and audit completeness with the code absent from the chain.

`dashboard/test/mfa-core.test.ts` covers encoding, ceremony conversion, login
interpretation, error-code collapsing, and the route handlers' origin, credential
selection, and cookie behaviour.

### Known limitations

- **The rate limiter is process-local.** Behind multiple uvicorn workers each
  worker enforces its own window, so the effective global limit is multiplied by
  the worker count — the same caveat that already applies to login and enrolment
  (`app/core/ratelimit.py`).
- **Expired challenge rows are pruned by the retention sweeper**
  (`app.core.mfa.purge_expired_challenges`), bounded per pass so one sweep cannot
  hold a long transaction open on a large backlog. They are inert once expired,
  so a backlog is a storage note rather than a security one.
- **No authenticator attestation or FIDO MDS integration**, as above.
- **No per-operator enrolment exemption or override.** Policy is role-based.
- **Email delivery is an availability boundary.** An operator whose only second
  factor is email cannot sign in while mail is delayed past the code's TTL. That
  is a lockout path with no cryptographic mitigation; it is why the factor is
  `fallback_only` at most, and why break-glass
  ([`ADMIN-SESSIONS.md`](ADMIN-SESSIONS.md)) is the answer for a total lockout
  rather than a longer TTL.
- **An emailed code is not phishing-resistant** and never can be. Enabling the
  factor is a deliberate trade of assurance for coverage; see section 10.

---

## 10. Email one-time codes (optional fallback)

Issue #226. **Off by default, and the default is the right choice for a
deployment that has issued security keys to everyone.**

### What it is trading away

Section 1 rejected TOTP because a code can be read aloud, typed into a
look-alike page, and replayed. An emailed code has exactly that weakness — it is
the same class of secret, delivered over a channel the operator does not control
either. Adding it does not make the account stronger; it makes the account
*reachable* by an operator who has no authenticator, at the cost of the property
that made WebAuthn worth building.

So the design question is never how to send a code. It is what the code is
allowed to do.

### `MFA_EMAIL_CODE_POLICY` — the whole decision

| Position | Effect | When it is defensible |
| --- | --- | --- |
| `off` | Email is never a factor. Enrolment and login by email both refuse. | Every operator holds a key. |
| `fallback_only` | Email is a login factor **only** for an operator with no active authenticator. | Rolling out keys gradually, or covering operators who cannot hold one. |
| `always` | Email is offered alongside WebAuthn to everyone. | Rarely. See below. |

`fallback_only` is the recommended position because it **cannot downgrade an
already-protected account**: an operator who holds a key must still use it, so
enabling the factor only reaches people who would otherwise have no second
factor at all.

`always` is the position to understand before choosing. It reduces every account
to the weaker factor — including accounts that hold a key — because an attacker
can simply phish the code and never touch the authenticator. The strong factor
becomes decorative. Choose it knowingly or not at all.

### No email code ever satisfies step-up

This is the load-bearing rule, and it is the same rule recovery codes get, for
the same reason. Device revocation, recovery-code minting, and operator
administration must not be reachable by phishing six digits. A session that got
in with an email code can do ordinary work and **can register an authenticator**
— that is the exit path — but it cannot remove the email factor, revoke a
device, or touch another operator's account.

Removing the email factor is itself step-up gated, so a phished code cannot be
escalated into a lasting change to the account.

### Why six digits is defensible

It is not the entropy. `10^6` is small. What bounds it is that a code dies after
`MFA_EMAIL_CODE_MAX_ATTEMPTS` (5) verifications and after
`MFA_EMAIL_CODE_TTL_SECONDS` (600s), and that sends are limited separately from
verifies — mailbox flooding and guessing are different abuses, and sharing one
budget would let either exhaust the other. Raise the length before relaxing
either bound.

Codes are stored hashed, single-use, and bound to a *purpose*: an enrolment code
cannot be presented at login, and vice versa.

### Endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/mfa/email/enrollment/start` | enrolment states | Send an enrolment code to the operator's login address. |
| `POST /api/v1/auth/mfa/email/enrollment/verify` | enrolment states | Complete enrolment. |
| `POST /api/v1/auth/mfa/email` | session + **step-up** | Remove the factor; mandatory reason. |
| `POST /api/v1/auth/mfa/login/email/send` | `mfa_pending` token | Send a login code. |
| `POST /api/v1/auth/mfa/login/email/verify` | `mfa_pending` token | Complete login. |

Enrolment accepts the same three states WebAuthn enrolment does (`get_enrollment_operator`):
a not-yet-enrolled session, a session that already presented a second factor, and
a restricted post-password token when policy obliges the operator to enrol.

### The destination is not a choice

Codes go to `Operator.email` and nowhere else. There is no per-factor address to
set, because a settable delivery address is an account-takeover primitive: an
attacker with a live session would otherwise point the factor at their own
mailbox. Changing where codes go means changing the login identity, through the
operator-administration path, with its own audit trail.

Responses are identical whether or not the operator actually has an email
factor, and nothing in a response says whether a message reached the wire.

### When delivery fails

The code is invalidated rather than left live in the database, the failure is
audited with a coded provider reason, and the caller gets `503
email_delivery_unavailable`. Telling an operator a code is coming when it is not
means they wait out the expiry and blame their mailbox.
