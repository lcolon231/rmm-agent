# Justified emergency override (issue #65) — design

Status: approved 2026-10-21. Builds on approval workflows (#64).

## Goal

Let an authorized person run one governed command during an incident without
waiting for a second approver, while keeping the approval policy in force and
producing evidence that is at least as complete as the approval it replaced.

The override is an *exception record*, not a bypass. A governed dispatch must
still spend either an approval or an override; nothing dispatches on neither.

## Decisions

| Question | Decision |
|---|---|
| Granularity | One override binds one exact command: agent, kind, canonical payload digest. Spent once. |
| Who may activate | Platform admin, or `client_admin` on the endpoint's tenant. Must also pass ordinary `authorize_command`. Step-up MFA required when the operator holds a second factor. |
| Opt-in | Per approval policy: `emergency_override_allowed` (default false). No policy, or policy not opted in, refuses activation. |
| Notification failure | Override still granted. Failure code recorded on the row, audited, flagged in the queue. |
| Expiry | Default 15 min, floor 60 s, ceiling 60 min. Evaluated on every read and every use. |
| Review | Open until a platform admin or tenant `client_admin` who is not the activator signs off, once. |
| Bypasses | Scheduled tasks and interactive shells stay refused for governed kinds. An override never reaches them. |

## Data model (Alembic 0046, additive, forward-only)

- `approval_policies.emergency_override_allowed BOOLEAN NOT NULL DEFAULT false`
- `emergency_overrides`:
  `id, agent_id (FK cascade), client_id, site_id, kind, payload JSON,
  payload_sha256, policy_id, activated_by_operator_id (FK set null),
  activated_by_email, justification TEXT, status ENUM(active, consumed,
  expired, revoked), created_at, expires_at, consumed_at, revoked_at,
  revoked_by_email, revoke_reason, notified_at, notification_error VARCHAR(64),
  reviewed_at, reviewed_by_email, review_note TEXT, source_ip, user_agent`.
  Indexes: `(client_id, status)`, `(reviewed_at, created_at)`.
- `commands.emergency_override_id VARCHAR(36) NULL` (FK set null, indexed).

Rows are never deleted by the application; retention pruning applies.

## Core module `app/core/emergency_overrides.py`

Single decision point, mirroring `app/core/approvals.py`:

- `activation_refusal(db, operator, agent, kind, policy)` → code or None.
  Order: operator disabled → `override_operator_disabled`; no policy →
  `override_not_required`; policy not opted in → `override_not_permitted`;
  not platform admin and not `client_admin` on tenant →
  `override_role_insufficient`; `authorize_command` fails →
  `override_command_not_authorized`.
- `expire_if_due(override, now)`.
- `consumption_refusal(db, override, operator, agent, kind, payload, now)` →
  agent/kind/payload mismatch, activator mismatch, expired, already consumed,
  revoked, activator no longer eligible (live re-check of activation rules).
- `override_expiry(ttl_seconds, now)` clamped to bounds.
- `audit_detail(override, **extra)` — ids, kind, scope, payload key names,
  digest, status; prose only via digest fields.

Constants: `MIN_JUSTIFICATION_BYTES=20`, `MAX_JUSTIFICATION_BYTES=512`,
`DEFAULT_TTL_SECONDS=900`, `MIN_TTL_SECONDS=60`, `MAX_TTL_SECONDS=3600`,
`MAX_OPEN_OVERRIDES_PER_OPERATOR=5`.

## API `app/api/emergency_overrides.py` (prefix `/api/v1`)

| Method | Path | Guard | Notes |
|---|---|---|---|
| POST | `/emergency-overrides` | operator role + `require_step_up` | Validates payload as dispatch would; refuses per `activation_refusal`; writes row; sends notification; audits. 201 with detail. |
| GET | `/emergency-overrides?unreviewed_only=&limit=` | readonly | Tenant-scoped. Applies expiry on read. No payload values. |
| GET | `/emergency-overrides/{id}` | readonly | Detail with payload and linked command id if consumed. 404 for foreign tenant. |
| POST | `/emergency-overrides/{id}/revoke` | operator | Activator or tenant admin; only `active`. Body: reason. |
| POST | `/emergency-overrides/{id}/review` | operator | Platform admin or tenant `client_admin`; never the activator; once. Body: note. |

Notification: immediate send through `build_transactional_provider` to
`email_notifications.configured_recipients()`. Subject names the endpoint,
kind, activator, and expiry. Success sets `notified_at`; failure sets
`notification_error` to the provider's safe code or `email_provider_unavailable`.

## Dispatch gate (`management.py`)

`CommandDispatch` gains `emergency_override_id: str | None`. In
`_apply_approval_policy`:

1. No policy: citing an override → 409 `override_not_required`.
2. Policy present, both ids cited → 409 `approval_and_override_both_cited`.
3. Override cited: load (404 `emergency_override_not_found` if missing or
   foreign tenant), `expire_if_due`, `consumption_refusal`; on refusal audit
   `approval_gate.denied` with the code. On success audit
   `approval_gate.allowed` with `reason=emergency_override_satisfied` and
   `emergency_override_id`.
4. `_spend_emergency_override` runs after every other gate, in the command
   transaction: conditional `UPDATE … WHERE status='active'` → `consumed`;
   rowcount != 1 → 409 `emergency_override_already_consumed`. Command row
   stores `emergency_override_id`.

Approval branch is unchanged.

## Audit actions (all registered in `redaction.py` and `test_redaction.py`)

`emergency_override.activated` (digest: justification), `.denied`,
`.notified`, `.notification_failed`, `.expired`, `.revoked` (digest: reason),
`.reviewed` (digest: note), `.consumed`. `approval_gate.allowed` /
`.denied` gain optional `emergency_override_id`.

## Dashboard

- Nav: "Emergency overrides" (Siren icon) after Approvals; page
  `/emergency-overrides`, admin-visible controls, readable by all roles.
- Page: warning banner; activation form (endpoint, kind, payload JSON,
  justification, expiry minutes); queue sorted unreviewed-first with status,
  countdown, notification state, revoke / review actions; "Run now" on an
  active override that the viewer activated, which dispatches via the existing
  commands proxy route citing `emergency_override_id`.
- Proxy routes under `dashboard/src/app/api/emergency-overrides/...`; the
  commands proxy route passes `emergency_override_id` through.
- Pure helpers in `lib/emergency-overrides-core.ts` with unit tests.

## Docs

New `docs/EMERGENCY-OVERRIDES.md` (shape, guarantees, states, refusal codes,
bypasses, evidence, rollout). Updates: `APPROVAL-WORKFLOWS.md` (link),
`AUDIT-EVENTS.md`, `SECURITY-ROADMAP.md`, `ROADMAP.md`, `ARCHITECTURE.md`,
`threat-model.md`, `README.md` status line.

## Tests (`server/tests/test_emergency_overrides.py`)

Policy not opted in; no policy; non-admin operator; weak justification;
operator without command authorization; happy path and command link; payload
mutation; expiry; single use under sequential replay; other operator cannot
spend; both ids cited; revoke then spend refused; self-review refused; second
review refused; notification failure recorded; tenant isolation on read and
spend; scheduled task still refused; audit events present and sanitized.

## Out of scope

Overrides for scheduled tasks or shell sessions; webhook notification of
overrides; per-policy TTL configuration; dashboard dispatch of approvals.
