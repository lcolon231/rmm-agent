# SPDX-License-Identifier: AGPL-3.0-only
"""Row, seam, and runner-change data for the NodeLink test-design matrix.

Every row is a *proposed* test (design only). Rubric inputs are explicit fields
so tasks/test-design/build.py can order rows mechanically:

  plane        trust | operations | product      (ARCHITECTURE.md §3.1/§3.2/§3.3)
  coverage     zero | thin                       (zero = nothing exercises the behavior today;
                                                  thin = reached only indirectly / happy path only)
  visibility   silent | visible                  (would a regression show up to an operator?)
  fixture_cost low | medium | high               (low = existing fixture copy; medium = new fake,
                                                  seam extraction, or Postgres-only; high = new
                                                  runner tier, Windows e2e, or multi-process)
  expected_fail  True when code reading says the test fails today (reason in rationale)
"""

from __future__ import annotations

PKG_STEP = "append the new file to dashboard/package.json \"test\" (hand-maintained list; ask before editing package.json)"
GO_LF = "new *_test.go must be LF and gofmt-clean (`tr -d '\\r' < f | gofmt -l`), Windows checkout is CRLF"
WIN_JOB = "runs only on the `agent-windows` (windows-latest) job: file is `//go:build windows`"
REDACTION = "emits audit action(s); test_redaction.py PRODUCER_DETAILS + AUDIT_DETAIL_SCHEMAS + docs/AUDIT-EVENTS.md must list it or the suite fails"
PG_ONLY = "Postgres-only: `@pytest.mark.skipif(not os.getenv('TEST_POSTGRES_URL'))`, runs in the CI `server` job (postgres:16)"

E2E = "tests/test_e2e.py"
TENANCY = "tests/_tenancy.grant_all_memberships (issue #66) after seeding operators + clients"

ROWS: list[dict] = []


def R(id, layer, tier, target, behavior, boundary, plane, coverage, visibility,
      fixture_cost, fixture, pattern, rationale, *, expected_fail=False,
      notes=(), handlers=()):
    ROWS.append(dict(
        id=id, layer=layer, tier=tier, target=target, behavior=behavior,
        boundary=boundary, fixture_strategy=fixture,
        existing_pattern_to_copy=pattern, priority=None, rationale=rationale,
        plane=plane, coverage=coverage, visibility=visibility,
        fixture_cost=fixture_cost, expected_fail=expected_fail,
        notes=list(notes), handlers=list(handlers),
    ))


# ───────────────────────────── server: core units ─────────────────────────────
R("SRV-01", "server", "unit", "app/core/timeutil.py ensure_utc/now_utc",
  "naive datetime, aware non-UTC datetime, or None is passed → returns UTC-aware value (or None) without shifting wall time incorrectly",
  "operations: token/command time windows", "operations", "zero", "silent", "low",
  "pure function, no DB, no app import", "tests/test_command_envelope_vectors.py (pure-function module test)",
  "0 import hits; only reached through /enroll and /heartbeat. Every expiry comparison depends on it, and a naive/aware mixup raises TypeError only at runtime.")
R("SRV-02", "server", "unit", "app/core/tenant_scope.py client_role_permits, client_id_filter, agent_client_filter",
  "each (ClientRole, minimum) pair and platform-admin vs member operator → permits/filters exactly per TENANT-AUTHORIZATION.md table",
  "trust: tenant boundary (#66), default-deny", "trust", "thin", "silent", "low",
  "pure: compile the returned SQLAlchemy expression and assert the WHERE clause; table-driven over roles",
  "tests/test_tenant_authorization.py",
  "0 import hits; covered only through 8 HTTP tests. A permissive filter regression leaks another tenant's rows with HTTP 200, which no operator would notice.")
R("SRV-03", "server", "unit", "app/core/tenant_scope.py assert_agent_visible / agent_client_id",
  "agent whose site has no client, or operator without membership → 404 'Not found' (never 403) for non-platform-admin",
  "trust: tenant boundary (#66), cross-tenant == 404", "trust", "thin", "silent", "medium",
  f"AsyncSessionLocal on SQLite; seed operator/client/site/agent directly; no HTTP. {TENANCY} only for the positive case",
  "tests/test_tenant_authorization.py",
  "Default-deny edge (orphan agent) is not exercised by any test; a None client_id must deny rather than match everything.")
R("SRV-04", "server", "unit", "app/core/enrollment.py redeem_enrollment_token",
  "expired, revoked, exhausted, or wrong-site token → EnrollmentRejected(reason) and the token's use count is unchanged",
  "trust: enrollment-token issuance", "trust", "thin", "silent", "medium",
  "AsyncSessionLocal + seeded EnrollmentToken rows; call the function directly with a minimal EnrollRequest",
  "tests/test_enrollment_management.py",
  "0 import hits; HTTP tests prove the happy path and negotiation refusal but not that each rejection reason leaves the token unconsumed.")
R("SRV-05", "server", "unit", "app/core/clientip.py client_ip",
  "TRUST_PROXY_HEADERS=false with spoofed X-Forwarded-For → socket peer; =true → rightmost XFF entry; empty/whitespace XFF → peer",
  "trust: per-IP rate limits + audit source IP", "trust", "thin", "silent", "low",
  "pure: Starlette Request built from a scope dict; monkeypatch settings.trust_proxy_headers",
  "tests/test_prodcheck.py",
  "Only exercised as a side effect of prodcheck. Spoofable IP silently defeats the enrollment and login rate limits.")
R("SRV-06", "server", "unit", "app/core/ratelimit.py LoginRateLimiter",
  "max_failures reached within window → retry_after > 0; window elapses → None; clear(key) resets only that key",
  "trust: operator auth brute-force limit", "trust", "thin", "visible", "low",
  "pure; inject a fake monotonic clock via monkeypatch of time.monotonic", "tests/test_revocation_ratelimit.py",
  "Window-expiry and per-key isolation are untested; lockout bugs either lock operators out or remove the limit.")
R("SRV-07", "server", "unit", "app/core/script_authorization.py authorize_command + decision_audit_detail",
  "every (role, script scope global/site/agent, CommandKind) cell → allow/deny exactly as SCRIPT-AUTHORIZATION.md; admin without scope is denied",
  "trust: arbitrary-script scope (default-deny, admin does not bypass)", "trust", "thin", "silent", "low",
  "pure: construct Operator/Agent model instances without a session; table-driven",
  "tests/test_script_authorization.py",
  "0 import hits (multi-line aware). HTTP tests sample the matrix; a full decision table pins the default-deny contract.")
R("SRV-08", "server", "unit", "app/core/patch_policies.py parse_rules / evaluate_update",
  "rule lists (classification, KB, deferral days, default action) × update dict → UpdateDecision; malformed rule → ValueError",
  "operations: patch approval (#52/#53)", "operations", "thin", "silent", "low",
  "pure; freeze `now` argument", "tests/test_patch_policies.py",
  "0 import hits; a wrong decision silently installs or withholds updates fleet-wide.")
R("SRV-09", "server", "unit", "app/core/patch_compliance.py summarize",
  "mixed EndpointCompliance rows incl. stale/unknown + truncated=True → counts and truncated flag in ComplianceSummary",
  "operations: patch compliance (#54)", "operations", "thin", "visible", "low",
  "pure", "tests/test_patch_compliance.py",
  "0 import hits; summary numbers feed the dashboard and CSV export.")

# ─────────────────────── server: likely real holes (expected to fail) ───────────────────────
R("SRV-10", "server", "integration", "POST /api/v1/agents/me/self-update/report (app/api/agent_updates.py:713)",
  "quarantined or revoked agent posts an outcome report → 403 agent_not_active and agent_version/attempt row unchanged",
  "trust: agent trust state (quarantine is fail-closed)", "trust", "zero", "silent", "low",
  f"{E2E} shape; enroll via _enroll helper, flip trust_state in DB, post report with the agent bearer",
  "tests/test_agent_trust.py",
  "expected to fail: get_current_agent admits quarantined agents and report_self_update has no trust_state check, so a quarantined endpoint can move its stored version and trigger a rollout halt.",
  expected_fail=True, notes=[REDACTION + " (agent_update.outcome_reported)", "depends on revision 0035 (agent_self_update)"])
R("SRV-11", "server", "integration", "POST /api/v1/agents/me/self-update/report replay",
  "identical report posted twice → second is a no-op (one audit event, one attempt transition)",
  "trust: replay protection on agent→server reports", "trust", "zero", "silent", "low",
  f"{E2E} shape; count AuditEvent rows with action agent_update.outcome_reported",
  "tests/test_e2e.py::test_result_delivery_is_idempotent_and_conflicts_fail_closed",
  "expected to fail: the report has no request id/nonce; each replay overwrites the attempt and appends another audit event.",
  expected_fail=True, notes=[REDACTION + " (agent_update.outcome_reported)"])
R("SRV-12", "server", "integration", "agent_updates._dispatch_update_command (rollout)",
  "an ApprovalPolicy governs agent_self_update for the target → rollout refuses or holds the command and audits approval_refused",
  "operations: approval / two-person authorization (#64)", "operations", "zero", "silent", "medium",
  f"{E2E} shape + {TENANCY}; seed ApprovalPolicy(kinds=['agent_self_update']); publish release via API; assert no queued Command",
  "tests/test_approval_workflows.py::test_scheduled_task_under_policy_is_refused",
  "expected to fail: _dispatch_update_command creates Command rows without calling approvals_core.resolve_policy, so a policy covering self-update is bypassed.",
  expected_fail=True, notes=["depends on revision 0041 (approval_workflows)", REDACTION])
R("SRV-13", "server", "integration", "POST /api/v1/agents/{id}/shell-sessions (app/api/shell_sessions.py:240)",
  "ApprovalPolicy names only CommandKind.shell (POSIX) → interactive session refused 409 shell_session_requires_approval",
  "operations: approval gate on interactive shell", "operations", "thin", "silent", "low",
  f"{E2E} shape; copy the powershell variant and change policy kinds", "tests/test_approval_workflows.py::test_interactive_shell_is_refused_under_a_script_policy",
  "expected to fail: the gate resolves policy for CommandKind.powershell only. Confirm intended semantics in APPROVAL-WORKFLOWS.md before treating as a bug.",
  expected_fail=True, notes=["depends on revision 0041"])

# ───────────────────────── server: agent-facing HTTP bounds ─────────────────────────
R("SRV-14", "server", "integration", "POST /api/v1/agents/me/monitoring/results",
  "no bearer → 401; quarantined → 403; >100 results → 422; duplicate result ids in a batch → 422; collected_at >5 min in future → 422 monitoring_result_from_future",
  "trust: agent bearer + operations: monitoring ingest bounds", "trust", "zero", "silent", "low",
  f"{E2E} shape; enroll, assign policy, then post crafted batches", "tests/test_monitoring.py",
  "Five fail-closed branches with zero HTTP tests; only core-level detail-size is tested.")
R("SRV-15", "server", "integration", "POST /api/v1/heartbeat bounds (schemas.py:214-228, 412, 419-427)",
  "inventory_hashes >16, pending_results >256, capabilities >16, logged_in_user of 64 KiB → 422 each",
  "trust: agent→server payload bounds", "trust", "zero", "silent", "low",
  f"{E2E} shape", "tests/test_agent_version_reporting.py::test_empty_oversized_and_malformed_versions_are_rejected",
  "expected to fail for logged_in_user: the field has no max_length. The others are declared but unpinned.",
  expected_fail=True)
R("SRV-16", "server", "integration", "POST /api/v1/agents/credentials/reattach nonce",
  "reattach replays the previous rotation_nonce → refused exactly like renew replay; no new credential minted",
  "trust: agent credential lifecycle", "trust", "zero", "silent", "low",
  f"{E2E} shape", "tests/test_agent_credential_expiry.py::test_replayed_nonce_is_rejected",
  "agents.py:320-331 compares rotation_nonce on reattach but only the renew path has a replay test.")
R("SRV-17", "server", "integration", "POST /api/v1/commands/{id}/result unknown id (agents.py:910)",
  "agent posts a result for a command id that does not exist or belongs to another agent → 404, nothing stored",
  "trust: agent can only touch its own commands", "trust", "thin", "silent", "low",
  f"{E2E} shape; two enrolled agents", "tests/test_e2e.py::test_result_before_dispatch_is_rejected",
  "Cross-agent result injection is the security-relevant case of this 404.")
R("SRV-18", "server", "integration", "agents/me/shell-sessions/{id}/complete + frame validation (shell_sessions.py:93-99)",
  "agent completes a session it does not own → 404; output frame with bad stream / bad base64 / empty → 422 code",
  "trust: shell relay (arbitrary execution channel)", "trust", "zero", "silent", "low",
  f"{E2E} shape; open session via operator API, attach as agent", "tests/test_shell_sessions.py",
  "complete has no HTTP test at all; the three 422 frame branches are untriggered.")
R("SRV-19", "server", "integration", "app/api/deps.py auth dependencies (19 HTTPException sites)",
  "expired JWT, stale generation, revoked sid, mfa_pending token on a full route, break-glass token on a mint/rotate route → 401/403 with the documented code",
  "trust: operator sessions (#69) + MFA (#67)", "trust", "thin", "silent", "low",
  f"{E2E} shape; mint tokens with app.core.security helpers; one representative route per dependency, parametrized",
  "tests/test_admin_sessions_break_glass.py",
  "All 19 deps.py sites were classed 'unknown' by the survey: status codes are asserted near paths but no test isolates which branch fired.")

# ─────────────────────── server: operator-router error branches ───────────────────────
R("SRV-20", "server", "integration", "PUT/DELETE/POST validate /api/v1/monitoring/webhook-endpoints/{id}",
  "unknown id → 404; stale version → 409 webhook_endpoint_version_conflict; rename onto existing → 409 webhook_endpoint_name_exists; validate on unknown → 404",
  "operations: webhook notifications", "operations", "zero", "visible", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_webhook_notifications.py::test_endpoint_api_authorization_rotation_masking_and_audit",
  "Three routes with no HTTP test; optimistic-concurrency 409 guards against lost updates between two admins.",
  notes=[REDACTION + " (webhook endpoint update/delete)"])
R("SRV-21", "server", "integration", "POST /api/v1/monitoring/webhook-endpoints/{id}/rotate-secret error branches",
  "unknown → 404; stale version → 409; secret version unavailable → 409; keyring unavailable → 503 with code/state; no secret material in body",
  "trust: webhook HMAC secret custody", "trust", "thin", "silent", "medium",
  "E2E shape; monkeypatch keyring to raise the store error", "tests/test_webhook_notifications.py",
  "Rotation happy path is tested; every failure branch is not. Failure must not return or log the secret.",
  notes=[REDACTION])
R("SRV-22", "server", "integration", "GET alerts/{id}/webhook-deliveries + POST webhook-deliveries/{id}/retry",
  "unknown alert/delivery → 404; retry of delivered/in-flight → 409 invalid_state; retry past attempt cap → 409 retry_limit_reached",
  "operations: webhook delivery retry", "operations", "zero", "visible", "low",
  f"{E2E} shape; seed WebhookDelivery rows directly", "tests/test_email_notifications.py::test_delivery_api_auth_masking_and_audited_retry",
  "Both routes have no HTTP test; email has the twin test, so copy it.", notes=[REDACTION])
R("SRV-23", "server", "integration", "POST /api/v1/monitoring/email-deliveries/{id}/retry error branches",
  "unknown → 404; invalid state → 409; attempt cap reached → 409",
  "operations: email delivery retry", "operations", "thin", "visible", "low",
  f"{E2E} shape", "tests/test_email_notifications.py::test_delivery_api_auth_masking_and_audited_retry",
  "Happy path and masking are tested; the three refusals are not.")
R("SRV-24", "server", "integration", "POST/GET/revoke /api/v1/enrollment-tokens",
  "unknown site → 404; assigned user unknown → 404; expiry in past or beyond policy → 422; max_uses over policy → 422; GET/revoke unknown → 404; corrupt assignment → 500 without leaking the hash",
  "trust: enrollment-token issuance", "trust", "thin", "visible", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_enrollment_management.py",
  "Seven untriggered branches on the endpoint that mints fleet-joining credentials.", notes=[REDACTION + " (enrollment_token.*)"])
R("SRV-25", "server", "integration", "GET /api/v1/signing-keys",
  "anonymous → 401; operator → only public key ids/PEMs and states, never private material or file paths",
  "trust: command-signing key registry", "trust", "zero", "silent", "low",
  f"{E2E} shape; scan the JSON for 'PRIVATE KEY' and the configured key path", "tests/test_key_rotation.py",
  "Route has no HTTP test at all.")
R("SRV-26", "server", "integration", "GET /api/v1/enrollment-dashboard",
  "operator with membership in client A only → counts and tokens for client A only; platform admin → all",
  "trust: tenant boundary (#66)", "trust", "zero", "silent", "medium",
  f"{E2E} shape; two clients, {TENANCY} then delete one membership", "tests/test_tenant_authorization.py",
  "Route has no HTTP test; aggregate endpoints are where tenant filters are most often forgotten.",
  notes=["depends on revision 0037 (tenant_scoped_authorization)"])
R("SRV-27", "server", "integration", "GET /healthz, /readyz, /metrics (app/main.py)",
  "DB unreachable → /readyz 503 'Database is unavailable' while /healthz stays 200; /metrics contains no operator emails, tokens, or hostnames",
  "operations: deploy health / observability", "operations", "zero", "visible", "low",
  "ASGITransport against app.main; monkeypatch engine.connect to raise", E2E,
  "None of the three have a test; Render health checks depend on /readyz semantics.")
R("SRV-28", "server", "integration", "app/api/approvals.py policy + request refusals",
  "duplicate policy name → 409; PATCH/DELETE unknown → 404; operator at outstanding-request cap → 429 approval_request_limit_reached; each decision refusal code → its mapped status",
  "operations: approval / two-person authorization (#64)", "operations", "thin", "visible", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_approval_workflows.py",
  "Five untriggered sites; _decision_refusal_status mapping is a table worth pinning.",
  notes=["depends on revision 0041"])
R("SRV-29", "server", "integration", "app/api/admin_sessions.py break-glass + session admin refusals",
  "label taken → 409; disable already-disabled → 409 state_unchanged; unknown account/activation/operator → 404",
  "trust: break-glass credentials (#69)", "trust", "thin", "visible", "low",
  f"{E2E} shape", "tests/test_admin_sessions_break_glass.py",
  "Six untriggered branches on emergency-access administration.", notes=["depends on revision 0039", REDACTION])
R("SRV-30", "server", "integration", "app/api/auth.py operator administration refusals + login lockout",
  "unknown operator on disable/role/platform-admin/memberships/script-permission/revoke-tokens → 404; revoke ungranted script permission → 409; unknown client/membership → 404; Nth failed login → 429",
  "trust: operator roles + script scope + login limit", "trust", "thin", "visible", "low",
  f"{E2E} shape; parametrize over the operator_id routes", "tests/test_administration.py",
  "Eight untriggered branches. Route-level 429 (auth.py:78) is untested even though the limiter is.")
R("SRV-31", "server", "integration", "app/api/mfa.py registration/verify/email/reset refusals",
  "expired challenge → 400 challenge_expired; bad credential id → 400; rename to same name → 409; unknown credential → 404; email verify with no email factor → 404; admin reset unknown operator → 404; verify failure → generic code only",
  "trust: WebAuthn + email OTP MFA (#67/#226)", "trust", "thin", "silent", "medium",
  "E2E shape + tests/webauthn_authenticator.py soft authenticator", "tests/test_mfa_webauthn.py",
  "Eight untriggered branches; the generic-failure branch must not leak which factor check failed.",
  notes=["depends on revisions 0038, 0040", REDACTION])
R("SRV-32", "server", "integration", "app/api/agent_updates.py admin refusals",
  "min_supported_version above release → 400; signing key unavailable → 503; invalid channel filter → 400; resume a non-paused release → 409",
  "operations: agent self-update publication (#63)", "operations", "thin", "visible", "low",
  f"{E2E} shape", "tests/test_agent_self_update.py",
  "503 path proves publishing fails closed when the signing key is missing.", notes=["depends on revision 0035"])
R("SRV-33", "server", "integration", "GET /api/v1/evidence/bundles/export error mapping (evidence.py:58-82)",
  "each EvidencePackageError (too many records, archive too large, signing unavailable) → its status + {code,state} and no partial body",
  "trust: evidence packages (offline-verifiable)", "trust", "zero", "silent", "medium",
  "E2E shape; monkeypatch evidence_packages limits (MAX_ARCHIVE_BYTES) small", "tests/test_evidence_bundles.py",
  "Three untriggered branches; a partial archive returned with 200 would verify as truncated evidence.")
R("SRV-34", "server", "integration", "app/api/scheduled_tasks.py refusals",
  "target agent/site unknown or in another tenant → 404; invalid cron on create/update → 400 (message contains no stack trace); toggle unknown → 404",
  "operations: scheduler", "operations", "zero", "visible", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_scheduled_tasks.py",
  "Five untriggered branches; the 400 echoes the exception text, which the dashboard forwards to the browser (see DSH-08).")
R("SRV-35", "server", "integration", "app/api/script_library.py refusals",
  "script >57344 bytes → 413 script_content_too_large; library at cap → 409; duplicate name → 409; unknown script/version → 404; parameter-value-set store error → mapped status",
  "trust: versioned script custody", "trust", "thin", "visible", "low",
  f"{E2E} shape", "tests/test_script_library.py",
  "Nine untriggered branches on the custody path for code that runs as SYSTEM.", notes=[REDACTION])
R("SRV-36", "server", "integration", "app/api/management.py monitoring policy/alert/maintenance refusals",
  "too many checks or interval out of bounds → 422; stale policy revision → 409; maintenance window cap → 409; ack/resolve in wrong state → 409; assign unavailable operator → 422; unknown alert → 404",
  "operations: monitoring + alert state machine", "operations", "thin", "visible", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_monitoring.py",
  "Eleven untriggered branches; alert state-machine 409s prevent double-resolve races.")
R("SRV-37", "server", "integration", "app/api/management.py patch-approval + agent restore/revoke 404s",
  "unknown patch policy on GET/PUT/DELETE → 404; effective policy / compliance history / restore / revoke for unknown or cross-tenant agent → 404",
  "trust: tenant boundary on agent-scoped reads", "trust", "thin", "silent", "low",
  f"{E2E} shape + {TENANCY}", "tests/test_tenant_authorization.py",
  "Cross-tenant must be indistinguishable from unknown; these 404s are where that holds.")
R("SRV-38", "server", "integration", "remote-desktop mappings + launch refusals (management.py:5260-5317, meshcentral.py:145-228)",
  "unknown agent/mapping → 404; launch error codes → mapped http_status with {code} only",
  "trust: MeshCentral launch", "trust", "thin", "silent", "medium",
  "E2E shape + existing fake MeshCentral client", "tests/test_meshcentral_launch.py",
  "Six untriggered branches.")
R("SRV-39", "server", "integration", "GET /api/v1/audit/anchors/{id}/verify",
  "unknown anchor → 404; tampered anchor row → verify result false with reason",
  "trust: audit chain anchoring", "trust", "thin", "silent", "low",
  f"{E2E} shape", "tests/test_anchoring.py",
  "404 branch untriggered.")

# ───────────────────────── server: Postgres-only ─────────────────────────
R("SRV-40", "server", "integration", "ux_approval_decision_one_per_operator + _spend_approval on PostgreSQL",
  "two sessions approve the same request as the same operator concurrently → exactly one decision row; two dispatches race → approval spent once",
  "operations: two-person authorization under concurrency", "operations", "thin", "silent", "medium",
  "two AsyncSession objects on TEST_POSTGRES_URL engine, asyncio.gather with a barrier", "tests/test_audit_sequence.py::test_concurrent_appends_serialize_on_postgresql",
  "Existing race tests run on SQLite, which serializes writers, so they cannot fail.",
  notes=[PG_ONLY, "depends on revision 0041"])
R("SRV-41", "server", "integration", "SELECT … FOR UPDATE paths on PostgreSQL (reattach, result completion)",
  "two concurrent reattach calls for one agent → one new credential; two concurrent conflicting results → one 204 + one 409",
  "trust: agent credential + result idempotency under concurrency", "trust", "thin", "silent", "medium",
  "PG engine + httpx ASGITransport, two clients with asyncio.gather", "tests/test_audit_sequence.py::test_concurrent_appends_serialize_on_postgresql",
  "FOR UPDATE is a no-op on SQLite; these locks are untested where they matter.", notes=[PG_ONLY])
R("SRV-42", "server", "integration", "support chat technician-launch row lock on PostgreSQL (fix a94747f0)",
  "heartbeat and technician-open race on one agent → launch token derived once; no stale token returned",
  "trust: support chat launch token", "trust", "thin", "silent", "medium",
  "PG engine; two concurrent heartbeats + one technician open", "tests/test_support_chat_technician.py",
  "The recent lock fix has a SQLite test only.", notes=[PG_ONLY, "depends on revisions 0044, 0045"])
R("SRV-43", "server", "integration", "alembic 0013 preflight: duplicate site names",
  "two sites with names equal after normalization under one client → upgrade refuses with the preflight message (SQLite and PostgreSQL)",
  "operations: migration safety", "operations", "zero", "visible", "medium",
  "test_migrations harness: upgrade to 0012, insert rows, upgrade to 0013", "tests/test_migrations.py::test_normalized_name_migration_refuses_ambiguous_existing_rows",
  "0013 checks duplicate_sites but the existing test inserts clients only; PG dialect run missing.",
  notes=[PG_ONLY + " for the PG variant"])
R("SRV-44", "server", "integration", "ux_commands_agent_nonce under the ORM (models vs migrations)",
  "two commands for one agent with the same nonce → IntegrityError on a create_all schema as well as on an alembic schema",
  "trust: server-side nonce uniqueness", "trust", "thin", "silent", "low",
  "AsyncSessionLocal with Base.metadata.create_all (SQLite)", "tests/test_migrations.py::test_command_v2_nonce_is_unique_per_agent",
  "expected to fail: the unique index exists only in alembic 0003/0012, not on the ORM model, so every create_all-based test runs without it.",
  expected_fail=True)

# ───────────────────────── server: external seams ─────────────────────────
R("SRV-45", "server", "integration", "app/core/anchor_publish.py S3Backend put failure",
  "moto-backed put_object raises ClientError → publication row stays unpublished, lag alert eventually fires, retry later publishes",
  "trust: external audit anchor (WORM)", "trust", "thin", "visible", "medium",
  "moto mock_aws + botocore Stubber to inject ClientError on first put", "tests/test_anchor_publish.py::test_s3_backend_publishes_with_object_lock",
  "Outage is tested only with a BrokenBackend stub, not the real S3 error path.")
R("SRV-46", "server", "integration", "S3Backend republish after DB commit failure",
  "publish succeeds, DB commit fails, publisher retries → no second object version (or a documented, verifiable duplicate)",
  "trust: anchor idempotency", "trust", "zero", "silent", "medium",
  "moto; monkeypatch session.commit to raise once", "tests/test_anchor_publish.py::test_republish_is_idempotent",
  "expected to fail: put_object has no existence check; idempotency is only the DB row.", expected_fail=True)
R("SRV-47", "server", "integration", "S3Backend against a bucket without Object Lock",
  "bucket created without ObjectLockEnabledForBucket → publisher refuses (or prodcheck fails) instead of writing mutable anchors",
  "trust: WORM guarantee", "trust", "zero", "silent", "medium",
  "moto bucket without lock config", "tests/test_anchor_publish.py::test_s3_backend_publishes_with_object_lock",
  "expected to fail: S3Backend never verifies bucket lock configuration.", expected_fail=True)
R("SRV-48", "server", "unit", "webhook HMAC receiver-side verification",
  "reference verifier given wrong key, tampered body, or timestamp outside tolerance → rejects; correct → accepts (pinned vector)",
  "trust: webhook authenticity", "trust", "thin", "silent", "low",
  "pure: reuse signature_for; add a tiny verify helper in the test", "tests/test_webhook_notifications.py::test_signature_vector_is_stable",
  "Only a positive vector exists; nothing proves a forged delivery would fail verification.")
R("SRV-49", "server", "integration", "webhook delivery against a hostile receiver",
  "receiver returns >16 KiB of headers or never finishes → delivery marked failed within the timeout, worker not blocked",
  "operations: outbound webhook safety", "operations", "zero", "silent", "medium",
  "local asyncio TCP server fixture emitting oversized headers", "tests/test_webhook_notifications.py",
  "MAX_RESPONSE_HEADER_BYTES is configured but never exercised.")
R("SRV-50", "server", "integration", "webhook retry signature timestamp",
  "delivery retried 10 minutes later → test pins current behavior (original timestamp reused) and documents the receiver freshness implication",
  "operations: webhook retry semantics", "operations", "zero", "silent", "low",
  "freeze time between attempts", "tests/test_webhook_notifications.py",
  "Design decision row: receivers enforcing freshness reject late retries; make it explicit before changing.")
R("SRV-51", "server", "integration", "MeshCentral launch: at-rest scan",
  "after a successful launch → no column in any table contains the plaintext login URL or its token",
  "trust: minted remote-desktop URL never persisted in plaintext", "trust", "thin", "silent", "low",
  "E2E shape + fake MeshCentral; iterate Base.metadata.sorted_tables and grep row values", "tests/test_meshcentral_launch.py::test_successful_launch_mints_once_and_audits",
  "Existing tests check audit detail and GET responses; a DB-wide scan closes the 'never persisted' claim.")

# ─────────────────────────────── dashboard ───────────────────────────────
R("DSH-01", "dashboard", "unit", "dashboard/test/support-chat-core.test.ts (orphan)",
  "npm test runs the file → fragment-token, oversize-body, and cross-origin chat proxy tests execute in CI",
  "trust: end-user chat token (fragment, never query)", "trust", "zero", "silent", "low",
  "none: file exists", "test/support-chat-core.test.ts",
  "Only test of handleChat and it has never run in CI. May fail on first run; it has not been executed against current code.",
  notes=[PKG_STEP], handlers=["GET /api/chat/[...parts]", "POST /api/chat/[...parts]"])
R("DSH-02", "dashboard", "unit", "src/app/api/endpoints/[endpointId]/shell-sessions/** → new shell-session-route-core.ts",
  "session revalidation: revoked server session → 401 before forwarding; role gating: readonly → 403; allowlisting: only shell frame fields reach the browser",
  "trust: interactive shell via BFF", "trust", "zero", "silent", "medium",
  "extract handlers into *-route-core.ts with injected { getSession, api } like operators/route.ts; fakes record calls",
  "test/operator-management-route-core.test.ts",
  "expected to fail: these 5 handlers check only that the session cookie exists, not getDashboardSession revalidation.",
  expected_fail=True, notes=[PKG_STEP],
  handlers=["POST /api/endpoints/[endpointId]/shell-sessions", "GET /api/endpoints/[endpointId]/shell-sessions/[sessionId]", "POST /api/endpoints/[endpointId]/shell-sessions/[sessionId]", "POST /api/endpoints/[endpointId]/shell-sessions/[sessionId]/input", "GET /api/endpoints/[endpointId]/shell-sessions/[sessionId]/output"])
R("DSH-03", "dashboard", "unit", "src/app/api/endpoints/[endpointId]/commands/route.ts → command-route-core.ts",
  "session revalidation: revoked session → 401; role gating: readonly → 403 without forwarding; allowlisting: dispatch response limited to command id/status/kind",
  "trust: command dispatch via BFF", "trust", "zero", "silent", "medium",
  "extract with injected deps; reuse validateDispatchInput", "test/operator-management-route-core.test.ts",
  "expected to fail: cookie-presence check only. validateDispatchInput is tested; the handler is not.",
  expected_fail=True, notes=[PKG_STEP], handlers=["POST /api/endpoints/[endpointId]/commands"])
R("DSH-04", "dashboard", "unit", "remote-desktop availability + launches route.ts → remote-desktop-route-core.ts",
  "session revalidation → 401 on revoked session; role gating: readonly launch → 403; allowlisting: launch returns login URL once and nothing else",
  "trust: MeshCentral launch via BFF", "trust", "zero", "silent", "medium",
  "extract with injected deps", "test/operator-management-route-core.test.ts",
  "expected to fail: cookie-presence check only.", expected_fail=True, notes=[PKG_STEP],
  handlers=["GET /api/endpoints/[endpointId]/remote-desktop/availability", "POST /api/endpoints/[endpointId]/remote-desktop/launches"])
R("DSH-05", "dashboard", "unit", "POST /api/endpoints/[endpointId]/support-chat (technician open)",
  "session revalidation → 401; role gating: readonly → 403; allowlisting: only conversation id/state picked; capability-unsupported 409 surfaced",
  "trust: support-chat-launch-v1 technician launch", "trust", "zero", "silent", "medium",
  "extract into support-chat-route-core (already exists for end-user) with injected deps", "test/support-chat-core.test.ts",
  "expected to fail: cookie-presence check only.", expected_fail=True, notes=[PKG_STEP],
  handlers=["POST /api/endpoints/[endpointId]/support-chat"])
R("DSH-06", "dashboard", "unit", "src/app/api/auth/logout/route.ts",
  "session revalidation: not needed, but upstream revoke failure → cookie still cleared; role gating: n/a; allowlisting: fixed {ok} body",
  "trust: operator session end", "trust", "zero", "visible", "low",
  "extract handler with injected revoke fn + cookie jar fake", "test/admin-sessions-core.test.ts",
  "Logout that leaves the cookie set on upstream error would keep a session alive in the browser.", notes=[PKG_STEP],
  handlers=["POST /api/auth/logout"])
R("DSH-07", "dashboard", "unit", "src/app/api/auth/login/route.ts",
  "session revalidation: n/a; role gating: n/a; allowlisting: success sets HttpOnly+Secure+SameSite cookie and returns no token; mfa_pending returns only next-step",
  "trust: operator login", "trust", "thin", "visible", "low",
  "extract handler; inject login API fn", "test/mfa-core.test.ts",
  "Helpers are tested; the handler that sets the cookie is not.", notes=[PKG_STEP], handlers=["POST /api/auth/login"])
R("DSH-08", "dashboard", "unit", "src/app/api/schedules/** → schedules-route-core.ts",
  "cross-origin POST → 403 before forwarding; scheduleId with '/' or '..' → encoded; upstream error → generic message, never err.message; role gating: readonly → 403; allowlisting: pick schedule fields",
  "operations: scheduled tasks via BFF", "operations", "zero", "silent", "medium",
  "extract with injected deps", "test/maintenance-window-route-core.test.ts",
  "expected to fail: no same-origin check, id not URL-encoded, server err.message echoed to the browser.",
  expected_fail=True, notes=[PKG_STEP],
  handlers=["POST /api/schedules", "POST /api/schedules/[scheduleId]/toggle", "POST /api/schedules/[scheduleId]/run-now"])
R("DSH-09", "dashboard", "unit", "src/app/api/support/** technician conversation handlers → support-route-core.ts",
  "session revalidation → 401; role gating: readonly may read but not send/close; allowlisting: message/conversation fields reshaped; cross-tenant 404 surfaced as not found",
  "trust: technician chat", "trust", "zero", "silent", "medium",
  "extract with injected deps", "test/operator-management-route-core.test.ts",
  "Five handlers, zero tests.", notes=[PKG_STEP],
  handlers=["GET /api/support/conversations", "GET /api/support/conversations/[conversationId]", "POST /api/support/conversations/[conversationId]/messages", "POST /api/support/conversations/[conversationId]/close", "GET /api/support/unread-count"])
R("DSH-10", "dashboard", "unit", "enrollment-tokens + enrollment-agents revoke handlers → enrollment-route-core.ts",
  "session revalidation → 401; role gating per handler; allowlisting: plaintext token returned once on create and never on list/revoke",
  "trust: enrollment-token issuance via BFF", "trust", "thin", "visible", "medium",
  "extract with injected deps; production-smoke.mjs mock responses as fixtures", "test/operator-management-route-core.test.ts",
  "Covered only by production-smoke.mjs, which CI does not run. Handlers pass server JSON through today.",
  notes=[PKG_STEP],
  handlers=["POST /api/enrollment-tokens", "POST /api/enrollment-tokens/[tokenId]/revoke", "POST /api/enrollment-agents/[agentId]/revoke"])
R("DSH-11", "dashboard", "unit", "lib/admin-sessions-route-core.ts handleListBreakGlass + break-glass activations GET",
  "session revalidation → 401; role gating: non-admin upstream 403 surfaced; allowlisting: credential secrets never present in list output",
  "trust: break-glass credentials", "trust", "zero", "silent", "low",
  "existing injected deps", "test/admin-sessions-core.test.ts",
  "Two GET handlers untested; both pass server JSON through.", notes=[PKG_STEP],
  handlers=["GET /api/auth/break-glass", "GET /api/auth/break-glass/activations"])
R("DSH-12", "dashboard", "unit", "lib/mfa-route-core.ts untested handlers",
  "handleRenameCredential, handleSendEmailCode (enrollment + login), handleEmailFactorMutation (verify/remove), handleStepUpOptions, mfa status GET: session revalidation (or mfa_pending restriction) → 401; allowlisting: no challenge secret beyond WebAuthn options",
  "trust: MFA (#67/#226)", "trust", "zero", "silent", "low",
  "existing injected deps in mfa-route-core", "test/mfa-core.test.ts",
  "Seven handlers without tests.", notes=[PKG_STEP],
  handlers=["PUT /api/auth/mfa/credentials/[credentialId]", "POST /api/auth/mfa/email/enrollment/start", "POST /api/auth/mfa/email/enrollment/verify", "POST /api/auth/mfa/email/remove", "POST /api/auth/mfa/login/email/send", "POST /api/auth/mfa/step-up/options", "GET /api/auth/mfa/status"])
R("DSH-13", "dashboard", "unit", "lib/script-library-route-core.ts handleScriptVersionCreate",
  "session revalidation → 401; role gating: readonly → 403; allowlisting: version fields only; 413 surfaced as size error",
  "trust: script custody", "trust", "zero", "visible", "low",
  "existing injected deps", "test/script-library.test.ts",
  "Only script-library handler without a test.", notes=[PKG_STEP], handlers=["POST /api/scripts/[scriptId]/versions"])
R("DSH-14", "dashboard", "unit", "lib/webhook-route-core.ts rotate/delete/validate",
  "session revalidation → 401; role gating: non-admin → 403; allowlisting: rotate returns new secret exactly once and delete/validate return no secret",
  "trust: webhook HMAC secret", "trust", "zero", "silent", "low",
  "existing injected deps", "test/webhook-route-core.test.ts",
  "Three handlers untested; rotate handles secret material.", notes=[PKG_STEP],
  handlers=["POST /api/webhook-endpoints/[endpointId]/rotate", "DELETE /api/webhook-endpoints/[endpointId]", "POST /api/webhook-endpoints/[endpointId]/validate"])
R("DSH-15", "dashboard", "unit", "GET /api/patch-compliance/export",
  "session revalidation → 401; role gating: none today (pin decision); allowlisting: CSV cells starting with = + - @ are escaped",
  "operations: compliance export", "operations", "zero", "visible", "low",
  "extract with injected deps", "test/patch-compliance-core.test.ts",
  "Untested export; CSV formula injection from hostnames/update titles is the classic risk.", notes=[PKG_STEP],
  handlers=["GET /api/patch-compliance/export"])
R("DSH-16", "dashboard", "unit", "POST /api/sites/[siteId]/installer-package",
  "session revalidation → 401; role gating: !canManage → 403; allowlisting: Content-Disposition filename sanitized; upstream JSON error never streamed as binary",
  "trust: installer carries enrollment token", "trust", "thin", "silent", "medium",
  "extract with injected deps; fake binary stream", "test/installer-download-core.test.ts",
  "Helpers tested; handler not.", notes=[PKG_STEP], handlers=["POST /api/sites/[siteId]/installer-package"])
R("DSH-17", "dashboard", "unit", "assistant passthrough response allowlist",
  "upstream adds an unexpected field (e.g. provider key) → BFF response omits it",
  "product: dashboard assistant", "product", "thin", "silent", "low",
  "existing assistant-route-core fakes", "test/assistant-route-core.test.ts",
  "Session revalidation and role are tested; allowlisting is 'pass through' today.", notes=[PKG_STEP],
  handlers=["GET /api/assistant/[...path]", "POST /api/assistant/[...path]"])
R("DSH-18", "dashboard", "unit", "GET /api/health + lib/nodelink-health-core.ts",
  "upstream down → status 'degraded' with no upstream URL or error text; session/role: public by design",
  "product: health endpoint", "product", "zero", "visible", "low",
  "pure core + injected fetch", "test/runtime-config.test.ts",
  "Public route; must not disclose internal topology.", notes=[PKG_STEP], handlers=["GET /api/health"])
R("DSH-19", "dashboard", "unit", "src/proxy.ts proxy() + config.matcher",
  "/login?email=x&password=y → redirect to /login with query stripped; other paths untouched; matcher is exactly ['/login']",
  "trust: credentials kept out of URLs", "trust", "thin", "silent", "low",
  "construct NextRequest; read node_modules/next/dist/docs proxy section first (Next 16 renamed middleware)",
  "test/dashboard-auth-core.test.ts",
  "sanitizedLoginUrl is tested; the proxy wiring and matcher are not.", notes=[PKG_STEP])
R("DSH-20", "dashboard", "unit", "lib/nodelink-api-core.ts requestNodelinkApi / extractNodelinkErrorCode",
  "non-JSON error body, {detail:{code}}, {detail:'str'}, 5xx HTML → typed error with code or generic; bearer never echoed",
  "product: BFF→server client", "product", "thin", "silent", "low",
  "injected fetchImpl", "test/runtime-config.test.ts",
  "Every handler depends on it; error-shape parsing is untested.", notes=[PKG_STEP])
R("DSH-21", "dashboard", "unit", "lib/dashboard-session.ts getDashboardSession",
  "/auth/me 401 → null; network error → null (fail closed); 200 → operator with role",
  "trust: per-request session revalidation", "trust", "zero", "silent", "medium",
  "needs `cookies()` and fetch injected: split into dashboard-session-core.ts", "test/runtime-config.test.ts",
  "The single function behind 'session revalidation' for 60+ handlers has no test.", notes=[PKG_STEP])
R("DSH-22", "dashboard", "unit", "lib/client-navigation.ts, endpoint-list.ts, dashboard-clock.ts",
  "pure formatting/filter helpers given representative inputs → stable outputs (sorting, relative time, empty states)",
  "product: navigation and lists", "product", "zero", "visible", "low",
  "pure", "test/dashboard-overview-core.test.ts",
  "Untested pure modules; cheap.", notes=[PKG_STEP])
R("DSH-23", "dashboard", "contract", "BFF↔server response contracts (contracts/bff/*.json, new)",
  "fixture generated from the FastAPI response model fails Pydantic validation server-side OR fails the *FromUnknown parser dashboard-side → the suite that changed fails",
  "product: BFF→server schema drift", "product", "zero", "silent", "medium",
  "server test dumps example responses per route into contracts/bff/; dashboard tests feed them to parsers",
  "tests/test_command_envelope_vectors.py + agent/internal/verify/vectors_test.go (shared-vector pattern)",
  "No test pins dashboard parsers to server shapes; drift surfaces as 502s in production.", notes=[PKG_STEP])
R("DSH-24", "dashboard", "unit", "components/login-form.tsx (component tier)",
  "submit with empty fields → inline errors, no fetch; mfa_pending response → MFA step rendered; password field never placed in URL",
  "trust: operator login UI", "trust", "zero", "visible", "high",
  "new component tier (see runner changes): node --test + tsx loader + happy-dom + @testing-library/react",
  "none in repo (new tier)", "Start the tier with the auth surface.", notes=[PKG_STEP])
R("DSH-25", "dashboard", "unit", "components/command-dispatch-form.tsx (component tier)",
  "script >56 KiB → submit disabled with size message; readonly role → form not rendered; governed kind → approval required notice",
  "operations: command dispatch UI", "operations", "zero", "visible", "high",
  "component tier", "none in repo (new tier)", "Highest-blast-radius form in the UI.", notes=[PKG_STEP])
R("DSH-26", "dashboard", "unit", "components/approval-queue-view.tsx (component tier)",
  "request created by current operator → approve button absent; approved once by another → shows 1 of 2",
  "operations: two-person authorization UI", "operations", "zero", "visible", "high",
  "component tier", "none in repo (new tier)", "UI must mirror self-approval refusal.", notes=[PKG_STEP])
R("DSH-27", "dashboard", "unit", "components/support-chat-panel.tsx + shell-session-panel.tsx (component tier)",
  "chat token read from location.hash only; shell output rendered as text (no HTML injection from endpoint output)",
  "trust: end-user/endpoint-controlled content in the browser", "trust", "zero", "silent", "high",
  "component tier", "none in repo (new tier)", "Endpoint output is attacker-influenced; rendering must stay text-only.", notes=[PKG_STEP])
R("DSH-28", "dashboard", "unit", "src/app/endpoints/[endpointId]/page.tsx (page tier)",
  "server returns 404/403/500 → page renders not-found/forbidden/error state without upstream detail",
  "product: endpoint detail page", "product", "zero", "visible", "high",
  "page tier: render the async server component with injected API fns", "none in repo (new tier)",
  "One representative page proves the page-tier harness before scaling to 42 pages.", notes=[PKG_STEP])

# ─────────────────────────────── agent ───────────────────────────────
R("AGT-01", "agent", "unit", "internal/telemetry psFloat + round2 (move to untagged telemetry_parse.go)",
  "'12,5', ' 7 ', '', 'garbage', '1e3' → (12.5,true),(7,true),(0,false),(0,false),(1000,true); round2 half-up",
  "operations: heartbeat telemetry", "operations", "zero", "visible", "low",
  "table-driven, stdlib testing; parser moved out of the windows-tagged file so it runs on ubuntu too",
  "agent/internal/patching/psoutput_test.go",
  "Package has 4 files and 0 tests; the comma-locale fix is exactly what breaks silently on de-DE hosts.", notes=[GO_LF])
R("AGT-02", "agent", "unit", "internal/telemetry Linux parsers (extract parseProcStat/parseMeminfo/parseUptime/parseOSRelease)",
  "captured /proc and /etc/os-release fixture strings (incl. missing MemAvailable, quoted PRETTY_NAME) → expected Sample fields and Available flags",
  "operations: heartbeat telemetry", "operations", "zero", "visible", "low",
  "testdata/ fixtures captured from real hosts; no file system access in tests",
  "agent/internal/inventory/software_test.go (normalize-from-fixture pattern)",
  "Hardcoded os.ReadFile paths today; extracting pure parsers is the seam.", notes=[GO_LF])
R("AGT-03", "agent", "unit", "internal/telemetry collect error mapping",
  "psOutput returns error for CPU only → CPUAvailable=false and CPUPercent=0, other fields still populated",
  "operations: telemetry truthfulness", "operations", "zero", "silent", "low",
  "make psOutput a package var; inject a fake; run on windows job", "agent/internal/power/power_test.go (injected command var)",
  "A failed query must read 'unavailable', not '0% CPU, healthy'.", notes=[GO_LF, WIN_JOB])
R("AGT-04", "agent", "unit", "internal/telemetry CollectContext cancellation",
  "ctx cancelled mid-sample → returns within 100 ms with empty Sample",
  "operations: runner loop liveness", "operations", "zero", "silent", "low",
  "fake psOutput that blocks until ctx.Done", "agent/internal/service/runner_test.go",
  "osVersion uses context.Background and cannot be cancelled; test pins the rest.", notes=[GO_LF])
R("AGT-05", "agent", "contract", "internal/inventory ContentHash vs contracts/test-vectors/inventory-hash-v1.json (new)",
  "payloads with non-ASCII ('Microsoft® Office'), '<>&', nested arrays, and large ints → digest equals pinned value (Go side)",
  "operations: inventory transport canonicalization (§6.1)", "operations", "zero", "silent", "low",
  "shared vector file read via ../../../contracts path like verify/vectors_test.go", "agent/internal/verify/vectors_test.go",
  "expected to fail: Go json.Marshal HTML-escapes <>& and emits raw UTF-8; Python json.dumps defaults ensure_ascii=True. Any such section hashes differently and resends forever.",
  expected_fail=True, notes=[GO_LF, "pair row: CTR-05 (Python side)"])
R("AGT-06", "agent", "unit", "internal/inventory Windows section normalizers (extract NormalizeSystem/CPU/Memory/Storage/Network)",
  "captured Get-CimInstance JSON (single object and array forms, nulls) → section maps with bounded fields",
  "operations: inventory collection", "operations", "zero", "visible", "medium",
  "move map-building out of inventory_windows.go (346 lines) into untagged normalize_*.go; testdata JSON fixtures",
  "agent/internal/inventory/defender_test.go",
  "Largest untested Windows file; other sections already follow the Normalize* pattern.", notes=[GO_LF])
R("AGT-07", "agent", "unit", "internal/svcproc unmarshalMaybeArray, firstLine, lastLine",
  "ConvertTo-Json single object vs array vs null vs empty → slice of len 1/N/0/0",
  "operations: service/process management", "operations", "zero", "silent", "low",
  "move to untagged file; table-driven", "agent/internal/patching/psoutput_test.go",
  "The PowerShell single-object quirk is a known silent data-loss bug class.", notes=[GO_LF])
R("AGT-08", "agent", "integration", "internal/patching embedded WUA scan/install scripts",
  "script parses; with stubbed Microsoft.Update.Session COM objects → emits the JSON contract BuildSection expects; install with reboot-required → flag set",
  "operations: Windows Update (#51)", "operations", "zero", "visible", "high",
  "agent/test/wua_scripts.ps1: extract script literal from scan_windows.go/install_windows.go, shadow New-Object -ComObject with stubs",
  "agent/test/reboot_probe_script.ps1",
  "Scripts never execute in CI; reboot probe proved the extraction pattern works.")
R("AGT-09", "agent", "unit", "internal/patching encodeUTF16LE",
  "ASCII, non-BMP, and empty script → base64 of UTF-16LE that PowerShell -EncodedCommand decodes back identically",
  "operations: script transport to PowerShell", "operations", "zero", "silent", "low",
  "table-driven with known vectors", "agent/internal/patching/psoutput_test.go",
  "Pure function, windows-tagged.", notes=[GO_LF, WIN_JOB])
R("AGT-10", "agent", "unit", "internal/power power_windows commandContext args",
  "reboot with delay 60 / shutdown / cancel → exact shutdown.exe argv incl. /c reason length bound",
  "operations: power operations", "operations", "zero", "visible", "low",
  "commandContext is already a var: inject recorder", "agent/internal/power/power_test.go",
  "Argument construction is untested; a wrong flag reboots immediately.", notes=[GO_LF, WIN_JOB])
R("AGT-11", "agent", "unit", "internal/deploy deploy_windows Authenticode + msiexec args",
  "unsigned or wrong-publisher installer → refused before execution; MSI → msiexec /i … /qn /norestart argv",
  "trust: software deployment signature check", "trust", "zero", "silent", "medium",
  "inject verifier + command runner vars", "agent/internal/deploy/deploy_test.go",
  "Signature refusal is the security property and has no test.", notes=[GO_LF, WIN_JOB])
R("AGT-12", "agent", "unit", "internal/selfupdate selfupdate_windows Authenticode failure path",
  "downloaded binary fails Authenticode → no replace, journal records failure, report says failed",
  "trust: agent self-update signature", "trust", "thin", "silent", "medium",
  "inject verifier; temp dir", "agent/internal/selfupdate/selfupdate_windows_test.go",
  "Replace/prune is tested; refusal on bad signature is not.", notes=[GO_LF, WIN_JOB])
R("AGT-13", "agent", "integration", "internal/client SubmitInventory",
  "server 200 → hashes acknowledged; 413/422 → error surfaced, section not marked sent; Authorization header carries bearer",
  "operations: agent→server inventory", "operations", "zero", "silent", "low",
  "httptest.Server recording requests", "agent/internal/client/client_test.go",
  "No direct test of the call.", notes=[GO_LF])
R("AGT-14", "agent", "integration", "internal/client SubmitMonitoringResults",
  "batch >100 results → split client-side; 409 superseded → dropped not retried; 422 future → logged and dropped",
  "operations: agent→server monitoring", "operations", "zero", "silent", "low",
  "httptest.Server", "agent/internal/client/client_test.go",
  "Pairs with SRV-14 server bounds.", notes=[GO_LF])
R("AGT-15", "agent", "integration", "internal/client ReportSelfUpdate + service/selfupdate.go:87",
  "5xx → retried with backoff and same payload; 403 → not retried",
  "operations: self-update outcome report", "operations", "zero", "silent", "low",
  "httptest.Server", "agent/internal/selfupdate/selfupdate_test.go",
  "No direct test.", notes=[GO_LF])
R("AGT-16", "agent", "integration", "internal/client shell-session input/output/complete",
  "output frames ≤16 KiB with monotonically increasing seq; identical retry reuses seq; complete posts once",
  "trust: shell relay agent side", "trust", "thin", "silent", "low",
  "httptest.Server", "agent/internal/client/support_chat_test.go",
  "Only attach is tested (via stub).", notes=[GO_LF])
R("AGT-17", "agent", "contract", "advertised capability list vs server max (16)",
  "len(supported capabilities) ≤ 16 and each ≤ 64 chars",
  "trust: enroll/heartbeat negotiation", "trust", "zero", "silent", "low",
  "table test over the capability constant; comment links schemas.py:214-228", "agent/internal/client/client_test.go",
  "Agent advertises about 13-14 today against a hard 16; one more capability-gated feature away from 422 on every heartbeat.", notes=[GO_LF])
R("AGT-18", "agent", "unit", "internal/service credential rotation nonce durability",
  "process dies after renew request is sent but before identity save → restart retries with a fresh nonce and server-side state stays consistent",
  "trust: agent credential lifecycle", "trust", "thin", "silent", "medium",
  "runner_test httptest server + injected save failure", "agent/internal/service/runner_test.go",
  "newRotationNonce is not persisted; test pins current behavior and documents the recovery path.", notes=[GO_LF])
R("AGT-19", "agent", "unit", "cmd/agent runValidateUpgrade + runEnroll",
  "config missing identity / mismatched server_url / unreadable file → non-zero exit with stable message (installer relies on it)",
  "trust: installer upgrade gate", "trust", "zero", "silent", "low",
  "temp dir configs; call run* functions directly", "agent/cmd/agent/main_test.go",
  "Called by the .iss upgrade path; only exercised by CI fresh install.", notes=[GO_LF])
R("AGT-20", "agent", "unit", "internal/monitoring probe_windows DiskPercent/ServiceState parsing",
  "captured outputs (locale decimals, missing drive, stopped/unknown service) → probe results",
  "operations: monitoring checks", "operations", "thin", "silent", "low",
  "extract parse funcs; table-driven", "agent/internal/monitoring/probe_windows_test.go",
  "Reboot probe is well covered; the other two probes are not.", notes=[GO_LF])
R("AGT-21", "agent", "contract", "internal/verify command-v3 invalid vectors + signed vector",
  "each invalid[] case in command-v3.json → verifier error code; signed v3 vector verifies with its public key",
  "trust: command-v3 envelope", "trust", "zero", "silent", "low",
  "extend vectors_test.go; requires CTR-02 to add signature to the vector file", "agent/internal/verify/vectors_test.go",
  "v3 is the production format but only its canonical bytes are pinned.", notes=[GO_LF, "pair row: CTR-01/CTR-02 (Python side)"])

# ───────────────────────────── contracts ─────────────────────────────
R("CTR-01", "contracts", "contract", "contracts/test-vectors/command-v3.json invalid[] (Python side)",
  "missing-key-id and retired-key-is-not-a-wire-state cases → server envelope validation refuses with stable codes",
  "trust: command-v3 envelope", "trust", "zero", "silent", "low",
  "extend tests/test_command_envelope_vectors.py", "tests/test_command_envelope_vectors.py::test_invalid_vectors_fail_closed_with_stable_codes",
  "Negative vectors exist in the file and are consumed by neither runtime.")
R("CTR-02", "contracts", "contract", "contracts/test-vectors/command-v3.json signed vector",
  "add public_key_b64 + signature_b64 for a v3 envelope → Python signs to the same bytes and Go verifies",
  "trust: command-v3 signature parity", "trust", "zero", "silent", "low",
  "deterministic Ed25519 test key in the vector file", "tests/test_command_envelope_vectors.py::test_valid_vectors_match_canonical_bytes_and_signatures",
  "v2 has signature parity; v3 (current) does not.")
R("CTR-03", "contracts", "contract", "contracts/*.schema.json structural validation",
  "every valid vector validates against its schema; every invalid vector fails schema or semantic checks",
  "trust: wire contracts", "trust", "zero", "silent", "medium",
  "Python only (Go is stdlib-only); needs a JSON Schema validator (see runner changes)",
  "tests/test_evidence_bundles.py::test_golden_v1_contract_vector_and_schema_are_stable",
  "No test loads a schema as a schema; they can drift from the vectors unnoticed.")
R("CTR-04", "contracts", "contract", "contracts/test-vectors/command-v1.json (orphan)",
  "v1 envelope presented to server and agent → both refuse as downgrade (or the files are retired)",
  "trust: downgrade rejection", "trust", "zero", "silent", "low",
  "Python + Go vector tests", "agent/internal/verify/vectors_test.go",
  "Consumed by no test on either side; decide: assert refusal or delete.")
R("CTR-05", "contracts", "contract", "contracts/test-vectors/inventory-hash-v1.json (Python side)",
  "same payloads as AGT-05 → canonical_inventory_bytes digest equals pinned value",
  "operations: inventory canonicalization (§6.1)", "operations", "zero", "silent", "low",
  "move the empty-payload pin from tests/test_inventory.py:127 into the shared file and add cases",
  "tests/test_inventory.py",
  "expected to fail together with AGT-05 until one side changes; §6.1 requires both suites to assert the same vector.",
  expected_fail=True, notes=["pair row: AGT-05"])
R("CTR-06", "contracts", "contract", "evidence-bundle-v1 / evidence-package-v1 negative vectors",
  "tampered record hash, wrong bundle_id, reordered package entries → offline verifier refuses with a stable reason",
  "trust: offline-verifiable evidence", "trust", "zero", "silent", "low",
  "add invalid[] to both vector files; Python only (server-only format)", "tests/test_evidence_bundles.py",
  "Only positive golden vectors exist.")

# ───────────────────────────── installer ─────────────────────────────
R("INS-01", "installer", "contract", "installer/test/test_support_shortcut_contract.py",
  "unittest discover runs the file → its assertions execute (convert bare functions to a TestCase)",
  "trust: installer contract", "trust", "zero", "silent", "low",
  "none", "installer/test/test_installer_contract.py",
  "expected to fail (to be collected): bare pytest-style functions are invisible to `python -m unittest discover`, so CI runs zero of them.",
  expected_fail=True)
R("INS-02", "installer", "integration", "sidecar nodelink-enroll.token (windows-lifecycle job)",
  "silent install with token file beside the installer and no /TOKEN → config.json enrollment_token equals file contents; file content not logged",
  "trust: enrollment token input", "trust", "zero", "silent", "medium",
  "extend the existing silent-install smoke step", "windows-lifecycle job silent-install smoke (.github/workflows/ci.yml)",
  "Only string-presence is tested.", notes=["CI change: ask first"])
R("INS-03", "installer", "integration", "/TOKEN precedence over sidecar",
  "both /TOKEN=a and sidecar file b present → config uses a",
  "trust: enrollment token input", "trust", "zero", "silent", "medium",
  "same step as INS-02", "windows-lifecycle job silent-install smoke",
  "Precedence is documented and untested.", notes=["CI change: ask first"])
R("INS-04", "installer", "integration", "tokenless upgrade in place",
  "install, then run a newer installer with no token → validate-upgrade passes, identity.json/config.json byte-identical, service running",
  "trust: identity preservation across upgrade", "trust", "zero", "silent", "high",
  "two stamped builds in the windows-lifecycle job", "agent/test/service_lifecycle.ps1",
  "Upgrade mode is only string-tested; losing identity.json forces re-enrollment fleet-wide.", notes=["CI change: ask first"])

# ───────────────────────────── cross-layer e2e ─────────────────────────────
R("X-01", "cross-layer", "e2e", "installer → service → enroll → first heartbeat (windows-lifecycle)",
  "local uvicorn (SQLite) started in the job, installer with server_url override for CI, /TOKEN from a freshly created token → agent row appears with a heartbeat within 60 s",
  "trust: installer→agent→server first contact", "trust", "zero", "visible", "high",
  "start server in background step; CI-only server_url define in the .iss compile; poll /api/v1/agents",
  "agent/test/service_lifecycle.ps1",
  "No server runs in the Windows job today; the smoke points config at the production URL.", notes=["CI change: ask first"])
R("X-02", "cross-layer", "contract", "Go client vs recorded server responses (contracts/agent-api/*.json, new)",
  "Python test records real FastAPI responses for enroll/heartbeat/result/renew; Go client decodes each and round-trips its own request into the server schema",
  "operations: agent↔server wire shape", "operations", "zero", "silent", "medium",
  "server test writes fixtures; agent test reads via relative path", "agent/internal/verify/vectors_test.go",
  "Both sides test against fakes of each other; nothing catches a field rename.", notes=[GO_LF])
R("X-03", "cross-layer", "e2e", "post-deploy read-only smoke",
  "after deploy: GET /healthz 200, /readyz 200, dashboard /api/health ok, /login renders, anonymous POST /api/enrollment-tokens 401; no writes",
  "operations: deploy verification", "operations", "zero", "visible", "low",
  "node script reusing production-smoke.mjs assertions without the mock; run from a workflow_dispatch job",
  "dashboard/scripts/production-smoke.mjs",
  "Nothing checks the deployed Render/Vercel pair today.", notes=["CI change: ask first"])
R("X-04", "cross-layer", "e2e", "dashboard/scripts/production-smoke.mjs in CI",
  "dashboard job runs smoke:production after build → CSRF 403, token-once, redirect assertions execute on every PR",
  "product: built dashboard against mock API", "product", "zero", "visible", "low",
  "existing script", "dashboard/scripts/production-smoke.mjs",
  "Script exists but no workflow invokes it; it has not been run in this design pass.", notes=["CI change: ask first"])
R("X-05", "cross-layer", "e2e", "support chat end-user path pipe → agent → server → BFF",
  "message written to the named pipe appears in the technician conversation via the BFF; fragment token never sent as query",
  "trust: support chat end-to-end", "trust", "zero", "visible", "high",
  "Go test harness: chatpipe client + agent client pointed at uvicorn; dashboard route-core with real fetch to uvicorn",
  "agent/internal/chatpipe/*_test.go + test/support-chat-core.test.ts",
  "Each hop is tested in isolation with fakes.")


# ─────────────────────────────── seams (§3) ───────────────────────────────
SEAMS = [
    dict(n=1, name="Agent → server", parties="Go agent (internal/client, internal/service) ↔ FastAPI agents.py / agent_updates.py",
         transport="HTTPS JSON polling, agent bearer; signed command-v3 envelopes downstream",
         dependency="Server side: real FastAPI app via ASGITransport + Python-simulated agent (fast, deterministic). Agent side: httptest.Server. Add recorded server fixtures (X-02) so the Go client is tested against real response bytes.",
         happy="enroll → heartbeat (version + inventory hashes) → command pickup → signed verify → result 204 → inventory submit → monitoring results → renew → self-update report",
         failures=[
             "Auth refused: revoked/unknown/expired bearer → 401 (covered); quarantined agent on monitoring results → 403 (SRV-14); quarantined self-update report → 403 (SRV-10, expected to fail)",
             "Payload bound exceeded: heartbeat lists/logged_in_user (SRV-15); monitoring batch >100 (SRV-14, AGT-14); capability list ≤16 (AGT-17)",
             "Stale/replayed: result exact retry 204 / conflict 409 (covered); reattach nonce replay (SRV-16); self-update report replay (SRV-11, expected to fail); concurrent results on PG (SRV-41)",
         ],
         go_only="Go httptest catches what Python fakes cannot: canonical inventory bytes (AGT-05/CTR-05), the command journal state machine across restart (covered in replay_test), rotation-nonce durability on crash (AGT-18), and client-side batching/retry policy (AGT-13..16).",
         rows=["SRV-10", "SRV-11", "SRV-14", "SRV-15", "SRV-16", "SRV-17", "SRV-41", "AGT-05", "CTR-05", "AGT-13", "AGT-14", "AGT-15", "AGT-17", "AGT-18", "X-02"]),
    dict(n=2, name="Dashboard BFF → server", parties="Next.js route.ts handlers (src/app/api/**) ↔ FastAPI operator API",
         transport="server-side fetch with Authorization: Bearer from the HTTP-only cookie, cache no-store",
         dependency="Injected fake API fns (route-core pattern) for behavior; shared contract fixtures (DSH-23) for shape, because a fake cannot drift with the server.",
         happy="cookie → getDashboardSession revalidates via /auth/me → role check → forward → *FromUnknown allowlist → browser",
         failures=[
             "Auth refused: revoked session reused → 401 before forwarding (DSH-02..05 expected to fail for cookie-only handlers; DSH-21 for the revalidator)",
             "Payload bound: script >56 KiB (DSH-25), chat oversize (DSH-01, currently not run)",
             "Stale/replayed: cross-origin replay of a mutation → 403 (covered for operators; DSH-08 expected to fail for schedules)",
         ],
         go_only="",
         rows=["DSH-01", "DSH-02", "DSH-03", "DSH-04", "DSH-05", "DSH-08", "DSH-10", "DSH-20", "DSH-21", "DSH-23"]),
    dict(n=3, name="Server → PostgreSQL", parties="app/core/audit.py, models, alembic ↔ PostgreSQL 16",
         transport="asyncpg via SQLAlchemy",
         dependency="Real Postgres only (CI `server` job TEST_POSTGRES_URL). SQLite serializes writers and ignores FOR UPDATE and advisory locks, so these tests cannot fail there.",
         happy="concurrent audit appends get contiguous seq (covered, PG-only)",
         failures=[
             "Auth/constraint refused: one operator approving twice concurrently → one decision row (SRV-40)",
             "Bound exceeded: migration 0013 preflight refuses duplicate site names (SRV-43)",
             "Stale/replayed: concurrent reattach / conflicting results serialize (SRV-41); nonce uniqueness absent from ORM schema (SRV-44, expected to fail); support-chat launch lock (SRV-42)",
         ],
         go_only="", rows=["SRV-40", "SRV-41", "SRV-42", "SRV-43", "SRV-44"]),
    dict(n=4, name="Server → S3 Object Lock / WORM", parties="app/core/anchor_publish.py S3Backend ↔ S3",
         transport="boto3 put_object with ObjectLockMode=COMPLIANCE",
         dependency="moto[s3] (already in CI). Real S3 would need credentials and costs; moto models Object Lock headers.",
         happy="scheduler creates anchor → publishes with lock → receipt verifies (covered)",
         failures=[
             "Auth refused: publication-status without auth → 401 (covered)",
             "Bound/misconfig: bucket without Object Lock (SRV-47, expected to fail)",
             "Stale/replayed: S3 ClientError then retry (SRV-45); republish after commit failure (SRV-46, expected to fail); lag alert (covered)",
         ], go_only="", rows=["SRV-45", "SRV-46", "SRV-47"]),
    dict(n=5, name="Server → email provider and webhook receivers", parties="email_notifications.py (Resend) / webhook_notifications.py ↔ external HTTPS",
         transport="HTTPS POST; webhooks signed HMAC-SHA256 over timestamp.payload",
         dependency="Fake Resend adapter and local receivers; real providers are out of scope for CI.",
         happy="alert transition → one delivery row per recipient → masked in API → signed webhook delivered (covered)",
         failures=[
             "Auth refused: forged/wrong-key/tampered webhook rejected by a verifier (SRV-48)",
             "Bound exceeded: hostile receiver header overflow (SRV-49)",
             "Stale/replayed: retry idempotency key (covered); retry timestamp freshness (SRV-50); delivery retry state refusals (SRV-22, SRV-23)",
         ], go_only="", rows=["SRV-20", "SRV-21", "SRV-22", "SRV-23", "SRV-48", "SRV-49", "SRV-50"]),
    dict(n=6, name="Server → MeshCentral admin API", parties="app/core/meshcentral*.py ↔ MeshCentral",
         transport="admin websocket; minted short-lived login URL returned once",
         dependency="Fake MeshCentral client (existing). A real MeshCentral container is a nightly candidate, not a PR check.",
         happy="mapping reconciled → launch mints once → URL returned once → close revokes (covered)",
         failures=[
             "Auth refused: readonly / no scope / untrusted agent (covered); unknown agent 404s (SRV-38)",
             "Fail closed: provider disabled or unavailable → 503 (covered)",
             "Stale: stale/conflict mapping refused (covered); minted URL never stored in plaintext anywhere (SRV-51)",
         ], go_only="", rows=["SRV-38", "SRV-51", "DSH-04"]),
    dict(n=7, name="Support chat (end-user ↔ technician)", parties="end-user → named pipe → agent → server ↔ BFF chat proxy (fragment token) ↔ technician BFF",
         transport="local named pipe (SYSTEM+INTERACTIVE ACL), agent bearer, browser fragment token, operator cookie",
         dependency="Server: real app + simulated agent (covered). BFF: injected fakes. End-to-end: X-05 harness with uvicorn.",
         happy="technician opens (support-chat-launch-v1) → launch rides heartbeat → agent launches window → end-user sends → technician reads",
         failures=[
             "Auth refused: agent credential cannot authorize chat and vice versa (covered); capability gate support-chat-launch-v1 (covered); technician handlers revalidate session (DSH-05, DSH-09)",
             "Bound exceeded: message bytes/count (covered server); BFF oversize body (DSH-01, never run)",
             "Stale/replayed: token after close refused (covered); fragment-not-query (DSH-01); launch lock race on PG (SRV-42)",
         ], go_only="", rows=["DSH-01", "DSH-05", "DSH-09", "DSH-27", "SRV-42", "X-05"]),
    dict(n=8, name="Approval / two-person authorization", parties="management.py dispatch, scheduler.py, shell_sessions.py, agent_updates.py rollout",
         transport="in-process gates over shared ApprovalPolicy",
         dependency="Real app on SQLite for logic; Postgres for the concurrency guarantee.",
         happy="request → two distinct approvals → exactly one dispatch (covered)",
         failures=[
             "Governed kind refused: dispatch (covered), scheduled task (covered), interactive shell for `powershell` (covered) / `shell` (SRV-13, expected to fail), self-update rollout (SRV-12, expected to fail)",
             "Bound exceeded: outstanding request cap 429 (SRV-28)",
             "Stale/replayed: mutated payload and double-spend (covered on SQLite); same race on PG (SRV-40)",
         ], go_only="", rows=["SRV-12", "SRV-13", "SRV-28", "SRV-40", "DSH-26"]),
    dict(n=9, name="Installer → service → first heartbeat (Windows CI)", parties="NodeLinkAgent.iss → Windows SCM service → server",
         transport="Inno Setup silent install, SCM, HTTPS",
         dependency="Extend the existing windows-lifecycle job; start uvicorn on SQLite locally in the job.",
         happy="install with /TOKEN → service running → enroll → first heartbeat (X-01)",
         failures=[
             "Auth refused: bad token → service stays running, no agent row, error logged without token (X-01 variant)",
             "Bound: token file vs /TOKEN precedence (INS-02, INS-03)",
             "Stale: upgrade in place preserves identity (INS-04); validate-upgrade refusals (AGT-19)",
         ], go_only="", rows=["X-01", "INS-01", "INS-02", "INS-03", "INS-04", "AGT-19"]),
    dict(n=10, name="Deployed smoke", parties="CI / operator → Render backend + Vercel dashboard",
         transport="HTTPS, read-only",
         dependency="production-smoke.mjs runs the built dashboard against an in-process mock API (no real data). deploy/soak/soak.py drives a running server with simulated Python agents (enroll, heartbeat, dispatch under admission control, outage/recovery, audit chain and anchor checks).",
         happy="X-04: run production-smoke in CI. X-03: post-deploy read-only probe of the real pair.",
         failures=[
             "Auth refused: anonymous mutation → 401 (in smoke; add to X-03)",
             "Bound: none safe against production; keep bounds in CI",
             "Stale: none against production data; soak covers outage/recovery off-production",
         ], go_only="", rows=["X-03", "X-04", "SRV-27"]),
]

RUNNER_CHANGES = [
    dict(name="Dashboard component and page tier",
         need="DSH-24..28: render .tsx with a DOM.",
         change="Keep `node --test`. Add a loader that strips JSX (`tsx` via `node --import tsx --test`) and `happy-dom` + `@testing-library/react` as devDependencies. One setup file registers the DOM globals. Stays a single runner; avoids Vitest/Jest. Strip-types cannot parse JSX or the @/ alias, so the loader is the minimum.",
         asks="package.json devDependencies + test script (ask first)"),
    dict(name="Dashboard test list drift",
         need="Every new dashboard test must be appended by hand; one file already orphaned.",
         change="Add a 6-line test (test/test-list.test.ts) that reads package.json and fails if any test/*.test.ts is missing from the script. Alternative: switch the script to `node --test test/` (Node 24 accepts a directory).",
         asks="package.json (ask first)"),
    dict(name="Postgres-only marker",
         need="SRV-40..43 and future PG rows each copy a skipif.",
         change="Add server/tests/conftest.py registering a `postgres` marker that auto-skips without TEST_POSTGRES_URL, plus a `pg_engine` fixture that creates a disposable schema per test. No CI change: the server job already sets the URL.",
         asks="none (test code only)"),
    dict(name="ORM ↔ migration index parity",
         need="SRV-44: create_all schemas miss alembic-only indexes.",
         change="Either declare ux_commands_agent_nonce on the model or add a test comparing Base.metadata indexes with an alembic-head schema on SQLite.",
         asks="none"),
    dict(name="Go httptest recorded fixtures",
         need="X-02: Go client tested against real server bytes.",
         change="Server test writes contracts/agent-api/*.json (request + response per endpoint); Go test reads them through a relative path like verify/vectors_test.go. Stdlib only.",
         asks="none"),
    dict(name="Windows-tagged parsers on Linux",
         need="AGT-01, AGT-06, AGT-07: pure parsers trapped in *_windows.go only run on windows-latest.",
         change="Move pure parsing into untagged files so `go test ./...` on ubuntu (which also runs gofmt/vet) covers them. Keep shell-out in the tagged file.",
         asks="none"),
    dict(name="WUA script harness",
         need="AGT-08: embedded PowerShell never executed.",
         change="agent/test/wua_scripts.ps1 following reboot_probe_script.ps1; add one `pwsh -File` step to the agent job.",
         asks="CI step (ask first)"),
    dict(name="JSON Schema validation",
         need="CTR-03: no test validates schemas as schemas.",
         change="Add `jsonschema` to the server test dependencies (CI pip line), Python side only; Go stays stdlib-only and keeps vector parity.",
         asks="CI pip line / requirements (ask first)"),
    dict(name="Installer test collection",
         need="INS-01: bare functions invisible to unittest discover.",
         change="Wrap test_support_shortcut_contract.py functions in a unittest.TestCase. No runner change.",
         asks="none"),
    dict(name="Windows lifecycle server",
         need="X-01, INS-02..04.",
         change="In windows-lifecycle: start uvicorn on SQLite in a background step, compile the installer with a CI-only server_url define, then poll for the first heartbeat. Also stops the current smoke from pointing a running service at production.",
         asks="ci.yml (ask first)"),
]
