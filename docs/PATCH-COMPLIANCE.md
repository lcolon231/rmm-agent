# Patch compliance reporting

Issue #54 adds a read-only compliance view over data NodeLink already retains:
the endpoint's effective patch approval policy and its Windows Update inventory.
It adds no database table, migration, background job, or agent behavior.

## States and precedence

Each non-revoked endpoint is assigned exactly one state, in this order:

1. **`exempt`** — no effective patch policy applies. Patch approval is opt-in,
   so the endpoint has no compliance requirement.
2. **`unknown`** — no usable Windows Update scan exists, or the latest scan is
   untrusted. Absence is not treated as compliance.
3. **`stale`** — the latest usable scan is older than
   `patch_compliance_stale_after_hours` (24 hours by default).
4. **`non_compliant`** — at least one update that the current effective policy
   approves is still missing.
5. **`compliant`** — a fresh, usable scan has no approved update still missing.

Deferred and denied missing updates remain visible as counts, but they do not
make a fresh endpoint non-compliant. A stale row also retains its calculated
missing counts so an operator can see the last known posture without mistaking
it for current evidence.

## Computation

The report resolves the same most-specific effective policy used by the
installation gate (`agent` > `site` > `client` > `global`) and evaluates the
latest retained `windows_updates` snapshot with the same ordered
approve/deny/defer rules. The result is computed when read; it does not mutate
policy, inventory, endpoint, or command records.

The readonly API exposes:

- `GET /api/v1/patch-compliance/summary` for state counts and the total number
  of approved-but-missing updates;
- `GET /api/v1/patch-compliance` for a filterable, sortable, paginated endpoint
  register;
- `GET /api/v1/agents/{id}/patch-compliance` for one endpoint and its current
  per-update decisions; and
- `GET /api/v1/agents/{id}/patch-compliance/history` for retained history.

Summary, list, and export accept `client_id` and `site_id` scope filters. List
also accepts state, hostname search, sorting, direction, page, and page size.

## Historical semantics

History is derived from retained `windows_updates` snapshots and is explicitly
reported as `evaluated_against: current_policy`. It answers, "What would each
retained scan look like under today's effective policy?" It does not reconstruct
the policy that happened to exist when a scan was collected. Policy edits can
therefore change the historical series without changing any stored snapshot.

The number of points is bounded by `patch_compliance_history_limit` (50 by
default, with an API maximum of 200) and by ordinary inventory retention.

## Export

`GET /api/v1/patch-compliance/export?format=csv|json` downloads the same bounded
per-endpoint rows. CSV uses stable columns for client, site, endpoint, state,
policy, scan time, and missing-update counts. JSON adds `generated_at` and
`truncated` metadata. Both responses use `Cache-Control: no-store`; the
dashboard proxies downloads through the operator's server-managed session.

## Resource bounds

`patch_compliance_max_endpoints` caps the number of endpoints evaluated for one
request (5,000 by default). Summary, list, and JSON export surface a `truncated`
flag when the scope exceeds the cap; the dashboard displays that condition.
Pagination occurs after computed state and hostname filters, because compliance
state is derived rather than stored.

## Failure, compatibility, and recovery

Invalid state, format, sort, direction, page, or limit values are rejected with
`422`; an unknown endpoint detail/history target returns `404`. If the dashboard
cannot authenticate the session or validate the API response, it shows no
protected rows or invented counts. An unavailable or unsupported endpoint scan
is represented as `unknown`, not as compliant.

The operations are reads, so retries and idempotency keys are not applicable: a
technician can safely reload or re-export after an unavailable response. The
only side effect is the append-only read/export audit event. No new trust
boundary, dependency, protocol negotiation, or mixed-agent compatibility path
is introduced.

## Audit and authorization

All endpoints require the readonly role or higher. Summary and list reads emit
`patch_compliance.viewed`; downloads emit `patch_compliance.exported`. Audit
details contain only coded filters, scope IDs, format, and row counts — never
hostnames, update titles, or other free-form endpoint data. See
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Verification

- `server/tests/test_patch_compliance.py` covers all five states, rollups,
  pagination/filtering, endpoint decisions, current-policy history, CSV/JSON,
  readonly access, and audit persistence.
- `server/tests/test_redaction.py` verifies the exact audit-detail contracts.
- `dashboard/test/patch-compliance-core.test.ts` verifies allowlisted parsing,
  fail-closed malformed responses, and state labels.

Rollout is server then dashboard. There is no schema or agent compatibility
step, and rollback removes only the reporting surface.
