# Prompt: design the complete unit + integration test matrix for NodeLink

Paste everything below the line into a Claude Code session opened at the repo
root. It is self-contained: the agent re-derives every fact it needs from the
checkout rather than trusting this file.

---

You are designing (not writing, not running) the complete unit and integration
test matrix for the NodeLink RMM monorepo you are checked out in. The output is
an HTML report at `tasks/test-design-plan.html` plus a machine-readable
`tasks/test-design-plan.json`. Do not add, edit, or run tests unless the user
asks; your job is the design.

## 1. Ground truth you must verify before designing

Three runtimes, three test runners, one CI workflow (`.github/workflows/ci.yml`):

| Layer | Stack | Runner | Where tests live |
|---|---|---|---|
| `server/` | FastAPI, Pydantic 2, async SQLAlchemy, Alembic | `pytest -q` (asyncio_mode=auto), SQLite in-process via `httpx.ASGITransport`; CI also runs Postgres 16 | `server/tests/test_*.py` |
| `dashboard/` | Next.js 16, React 19, TS | Node's built-in `node --test` with `--experimental-strip-types`; **the file list is hand-maintained in `package.json` `"test"`** | `dashboard/test/*.test.ts` |
| `agent/` | Go 1.22, stdlib-only | `go test ./...` on ubuntu + windows; Windows-only behavior is covered by `agent/test/*.ps1` driven from CI | `agent/internal/**/_test.go` |
| `installer/` | Inno Setup + Python contract tests | `python -m unittest discover -s installer/test` (Windows CI only) | `installer/test/test_*.py` |
| `contracts/` | JSON schemas + canonical signature vectors | consumed by both Python and Go suites | `contracts/test-vectors/*.json` |

Re-run the survey yourself; do not copy numbers from this prompt:

```bash
# server: modules with no same-named test, then confirm via import graph
cd server && for f in app/api/*.py app/core/*.py; do n=$(basename "$f" .py); [ "$n" = __init__ ] && continue; [ -f "tests/test_$n.py" ] || echo "$n"; done
grep -rl "app\.core\.<module>\b" tests/   # 0 hits = truly untested by module

# dashboard: lib modules with no test, and test files orphaned from npm test
cd dashboard && for f in src/lib/*.ts; do n=$(basename "$f" .ts); ls test/ | grep -q "^$n" || echo "$n"; done
for t in test/*.test.ts; do grep -q "$(basename $t)" package.json || echo "ORPHAN $t"; done

# agent: source/test file ratio per package
cd agent && for d in $(find internal cmd -type d); do s=$(ls "$d"/*.go 2>/dev/null | grep -v _test.go | wc -l); t=$(ls "$d"/*_test.go 2>/dev/null | wc -l); [ "$s" -gt 0 ] && printf "%-32s src=%-3s test=%s\n" "$d" "$s" "$t"; done
```

Honesty rules for the survey:

- A missing `test_<name>.py` is **not** evidence of a gap. `app/core/mfa.py` is
  covered by `test_mfa_webauthn.py` and `test_mfa_email_code.py`. Classify a
  module as a gap only when the import-graph grep returns zero and no HTTP-level
  test exercises its router. Say which of the two you checked.
- `server/app/api/*` routers are tested almost entirely through HTTP. That is
  fine for behavior; it is a gap for error-branch coverage (every `raise
  HTTPException` in a router that no test triggers).
- `dashboard/src/components/*.tsx` (39 files) and `src/app/**/page.tsx` have
  **zero** tests today. There is no Playwright/Cypress; the only UI check is a
  `curl /login | grep "Sign in"` smoke in CI. Treat component and page tests as
  a new tier, not a gap in an existing one.
- `dashboard/test/support-chat-core.test.ts` exists but is absent from the
  `npm test` list, so CI has never run it. Flag every orphan you find the same
  way, and make "append to package.json test list" an explicit step of every
  new dashboard test you design.
- `agent/internal/telemetry` has 4 source files and 0 tests. Low-ratio
  packages (`inventory` 11:5, `patching` 8:4, `monitoring` 7:3, `selfupdate`
  5:2, `power`/`deploy`/`svcproc`/`chatlaunch` 3:1) need a per-file look, not a
  ratio verdict: a 3:1 package may be one big file plus two tiny ones.
- Read `docs/ARCHITECTURE.md` §12 "Change discipline" and the per-feature docs
  it links. Security-sensitive behavior requires tests at *every* affected
  boundary; your matrix must show each boundary row for each such feature.

## 2. Unit test design (per layer)

For every module/package/component you classify as a gap or as thin, produce
one row per proposed test with these fields:

`id`, `layer`, `tier` (unit | integration | contract | e2e), `target` (file or
symbol), `behavior` (one sentence in the form "<when> → <then>"),
`boundary` (which trust/operations/product-plane boundary it guards, from
ARCHITECTURE.md §3), `fixture_strategy`, `existing_pattern_to_copy` (a real
test file in this repo whose shape to reuse), `priority`, `rationale`.

Layer-specific requirements:

**server/**
- Follow the shape of `tests/test_e2e.py`: env vars set before `app.main`
  import, `engine.begin()` drop/create, seeded `Operator`, `ASGITransport`.
  Tenant-scoped routes need `tests/_tenancy.grant_all_memberships` (issue #66).
- For each `app/core/*` module with zero import-graph hits, design pure-function
  unit tests first (no DB), then one HTTP test proving the router uses it.
- For each router, enumerate its `HTTPException` branches and map each to a
  test; the ones no existing test triggers are your rows.
- Redaction (`core/redaction.py`, `tests/test_redaction.py` PRODUCER_DETAILS) is
  a registry: any new audit action needs a row there or the suite fails. Say so
  on every test that emits a new audit event.
- Migrations: `test_migrations.py` runs against Postgres in CI. Any test that
  depends on a column added after revision 0036 must say which revision.

**dashboard/**
- Three tiers exist or should: (a) `*-core.ts` pure logic → `node --test`
  (exists); (b) `*-route-core.ts` BFF handlers with injected deps
  (`getSession`, API fns) → `node --test` with fakes (partially exists; see
  `src/app/api/operators/route.ts` for the injection shape); (c) components
  and pages → **does not exist**. For (c), recommend one runner (React Testing
  Library under `node --test` with a DOM shim, or Vitest+jsdom) and justify it
  against the repo's "stdlib-first, no Jest" convention; do not pick Playwright
  for unit work.
- Every `src/app/api/**/route.ts` (83 handlers) must appear in the matrix with
  either "covered by `<route-core test>`" or a proposed row. Session
  revalidation, role gating, and response-field allowlisting are the three
  behaviors each handler row must name.
- Read `dashboard/AGENTS.md` first: this Next.js differs from your training
  data. Check `node_modules/next/dist/docs/` before proposing anything that
  touches route handler signatures or `proxy.ts`.

**agent/**
- Table-driven, stdlib `testing`, no testify. Windows-only paths (DPAPI, SCM,
  Job Objects, registry) are behind `//go:build windows`; design those tests to
  run on the `windows-latest` job and say so. Anything that needs a real
  registry or service goes into `agent/test/*.ps1` instead, like
  `reboot_probe_script.ps1`.
- `internal/telemetry`: design from zero. The collector shells out to
  PowerShell/CIM; the seam to test is the parser, with captured fixture output,
  not the shell-out.
- Canonicalization parity: any test touching inventory hashing or the
  command envelope must assert a pinned vector from `contracts/test-vectors/`
  in **both** Go and Python, since drift there makes every section look
  permanently changed (ARCHITECTURE.md §6.1).
- gofmt gotcha: CI fails on unformatted files and the Windows checkout is
  CRLF; note that any proposed test file must be LF and gofmt-clean.

**installer/ and contracts/**
- Installer contract tests are token-only (`/TOKEN=`, `server_url` pinned to
  the production host). Any new `/FLAG` needs a row.
- Every schema in `contracts/*.schema.json` must have positive and negative
  vectors consumed by both runtimes. List any schema whose vectors are consumed
  by only one side.

## 3. Integration seam matrix

Design one block per seam. Each block names: the two parties, the transport,
the fake or real dependency used in tests (and why), the happy path, and at
least three failure-mode tests (auth refused, payload bound exceeded, stale
or replayed state). Seams that must appear:

1. Agent → server: enroll, heartbeat (version report + inventory hashes +
   command pickup), `POST /agents/me/inventory`, `POST /agents/me/monitoring/results`,
   `POST /commands/{id}/result` idempotency (204 exact retry, 409 conflict),
   credential renew/reattach, self-update outcome report. Today this is tested
   with Python fakes of the agent; say where a Go `httptest` client against a
   recorded server fixture would catch what the Python side cannot
   (canonicalization, nonce persistence, journal state machine).
2. Dashboard BFF → server: every `route.ts` forwards a bearer server-side.
   Design contract tests that pin the request the BFF sends and the response
   fields it allowlists, so a server schema change fails in the dashboard
   suite rather than in production.
3. Server → PostgreSQL: advisory-lock audit `seq` serialization, unique
   constraints that make "two distinct approvers" true under concurrency,
   migration preflight refusals (rev 0013 duplicate names). SQLite cannot test
   these; mark them Postgres-only and tie them to the CI `TEST_POSTGRES_URL` job.
4. Server → S3 Object Lock / WORM (anchor publishing): `moto[s3]` is already a
   CI dependency; design idempotent-publish and lag-alert tests.
5. Server → email provider and → webhook endpoints: delivery rows, masked
   recipients, retry idempotency, HMAC rotation/validation.
6. Server → MeshCentral admin API: fail-closed 503, stale mapping, minted URL
   never persisted or audited.
7. Support chat: end-user (agent-launched window, fragment token) ↔ technician,
   including the `support-chat-launch-v1` capability gate.
8. Approval / two-person authorization across dispatch, scheduled tasks, and
   shell sessions (all three must refuse a governed kind).
9. Installer → service → first heartbeat on Windows CI (extend the existing
   `windows-lifecycle` job rather than inventing a new one).
10. Deployed smoke: `dashboard/scripts/production-smoke.mjs` and `deploy/soak/`
    exist; say what they cover and what a post-deploy check should add
    without touching production data.

## 4. Prioritization rubric

TODO(human): define the scoring rule that orders every row in the matrix.
Write it as 2–10 lines a reviewer can apply mechanically to a single row
(for example: a weighted sum, a decision tree, or a tiered gate). It must
produce a total order for the ~80 rows this matrix will contain and must say
how a tie is broken. Consider at least: whether the row guards a trust-plane
boundary (ARCHITECTURE.md §3.1), whether the behavior has zero coverage
today versus thin coverage, whether a regression would be visible to an
operator or silent, and the cost of the fixture the test needs.

## 5. Output

`tasks/test-design-plan.html`, self-contained (inline CSS/JS, no CDN), light
and dark theme via `prefers-color-scheme` tokens, readable at 400px, with:

1. A summary strip: rows proposed per layer, per tier, per priority.
2. The survey evidence (the exact commands run and their output), so a reader
   can re-verify every "gap" claim.
3. One table per layer, sortable by priority, each row carrying every field
   from §2.
4. One block per seam from §3.
5. A "runner changes" section: anything the matrix needs that the runners
   cannot do today (dashboard component tier, Postgres-only markers, Go
   httptest fixtures), each with the smallest change that unblocks it.
6. The rubric from §4, verbatim, and a worked example applying it to one row.

`tasks/test-design-plan.json`: the same rows as an array, so a later session
can turn rows into issues or tests without re-reading the HTML.

## 6. Constraints

- Design only. If you believe a test would fail today, say "expected to fail:
  <why>" in `rationale`; do not run it to find out unless asked.
- Never mark something covered because a file with a similar name exists.
- Never propose Jest, testify, or a second test runner for a layer that has
  one, without a stated reason the existing runner cannot do the job.
- If you commit anything, use plain commit messages with no AI attribution
  lines.
- Stop and ask before any step that would modify `package.json`, `go.mod`,
  `requirements.txt`, or CI.

Done means: both output files exist, every §3 seam has a block, every
`route.ts` and every zero-test module/package appears in a table, and the
summary strip's numbers match the JSON row count.
