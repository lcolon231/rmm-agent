# Local end-to-end verification

How to run the server and dashboard against a seeded throwaway database, for a PR's "end-to-end or manual verification".

## 1. Read the contract first

Read the API table of the feature doc in full (for example `docs/RETENTION.md`, "Tenant-specific retention"). It lists the rules a hand-written request trips over: full-replacement writes, version floors, exact audit action names.

## 2. Environment

The seed and the server must share one environment. From `server/`, with the venv from `server/README.md`:

```bash
export ENVIRONMENT=development DEBUG=true
export DATABASE_URL="sqlite+aiosqlite:///<scratch dir>/e2e.db"   # absolute path, outside the repo
export SECRET_KEY=local-e2e-only
export COMMAND_SIGNING_KEY_PATH="<main checkout>/server/command_signing_key.pem"
```

- Set `SQL_ECHO=true` only to debug queries. It logs every statement and buries tracebacks.
- Add any feature bounds the test needs as env overrides (for example `RETENTION_MAX_ALERT_DAYS=0` to allow "keep forever" on alerts).

In a git worktree, these files are absent because they are gitignored:

- `server/.env`: the exports above replace it.
- `command_signing_key.pem`: point at the main checkout's key, or run `python scripts/gen_command_keys.py`.
- `dashboard/node_modules`: run `npm ci`.

## 3. Seed and start

```bash
python scripts/dev_seed.py --reset [--scenario retention]    # prints client IDs as JSON
python -m uvicorn app.main:app --host 127.0.0.1 --port 8011
```

In `dashboard/`:

```bash
NODELINK_API_BASE_URL=http://127.0.0.1:8011 npx next dev -p 3011
```

Use ports other than 8000 and 3000, so the run cannot collide with a dev server you already have open.

The seed creates two clients, `alpha` and `bravo`. Every persona except `platform` is a member of both. Each signs in as `<persona>@dev.test` with the `password` the seed prints. It is random per run unless `NODELINK_DEV_SEED_PASSWORD` is set.

| Persona | Global role | Client role |
|---|---|---|
| `admin`, `admin2` | admin | client_admin |
| `reader` | readonly | client_readonly |
| `operator` | admin | client_operator |
| `platform` | admin, platform admin | none |

Two admins exist so you can test optimistic-concurrency conflicts. For rows a feature needs beyond this cast, add a function to `SCENARIOS` in `server/scripts/dev_seed.py`.

## 4. Drive the dashboard

When a browser is available, sign in at `http://127.0.0.1:3011` and use the feature.

Without one, drive the same path the browser uses:

```bash
D=http://127.0.0.1:3011
PW=<password from the seed output>
curl -s -c admin.jar -X POST $D/api/auth/login -H "origin: $D" -H "content-type: application/json" \
  -d "{\"email\":\"admin@dev.test\",\"password\":\"$PW\"}"
curl -s -b admin.jar "$D/clients/<alpha id>"                      # server-rendered page
curl -s -b admin.jar -X PUT "$D/api/clients/<alpha id>/<route>" \
  -H "origin: $D" -H "content-type: application/json" -d '{...}'  # BFF write
```

BFF writes need a same-origin `Origin` header.

## 5. Record the result

Put the result in the PR, including what you could not exercise. Step-up is the usual gap: `require_step_up` passes automatically for an operator with no MFA credential, so the WebAuthn path needs a real or virtual security key.
