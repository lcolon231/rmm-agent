# MeshCentral remote desktop integration (issue #62)

NodeLink integrates an external **MeshCentral** deployment to provide remote
desktop without inventing a proprietary protocol. MeshCentral is a **separate
security and operational boundary** with its own agent, permissions, updates,
sessions, and logs. NodeLink's responsibility is narrow and fail-closed:

1. **Identity map** a NodeLink agent to a MeshCentral node (manual, admin-owned).
2. **Authorize** a session launch at the NodeLink API boundary.
3. **Audit** the launch decision in NodeLink's tamper-evident chain.
4. **Mint** a short-lived, single-device, desktop-scoped access URL through
   MeshCentral's own admin API and return it once to the operator.

NodeLink never proxies the desktop stream, never persists the minted login
material or the MeshCentral admin credential, and never claims MeshCentral's
in-session activity under its command signature or audit guarantees.

## Contract

### Launch

`POST /api/v1/agents/{agent_id}/remote-desktop/launches`

Requires operator role **and** the explicit arbitrary-script scope used for
interactive shell (`authorize_command`, admin is not a bypass). Ordered,
fail-closed gates, each producing an audit event:

| Order | Condition | Response | Audit |
| --- | --- | --- | --- |
| 1 | provider disabled | `409 remote_desktop_disabled` | `meshcentral.launch_denied` (`provider_disabled`) |
| 2 | agent not found | `404` | — |
| 3 | not authorized (role/scope) | `403 remote_desktop_not_authorized` | `meshcentral.launch_denied` (`not_authorized`) |
| 4 | agent not trusted | `409 agent_not_trusted` | `meshcentral.launch_denied` (`agent_not_trusted`) |
| 5 | no mapping / unmapped | `409 remote_desktop_unmapped` | `meshcentral.launch_denied` |
| 5 | stale mapping | `409 remote_desktop_mapping_stale` | `meshcentral.launch_denied` |
| 5 | conflicting mapping | `409 remote_desktop_mapping_conflict` | `meshcentral.launch_denied` |
| 6 | per-operator rate limit | `429 remote_desktop_rate_limited` (`Retry-After`) | `meshcentral.launch_denied` (`rate_limited`) |
| 7a | MeshCentral unavailable | `503 remote_desktop_unavailable` | `meshcentral.launch_requested` then `meshcentral.launch_failed` |
| 7b | success | `201` with `login_url` (once) | `meshcentral.launch_requested` then `meshcentral.session_launched` |

States: **valid** = `201` with `login_url`; **invalid** = `4xx` code above;
**unavailable** = `503 remote_desktop_unavailable`; **unsupported** =
`409 remote_desktop_disabled`/`remote_desktop_unmapped`.

`login_url` and `login_expires_at` are returned **only** on the `201` create
response. They are never stored and never returned by any GET.

### Other endpoints

- `GET /agents/{agent_id}/remote-desktop/availability` → `{available, reason,
  provider_enabled}` so the dashboard renders fail-closed without a launch.
- `GET /agents/{agent_id}/remote-desktop/launches/{id}` → launch record without
  `login_url`; a non-owner receives `404` (launch-ID oracle protection).
- `POST /agents/{agent_id}/remote-desktop/launches/{id}/close` → marks the
  NodeLink record `closed` and issues a **best-effort** MeshCentral revoke.
  NodeLink cannot force-terminate a live MeshCentral session; MeshCentral
  remains authoritative for its own session lifetime.

### Admin (mapping + provider), admin-only

- `GET /remote-desktop/provider` — non-secret provider + mapping-count summary.
- `GET|POST|DELETE /remote-desktop/mappings` — manual mapping CRUD
  (`meshcentral.mapping_created` / `mapping_deleted`).
- `POST /remote-desktop/mappings/sync` — reconciliation
  (`meshcentral.mapping_synced`, plus `mapping_stale` per transition).

## Identity mapping and reconciliation

v1 mappings are **manual and admin-owned** (`origin = manual`). An administrator
maps an agent to a MeshCentral node id. Reconciliation (`meshcentral_mapping.py`)
is read-only with respect to admission: it refreshes freshness and ages a mapping
to `stale` (not confirmed within `MESHCENTRAL_MAPPING_STALE_AFTER_SECONDS`),
`unmapped` (node absent from MeshCentral), or `conflict` (two agents claim one
node). It never creates a mapping and never promotes one to `active`; when
MeshCentral is unavailable it leaves every mapping untouched and lets staleness
age it out. A launch always re-derives availability, so a stale/conflict/unmapped
mapping fails closed.

**Permission sync.** NodeLink never pushes its roles into MeshCentral's
permission model, so there is no standing permission to drift. Each launch
re-derives NodeLink authorization at mint time and requests only a single-device,
TTL-bounded grant. Revoking an operator's scope after a mapping exists fails the
next launch closed.

## Configuration

All secrets are environment-only and never persisted or returned.

| Env var | Meaning |
| --- | --- |
| `MESHCENTRAL_PROVIDER` | `disabled` (default) or `enabled` |
| `MESHCENTRAL_BASE_URL` | `https://` MeshCentral server |
| `MESHCENTRAL_ADMIN_TOKEN` | admin login token (env-only) |
| `MESHCENTRAL_ADMIN_USERNAME` | admin username, if token auth is unavailable |
| `MESHCENTRAL_LOGIN_COOKIE_ENCRYPTION_KEY` | base64url 32-byte AES-GCM key |
| `MESHCENTRAL_TLS_PIN_SHA256` | optional server cert SHA-256 pin |
| `MESHCENTRAL_LOGIN_TTL_SECONDS` | minted grant lifetime (default 120) |
| `MESHCENTRAL_MAPPING_SYNC_INTERVAL_SECONDS` | reconciliation cadence |
| `MESHCENTRAL_MAPPING_STALE_AFTER_SECONDS` | staleness window (default 86400) |
| `MESHCENTRAL_MAX_LAUNCHES_PER_OPERATOR_PER_MINUTE` | launch rate limit |

## Secret rotation

`MESHCENTRAL_ADMIN_TOKEN` and `MESHCENTRAL_LOGIN_COOKIE_ENCRYPTION_KEY` are
deploy-managed (like `WEBHOOK_SECRET_ENCRYPTION_KEY`), not API-mutable. To rotate
the admin token, generate a new MeshCentral login token, update the env var, and
restart. To rotate the encryption key, run a **two-key overlap** window: any
material encrypted under the old key must be consumed or expired before the old
key is removed (the default flow mints synchronously and does not persist login
material, so the key normally has nothing to migrate). Rotating without overlap
fails closed — old ciphertext will not decrypt under the new key.

## Compatibility, rollout, rollback

- Additive schema (Alembic `0036`, forward-only). No NodeLink **agent** change;
  MeshCentral runs its own agent. Mixed versions degrade to "remote desktop
  unavailable."
- **Rollout:** provider defaults to `disabled`. Enable per deployment after the
  manual E2E below passes.
- **Rollback:** set `MESHCENTRAL_PROVIDER=disabled` (immediate, fail-closed).
  Schema rollback follows the forward-only policy in `docs/ROLLBACK.md`.

## Manual end-to-end verification (live MeshCentral)

There is no live MeshCentral in CI, so automated tests run against a
`FakeMeshCentralClient`. Before flipping README status to implemented, run this
against a real MeshCentral (verified with **v1.2.5**):

1. Start MeshCentral and create a **"Manage using a software agent"** device
   group; install the MeshCentral agent on a test Windows endpoint so a real
   node exists.
2. Generate an admin **login token** (My Account → Account Security → login
   tokens) and, for a self-signed/LAN deployment, capture the server certificate
   SHA-256 for `MESHCENTRAL_TLS_PIN_SHA256`.
3. Set `MESHCENTRAL_PROVIDER=enabled`, `MESHCENTRAL_BASE_URL`,
   `MESHCENTRAL_ADMIN_TOKEN`, and `MESHCENTRAL_LOGIN_COOKIE_ENCRYPTION_KEY`.
4. As an admin, `POST /remote-desktop/mappings` mapping a NodeLink agent to the
   MeshCentral node id; confirm `GET /remote-desktop/provider` reports it.
5. As an authorized operator, `POST .../remote-desktop/launches`; confirm a real
   short-lived single-device `login_url` opens the endpoint desktop in
   MeshCentral, and that it expires at `login_expires_at`.
6. Verify the audit chain (`scripts/verify_chain.py` or the audit UI) records
   `meshcentral.launch_requested` → `meshcentral.session_launched` with **no**
   login URL or credential in any detail.
7. Confirm the fail-closed states: disabled provider (`409`), unmapped/stale
   mapping (`409`), and MeshCentral stopped (`503`).

Capture the responses and audit entries as verification evidence.
