# Package management (Winget + optional Chocolatey)

Issue #55 adds a package-provider interface with two typed commands on the
existing signed `command-v3` transport: `scan_packages` (read-only discovery) and
`install_packages` (install/upgrade). **Winget** is the always-available default;
**Chocolatey** is an opt-in provider, enabled per endpoint and additionally
carrying signed source trust evidence. Neither command accepts a script or falls
back to shell execution.

## Providers

- **Winget** — the default. Needs no configuration; every agent that advertises
  `package-management-v1` can run winget discovery and install/upgrade.
- **Chocolatey** — opt-in. The agent advertises `chocolatey-provider-v1` **only**
  when the operator sets `packages.chocolatey_enabled` in the agent config. A
  Chocolatey `install_packages` must also carry `source`, `source_digest`
  (SHA-256), and `signer`, which the server records and the agent re-validates at
  the endpoint before invoking `choco.exe`. An optional
  `packages.chocolatey_sources` allowlist further constrains which source feeds
  may be used.

Agent config (`config.json`):

```json
{
  "packages": {
    "chocolatey_enabled": true,
    "chocolatey_sources": ["https://community.chocolatey.org/api/v2/"]
  }
}
```

## Contract

### `scan_packages`

```json
{ "provider": "winget" }
```

- `provider` is optional; omitted means winget. `chocolatey` is accepted only
  when the endpoint opted in.
- Read-only. The normalized result — installed packages and available upgrades —
  is submitted through the ordinary inventory pipeline as the
  `installed_packages` section (so it inherits section history/diff). The command
  output is a small summary (`status`, `provider`, `installed_count`,
  `upgradable_count`, and any `error_code`).

### `install_packages`

```json
{
  "provider": "chocolatey",
  "operation": "install",
  "package_ids": ["googlechrome"],
  "source": "https://community.chocolatey.org/api/v2/",
  "source_digest": "<sha256 hex>",
  "signer": "NodeLink Ops"
}
```

- `provider` is `winget` or `chocolatey`; `operation` is `install` or `upgrade`.
- `package_ids` is a bounded (1–100), de-duplicated list matching
  `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`.
- **Winget** must not include `source`, `source_digest`, or `signer`.
- **Chocolatey** requires all three: `source` (1–512 printable bytes),
  `source_digest` (lowercase SHA-256 hex), and `signer` (1–255 printable bytes).
- The result carries per-package outcomes (`result_code` 0 = success), the
  classified `status` (`success`/`partial`/`failed`), and installed/failed lists.

## States and failure behavior

| State | Meaning |
| --- | --- |
| valid | Payload accepted, provider invoked, per-package outcomes returned. |
| invalid | Payload malformed, unknown provider/operation, bad ids, or unknown fields — rejected `422` at the API and re-rejected on the agent. |
| unavailable | Discovery ran but the provider CLI failed; section status `unavailable` with an `error_code`. |
| refused | Chocolatey requested without endpoint opt-in or without valid source/digest/signer — fails closed. |
| unsupported | Command dispatched to an agent that has not advertised the required capability — `409 agent_capability_unsupported`. |

Failures are fail-closed: a disabled or unproven Chocolatey path is refused
before any provider is invoked, and a requested package with no reported outcome
is counted as a failure rather than a silent success.

## Authorization

- `scan_packages` — operator role (read-only, like `scan_updates`). Its command
  detail is viewable at operator/readonly level; the useful data lands in the
  inventory section under normal RBAC.
- `install_packages` — **administrator-only**. Installing arbitrary software is a
  broad trust boundary, and Chocolatey pulls third-party sources.

Both require the `package-management-v1` capability; Chocolatey installs also
require `chocolatey-provider-v1`. Missing capabilities fail closed with
`409 agent_capability_unsupported` and an audited `command.authorization_denied`.

## Audit and evidence

- `package_scan.dispatched` — `provider`.
- `package_install.gated` — `provider`, `operation`, `requested` (count),
  `source_present`, `source_digest`, `signer_present`.

Package ids and source URLs are **never** stored as prose. Only counts and the
accountable SHA-256 source digest ride the audit trail. See
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Compatibility, migration, and rollback

- **No schema change.** Package commands ride the existing signed `Command`
  model, and discovery uses the per-section inventory JSON framework
  (`installed_packages` section + `SECTION_MODELS`), so there is **no Alembic
  revision**.
- **Mixed-version fleets are safe.** The new kinds are gated by
  `package-management-v1`; an agent that predates them never advertises the
  capability, so the server refuses dispatch (`409`) rather than sending a
  command the agent cannot verify. An older agent also rejects the kind at
  signature/kind validation.
- **Rollback** is removing the capability advertisement (downgrade the agent) or
  disabling `packages.chocolatey_enabled`; no data migration is involved.

## Platform support

Winget requires Windows 10 21H2+/Windows 11 with App Installer present.
Chocolatey requires an operator-managed `choco.exe`. On non-Windows builds both
providers report `unsupported`. Only the Windows x64 agent is a supported target.

## Deferred

- Dashboard UI for package dispatch and results (backend + agent only in this
  change).
- Package approval policies (scoped allow/deny like patch approval).
- MSStore-specific licensing flows and package pinning.
