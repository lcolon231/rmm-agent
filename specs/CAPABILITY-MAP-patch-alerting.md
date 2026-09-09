# Capability Map: Patch-State Alerting

Source request: alert when an endpoint needs a restart after an update, and
alert when an endpoint has not been updated in a significant amount of time.

## Modules

| Module id | Responsibility | Depends on |
|---|---|---|
| reboot-cause | Attribute an existing `reboot_pending` alert to the update(s) that caused it, so the alert says *why* a restart is needed | — (extends shipped `reboot_pending` check) |
| patch-age-windows | New server-evaluated `patch_age` check type: alert when the newest installed Windows Update is older than a configured threshold | — |

Build order: reboot-cause, patch-age-windows — no dependency between them, either
order, or in parallel.

**Descoped: `patch-age-packages`.** Package-manager/Linux staleness was
considered and cut on 2026-09-02; see "Why the package path is out of scope".

## Why these boundaries

`reboot_pending` already ships end to end — Go probe
(`agent/internal/monitoring/probe_windows.go:59`), policy schema
(`server/app/schemas/monitoring.py:159`), alert lifecycle
(`server/app/core/monitoring.py`), alerts page. Nothing new is needed to *fire*
a restart alert; the gap is that the alert carries no cause. That is a payload
and rendering change, independently testable, and it shares no code with the
patch-age work.

`patch_age` is a new check type. It is server-evaluated from stored inventory
(like `offline`, not like `cpu`) because the data — `WindowsUpdatesInventory.installed[].installed_on`
— is already on the server and needs no new agent probe.

## Why the package path is out of scope

Windows + Linux package coverage was requested, then cut. Two facts made it a
much larger piece of work than the Windows check:

1. `InstalledPackage` (`server/app/schemas/inventory.py:534`) has **no install
   timestamp** — only `package_id`, `name`, `version`, `source`. There is
   nothing to age. This needs a schema field (`installed_on`) plus agent work to
   populate it.
2. There is **no Linux package provider** in the agent. `agent/internal/packages/`
   is `packages_windows.go` (winget/chocolatey) and a `packages_other.go` stub,
   and `agent/supported-targets.txt` lists `linux/amd64` as **dev**, not a
   supported target.

Covering it means "add dpkg/rpm package discovery with install dates to a
platform we do not ship". That is a product decision about supported platforms,
not a detail of this feature, so it is not in this initiative.

## Forward compatibility

`patch-age-windows` still defines `patch_age` in terms of "newest install
evidence", not "newest Windows Update", and reports `unknown` — never `ok` — for
an endpoint with no `windows_updates` inventory. A second evidence source can
therefore be added later without a new check type, a policy migration, or a
change to already-stored revisions.
