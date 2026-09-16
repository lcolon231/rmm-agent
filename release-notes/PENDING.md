# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state — a minimum agent
version for a new capability, a new known limitation, an operator action a
change creates.

A feature branch records its release-visible consequences here as it lands.
When a tag is cut, they are folded into that tag's manifest and the entry is
cleared, so this file lists only what no manifest carries yet.

## Carried

**Support-chat tray (next tag must state):** a system-tray launcher for support
chat landed after v0.1.9 (`specs/SPEC-support-chat-tray.md`). The next manifest
must state: it requires the agent version that first ships it; it is Windows-only
(`rmm-agent tray`, no-op elsewhere); the installer now creates an all-users
Startup shortcut "NodeLink Support" that launches the tray at logon as a
non-elevated process, removed on uninstall; it adds no server change, no
migration, and no `agent/go.mod` dependency (native `Shell_NotifyIcon`); and it
makes the existing `#24` unsigned-artifact limitation more visible because the
tray is a persistent user-session process rather than a transient CLI. No new
credential or network surface — it is only a launcher for the shipped
`chatpipe.Request` flow.

The v0.1.9 facts — endpoint support chat from #234 (agent 0.1.9 required,
Windows-only, operator dashboard deferred to #235, migration 0044), per-update
`reboot_required` from #256 (agent 0.1.9 required), and the #248
global-script-grant repair (migration 0043) — are stated in
[`v0.1.9.json`](v0.1.9.json) and need no further carry-forward.

Note for whoever cuts the next tag: v0.1.9's rollback and evidence records were
rehearsed against a disposable database. The pre-migration 0042 backup it names
is the rehearsal's, not the live deployment's, so take and verify a fresh
backup of the real database before promoting and repoint
`rollback.target.database.backup_manifest` at it.
