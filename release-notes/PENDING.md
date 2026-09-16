# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state — a minimum agent
version for a new capability, a new known limitation, an operator action a
change creates.

A feature branch records its release-visible consequences here as it lands.
When a tag is cut, they are folded into that tag's manifest and the entry is
cleared, so this file lists only what no manifest carries yet.

## Carried

Nothing pending. The support-chat tray launcher
(`specs/SPEC-support-chat-tray.md`) — agent 0.1.10 required, Windows-only
(`rmm-agent tray`), the all-users Startup shortcut, no migration, no server
change, no `agent/go.mod` dependency, and the more-visible `#24` unsigned-artifact
limitation from a persistent user-session process — is stated in
[`v0.1.10.json`](v0.1.10.json) and needs no further carry-forward. The v0.1.9
facts are stated in [`v0.1.9.json`](v0.1.9.json).

Note for whoever cuts the next tag: v0.1.10's rollback and evidence records were
rehearsed against a disposable database. Because v0.1.10 adds no migration its
rollback is restore-free; a tag that does add a migration must again take and
verify a fresh backup of the real database before promoting and repoint
`rollback.target.database.backup_manifest` at it.
