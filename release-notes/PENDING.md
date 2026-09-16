# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state — a minimum agent
version for a new capability, a new known limitation, an operator action a
change creates.

A feature branch records its release-visible consequences here as it lands.
When a tag is cut, they are folded into that tag's manifest and the entry is
cleared, so this file lists only what no manifest carries yet.

## Carried

Nothing pending. The v0.1.9 facts — endpoint support chat from #234 (agent
0.1.9 required, Windows-only, operator dashboard deferred to #235, migration
0044), per-update `reboot_required` from #256 (agent 0.1.9 required), and the
#248 global-script-grant repair (migration 0043) — are stated in
[`v0.1.9.json`](v0.1.9.json) and need no further carry-forward.

Note for whoever cuts the next tag: v0.1.9's rollback and evidence records were
rehearsed against a disposable database. The pre-migration 0042 backup it names
is the rehearsal's, not the live deployment's, so take and verify a fresh
backup of the real database before promoting and repoint
`rollback.target.database.backup_manifest` at it.
