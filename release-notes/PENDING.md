# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state — a minimum agent
version for a new capability, a new known limitation, an operator action a
change creates.

A feature branch records its release-visible consequences here as it lands.
When a tag is cut, they are folded into that tag's manifest and the entry is
cleared, so this file lists only what no manifest carries yet.

## Carried

Nothing pending. The restart-cause work from #231 — agent 0.1.8 required for
categorical cause reporting, the unknown verdict for older agents, and the
best-effort file-rename count whose paths are deliberately never collected —
is stated in [`v0.1.8.json`](v0.1.8.json) and needs no further carry-forward.

Note for whoever cuts v0.1.8: that manifest is written and passes preflight,
but its rollback and evidence records were rehearsed against a disposable
database. The pre-migration 0035 backup it names is the rehearsal's, not the
live deployment's, so take and verify a fresh backup of the real database
before promoting and repoint `rollback.target.database.backup_manifest` at it.
