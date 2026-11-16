# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state — a minimum agent
version for a new capability, a new known limitation, an operator action a
change creates.

A feature branch records its release-visible consequences here as it lands.
When a tag is cut, they are folded into that tag's manifest and the entry is
cleared, so this file lists only what no manifest carries yet.

## Carried

Nothing pending. Everything merged between v0.1.11 and v0.1.12 is stated in
[`v0.1.12.json`](v0.1.12.json): the public API v1 and `nlk_` tokens (#72),
emergency overrides (#65), the evidence vault (#81), tenant retention policies
(#88), the community repository (#74), support-chat retention (#237), relay
routing (#87, partial), the dashboard redesign, and the GUI-subsystem tray
(#322). Earlier facts are in the earlier manifests.

Note for whoever cuts the next tag: v0.1.12 adds migrations 0045 through 0051,
so its rollback to v0.1.11 restores a 0044 backup. That evidence was rehearsed
against a disposable database, as for v0.1.9 and v0.1.10. A tag that adds a
migration must again take and verify a fresh backup of the real database before
promoting. A tag that adds none rolls back to v0.1.12 at 0051, and no release
has yet produced 0051 recovery-point evidence, so that tag must take and verify
one rather than reuse v0.1.12's 0044 evidence.
