# Pending release-note facts

Facts that landed on `main` after the last tag and that the **next** tag's
source manifest (`release-notes/<tag>.json`) must state. A tagged manifest is
written at release time against real artifacts and evidence, so a feature branch
records its release-visible consequences here instead of drafting one early.

Clear an entry once the tag whose manifest carries it is created.

## Next tag: v0.1.8

### Agent version required for categorical restart-cause reporting (#231)

The `reboot_pending` check now reports **which** Windows reboot-required
registry source is set instead of whether any is, and the server turns that into
a categorical `verdict` on the alert detail (`update_caused`,
`not_update_caused`, `unknown`). Reading the endpoint's own registry needs an
agent release; there is no server-side substitute.

The manifest must state, in `release.intended_use` and
`protocols.mixed_version_behavior`:

- **Categorical restart-cause reporting requires agent 0.1.8 or later.**
- Endpoints on 0.1.7 or earlier keep working unchanged. They send no `sources`
  key, so the alert detail reports `verdict: "unknown"` and the dashboard reads
  "Cause unavailable" while still showing correlated update activity beneath it,
  labelled as correlation.
- Roll the server out before the agent, as for every monitoring change. A 0.1.8
  agent against an older server is also safe: the extra detail keys are additive
  and stay well inside the 16 KiB bounded-detail cap.

And in `known_limitations`:

- Absence of `sources` means the cause is unknown; it must never be read as
  evidence that a restart is not update-related.
- `pending_file_rename_count` is best-effort and is omitted rather than reported
  as zero when the count query fails. The file paths behind it are deliberately
  never collected, because result detail is meant to stay safe to forward to
  alert email and third-party webhooks.

No schema change, no new command kind, no protocol change, and no authorization
change: `database.alembic_revision` is unaffected by this work.
