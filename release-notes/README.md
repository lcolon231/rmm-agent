# Release-specific evidence

Every version tag requires a source manifest at
`release-notes/<tag>.json`. Copy `TEMPLATE.json`, rename it to the exact tag,
and replace every required value before creating the tag. The template is
intentionally invalid until completed.

The release gate has two fail-closed phases:

1. **Preflight**, before tests or builds, validates the tag, component
   versions, exact Alembic and protocol identifiers, known limitations,
   upgrade and rollback procedures, security impact, immutable rollback
   target, verified-backup reference, and retained evidence links. Missing
   fields, placeholder text, mutable references such as `main` or `latest`,
   abbreviated commits, and invalid digests stop the workflow.
2. **Finalization**, after the agent and installer jobs finish but before a
   GitHub Release exists, binds the tag to `GITHUB_SHA`, verifies
   `SHA256SUMS.txt` and the installer checksum sidecar against the downloaded
   build outputs, computes all final artifact digests, and renders
   `RELEASE-NOTES.md` plus `release-evidence-<version>.json`.

The GitHub Release is created once, only after finalization. Its body is the
validated Markdown, and both rendered files are retained as release assets.
Artifact digests and the source commit are workflow-generated because neither
can be self-recorded in the source manifest before the tagged commit and
artifacts exist.

## Validation command

From the repository root:

```bash
python3 server/scripts/validate_release_notes.py \
  --manifest release-notes/v1.2.3.json \
  --tag v1.2.3 \
  --phase preflight
```

The validator exits `2` for an invalid record. Its unit and artifact-binding
tests run in the server test suite:

```bash
cd server
pytest -q tests/test_release_notes.py
```

`examples/v0.0.0-release-notes-rehearsal.json` is a valid synthetic input used
by those tests. It is not a deployable release record. The tests build
deterministic synthetic artifacts, prove checksum-tamper rejection, and render
the same complete evidence shape that a real tag publishes.

## Release operator checklist

- Use an exact tag and full rollback commit, never a branch or `latest`.
- Record every agent artifact digest and the installer digest for the
  last-known-good rollback target.
- Link a versioned backup manifest plus its SHA-256 and immutable restore
  verification evidence.
- State limitations even when they block deployment.
- Name schema and command-envelope compatibility explicitly.
- Provide executable upgrade verification and the forward-fix/redeploy/restore
  decision path.
- Describe fixed vulnerabilities, retained/new risks, and required operator
  actions without making unsupported readiness claims.
- Run preflight before tagging, then confirm the tag workflow publishes the
  rendered notes and JSON evidence before approving deployment.
