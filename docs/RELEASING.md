# Releasing the NodeLink RMM agent

Releases are automated by `.github/workflows/release.yml`, which fires on a
version tag. The server is run from source (uvicorn), so only the **agent** is
released as a binary.

Supported platforms are defined by the
[Windows support matrix](WINDOWS-SUPPORT-MATRIX.md) and the machine-readable
[`agent/supported-targets.txt`](../agent/supported-targets.txt). CI
(`tools/check_release_targets.py`) fails if the shipped build targets drift from
that list. **Every release must identify the support matrix and call out any
release-specific platform exceptions in its notes.**

The current release process publishes SHA-256 checksums, an SPDX SBOM, and
signed SLSA build-provenance attestations for every artifact, and Windows
service/installer lifecycle tests run in CI on every push. It does **not**
Authenticode-sign the Windows agent or installer — that requires a paid
code-signing certificate and is the one remaining release-authenticity gap —
and a production rollback has not been validated against a real deployment.
The release rollback path is automated and CI-rehearsed, but a timed operator
drill is still required. Do not describe a tagged artifact as production-ready. See
[`DEPLOYMENT-READINESS.md`](DEPLOYMENT-READINESS.md).

## Cutting a release

1. Make sure `main` is green (the CI workflow runs the Go and Python suites on
   every push/PR).
2. Copy [`release-notes/TEMPLATE.json`](../release-notes/TEMPLATE.json) to
   `release-notes/<tag>.json` and fill every release-specific field. The record
   names the server tag, agent and installer versions, Alembic and protocol
   compatibility, known limitations, upgrade and rollback procedures, security
   impact, immutable last-known-good component digests, verified backup, and
   retained rollback evidence.
3. Run the same preflight used by the release workflow:

   ```bash
   python3 server/scripts/validate_release_notes.py \
     --manifest release-notes/v0.1.2.json \
     --tag v0.1.2 \
     --phase preflight
   ```

   Placeholder text, missing fields, mutable identifiers, abbreviated commits,
   and invalid digests fail validation. Confirm the named rollback backup has
   passed `verify_restore.py`.
4. Commit the completed manifest, make sure `main` is green, then tag and push:

   ```bash
   git checkout main && git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

5. The workflow revalidates the manifest before tests or builds, cross-builds
   with the version stamped in
   (`-ldflags "-X main.version=<tag without v>"`), and publishes a GitHub
   Release with:
   - `rmm-agent-windows-amd64.exe`
   - `rmm-agent-linux-amd64`
   - `rmm-agent-darwin-arm64`
   - `SHA256SUMS.txt`
   - `NodeLinkAgentSetup-<version>.exe` — the graphical Windows installer
     (built on a Windows runner from `installer/NodeLinkAgent.iss`; see
     `installer/README.md`). Like the raw binaries it is **unsigned**;
     Authenticode signing slots in at the same place (below). Linux/macOS have
     no installer — those platforms use the foreground/systemd path described
     in `agent/README.md`.
   - `RELEASE-NOTES.md` and `release-evidence-<version>.json` — the validated
     release body and machine-readable record bound to the tag commit and final
     artifact digests.

`rmm-agent.exe -version`-style identification: the version is compiled in and
printed in the startup log line (`NodeLink RMM agent <version> starting`).

## Verifying a download

Checksums:

```bash
sha256sum -c SHA256SUMS.txt      # from the folder containing the binaries
```

On Windows (PowerShell):

```powershell
Get-FileHash .\rmm-agent-windows-amd64.exe -Algorithm SHA256
# compare against the matching line in SHA256SUMS.txt
```

Build provenance (proves the artifact was built by this repo's release
workflow from the tagged source, via a signed Sigstore attestation):

```bash
gh attestation verify rmm-agent-windows-amd64.exe --repo lcolon231/rmm-agent
gh attestation verify NodeLinkAgentSetup-<version>.exe --repo lcolon231/rmm-agent
```

SBOM: `nodelink-<version>.spdx.json` is an SPDX 2.3 document listing the Go and
Python dependencies the release was built from. Inspect it with any SPDX tool
(e.g. `syft convert`, `grype sbom:...` for vulnerability matching).

## Code signing (not yet wired up)

The published `.exe` is currently **unsigned**, so Windows SmartScreen may warn
on first run and some AV products are warier of unsigned binaries. This is
acceptable for machines you own and a knowing early client, but sign before
wider distribution.

To add signing, you need an Authenticode certificate:

- **OV** (Organization Validation) — ~$100–300/yr, now usually delivered on a
  hardware token or via a cloud HSM.
- **EV** or **Azure Trusted Signing** — better SmartScreen reputation from day
  one; Azure Trusted Signing is the least painful for CI.

Where it slots in: after `Cross-build all targets` and before publishing, add a
signing step that runs `signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256
...` (Windows runner) or Azure Trusted Signing's action, using secrets stored in
the repo/organization. Then regenerate `SHA256SUMS.txt` so the checksums cover
the signed binary. The Windows installer gets the same treatment in its own
job: sign the agent `.exe` before `ISCC` compiles it in, then sign the produced
`NodeLinkAgentSetup-<version>.exe` before upload. Keep the certificate/keys in GitHub Actions secrets or a
cloud HSM — never in the repo.

## Release evidence

Each release publishes and (where possible) verifies:

For releases containing revision `0021` or later, the compatibility record must
name the script-library migration, confirm a pre-upgrade backup, and retain
evidence for operator draft creation, readonly exact-version retrieval and
digest comparison, admin final review, idempotent deprecation, audit-chain
verification, and dashboard unavailable-state behavior. If rolling back the
application while retaining the additive schema, pause library writes; a
pre-`0021` restore requires an explicit library data-loss decision. See
[`SCRIPT-LIBRARY.md`](SCRIPT-LIBRARY.md).

- **SHA-256 checksums** — `SHA256SUMS.txt` for the binaries and a `.sha256`
  sidecar for the installer. *Done.*
- **SBOM** — `nodelink-<version>.spdx.json`, an SPDX document covering the Go
  module and Python server dependencies. *Done.*
- **Build provenance** — signed SLSA attestations tying each artifact digest to
  the source ref and workflow (`actions/attest-build-provenance`), verifiable
  with `gh attestation verify`. *Done.*
- **Windows service and installer lifecycle results** — exercised by the
  `windows-lifecycle` CI job on every push (see `.github/workflows/ci.yml`).
  *Done.*
- **Authenticode signatures and trusted timestamps** for the embedded agent and
  final installer. *Not done — requires a paid certificate (see below). This is
  the remaining release-authenticity gap.*
- **Compatibility, migration, backup, upgrade, and rollback notes** — see the
  tag-specific source manifest under `release-notes/`, its rendered release
  assets, and `docs/BACKUP-RESTORE.md`.

The workflow validates the operator-authored manifest before building. Agent
and installer jobs upload temporary workflow artifacts but do not create or
modify a GitHub Release. A final job downloads both outputs, verifies their
checksum files, binds their SHA-256 digests and the checked-out tag commit into
the evidence, and renders the release body. The single publication step cannot
run unless all
of those checks pass. The signing step will fail closed in the same pre-publish
path once it is added.

## Current schema and agent compatibility

The v0.1.2 enrollment candidate requires Alembic revision `0012`; non-debug
startup requires `alembic upgrade head`. Roll out the database revision,
server, and dashboard together. Revision 0009 adds the `result_pending` enum value and
`agent_completed_at`; durable dispatch-lease recovery is active only after both
server and agent are upgraded. Command dispatch returns `409` until an agent advertises
`command-v3`; old queued commands are expired by the migration. A new agent
refuses commands from an old server because they lack an envelope version, and
a new server rejects enrollment when no supported version overlaps.

Revision `0010` adds nullable operator arbitrary-script permission columns.
Null is intentionally default deny for all existing and new operators,
including admins. No agent or signed-envelope change is required. After
migration, admins must explicitly grant the narrowest necessary global, site,
or agent scope; see `SCRIPT-AUTHORIZATION.md`.

Revision `0011` adds enrollment-token assignment/lifecycle metadata, agent
credential and enrollment metadata, and audit query dimensions. Revision
`0012` conditionally repairs legacy debug-created databases whose Alembic
marker was stamped without the matching schema. New token creation requires
expiry; legacy tokens with no expiry fail closed. Preserve `/api/v1/enroll`
compatibility while deploying the `/api/v1/agents/enroll` alias, token
management dashboard, and agent CLI together. See
[`agent-enrollment/operations.md`](agent-enrollment/operations.md).

Public v0.1.1 has no Alembic marker. Its exact schema may be adopted as baseline
`0001` only through `server/scripts/adopt_v011_schema.py`, which fails closed
on schema drift, and then upgraded forward to `0012`. Directly stamping an
unverified database is unsupported. This is an upgrade path only: a v0.1.1
server remains incompatible with an `0012` database and is not an in-place
rollback target. The retained-evidence procedure is
[`V0.1.2-RELEASE-DRILL.md`](V0.1.2-RELEASE-DRILL.md).

There is no in-place schema or protocol downgrade. Prefer a forward fix. A
restore to an older database and matching old components is an explicit destructive
recovery choice and discards post-backup data; it is not a normal release
rollback.

## Rollback

The operator runbook is [`ROLLBACK.md`](ROLLBACK.md). The tag-specific source
manifest and finalized release evidence name the compatible server, agent,
installer, schema, protocols, backup, and immutable last-known-good target.
The runbook fails closed until external agent rollout is paused, treats
migrations as forward-only, preserves the failed-state backup and audit
evidence, and defines post-rollback checks.
`scripts/plan_release_rollback.py` records the forward-fix/redeploy/restore
decision, and the PostgreSQL CI suite rehearses the restore path through
`verify_restore.py`.

This is reproducible automated evidence, not a claim that a production
deployment or operator response has been drilled. Perform and retain a timed
production-topology rehearsal before treating the release as production-ready.

## What is intentionally NOT released here

- **The server** — run from source behind a TLS-terminating proxy
  (`docs/DEPLOYMENT-TLS.md`). A container image is a reasonable future
  addition.
- **The command signing key** — generated per-deployment
  (`scripts/gen_command_keys.py`), never built into or shipped with the agent.
  The agent receives only the **public** key, at enrollment.
