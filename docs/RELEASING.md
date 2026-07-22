# Releasing the NodeLink RMM agent

Releases are automated by `.github/workflows/release.yml`, which fires on a
version tag. The server is run from source (uvicorn), so only the **agent** is
released as a binary.

The tag-triggered release workflow is configured to publish SHA-256 checksums,
an SPDX SBOM, and signed SLSA build-provenance attestations for every executable
artifact, and Windows service/installer lifecycle tests run in CI on every
push. It does **not**
Authenticode-sign the Windows agent or installer — that requires a paid
code-signing certificate and is the one remaining release-authenticity gap —
and a production rollback has not been validated against a real deployment. Do
not describe a tagged artifact as production-ready. See
[`DEPLOYMENT-READINESS.md`](DEPLOYMENT-READINESS.md).

## Cutting a release

1. Make sure `main` is green (the CI workflow runs the Go and Python suites on
   every push/PR).
2. Tag and push:

   ```bash
   git checkout main && git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. The workflow runs the Go tests, cross-builds with the version stamped in
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

The workflow publishes and (where possible) verifies:

- **SHA-256 checksums** — `SHA256SUMS.txt` covers all three agent binaries and
  the SBOM; a `.sha256` sidecar covers the installer. *Workflow implemented.*
- **SBOM** — `nodelink-<version>.spdx.json`, an SPDX document covering the Go
  module and Python server dependencies. *Workflow implemented.*
- **Build provenance** — signed SLSA attestations tying each artifact digest to
  the source ref and workflow (`actions/attest-build-provenance`) for all three
  agent binaries and the Windows installer, verifiable with
  `gh attestation verify`. *Workflow implemented.*
- **Windows service and installer lifecycle results** — exercised by the
  `windows-lifecycle` CI job on every push (see `.github/workflows/ci.yml`).
  *Done.*
- **Authenticode signatures and trusted timestamps** for the embedded agent and
  final installer. *Not done — requires a paid certificate (see below). This is
  the remaining release-authenticity gap.*
- **Compatibility, migration, backup, upgrade, and rollback notes** — see the
  sections below and `docs/BACKUP-RESTORE.md`.

Because the SBOM, provenance, and checksum steps run inline, a failure in any of
them fails the release job. The signing step will fail closed the same way once
it is added.

### Tagged-release evidence status

SBOM generation and provenance attestation were added after the existing
`v0.1.0` and `v0.1.1` releases. Those releases therefore do not prove this
workflow path: their asset lists contain neither an SPDX SBOM nor the installer
checksum sidecar. The first tag cut after this workflow change must be treated
as the evidence run. For that tag, retain the workflow URL and verify:

```bash
gh release view <tag> --repo lcolon231/rmm-agent --json assets,url
gh attestation verify rmm-agent-windows-amd64.exe --repo lcolon231/rmm-agent
gh attestation verify rmm-agent-linux-amd64 --repo lcolon231/rmm-agent
gh attestation verify rmm-agent-darwin-arm64 --repo lcolon231/rmm-agent
gh attestation verify NodeLinkAgentSetup-<version>.exe --repo lcolon231/rmm-agent
sha256sum -c SHA256SUMS.txt
```

On Windows, separately compare the installer digest with
`NodeLinkAgentSetup-<version>.exe.sha256`. Do not mark the tagged evidence as
verified until every command succeeds. Provenance and SBOM evidence can only
come from an actual tag push because the release workflow does not run on pull
requests.

## Current schema and agent compatibility

Server releases containing Alembic revision `0004` require `alembic upgrade
head` before non-debug startup. Roll out the database revision and server first,
then upgrade agents. Command dispatch returns `409` until an agent advertises
`command-v3`; old queued commands are expired by the migration. A new agent
refuses commands from an old server because they lack an envelope version, and
a new server rejects enrollment when no supported version overlaps.

There is no in-place schema or protocol downgrade. Prefer a forward fix. A
restore to the pre-`0004` database and old components is an explicit destructive
recovery choice and discards post-backup data; it is not a normal release
rollback.

## Rollback (not yet validated)

Every production-intended release needs a version-specific rollback procedure
that names compatible server, agent, installer, and schema versions; states
whether migrations are reversible; pauses automatic update; preserves audit
evidence; and verifies the restored service. The generic acceptance checklist is
in [`DEPLOYMENT-READINESS.md`](DEPLOYMENT-READINESS.md). There is no supported
production rollback procedure today.

## What is intentionally NOT released here

- **The server** — run from source behind a TLS-terminating proxy
  (`docs/DEPLOYMENT-TLS.md`). A container image is a reasonable future
  addition.
- **The command signing key** — generated per-deployment
  (`scripts/gen_command_keys.py`), never built into or shipped with the agent.
  The agent receives only the **public** key, at enrollment.
