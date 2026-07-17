# Releasing the NodeLink RMM agent

Releases are automated by `.github/workflows/release.yml`, which fires on a
version tag. The server is run from source (uvicorn), so only the **agent** is
released as a binary.

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

`rmm-agent.exe -version`-style identification: the version is compiled in and
printed in the startup log line (`NodeLink RMM agent <version> starting`).

## Verifying a download

```bash
sha256sum -c SHA256SUMS.txt      # from the folder containing the binaries
```

On Windows (PowerShell):

```powershell
Get-FileHash .\rmm-agent-windows-amd64.exe -Algorithm SHA256
# compare against the matching line in SHA256SUMS.txt
```

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
the signed binary. Keep the certificate/keys in GitHub Actions secrets or a
cloud HSM — never in the repo.

## What is intentionally NOT released here

- **The server** — run from source behind a TLS-terminating proxy
  (`docs/DEPLOYMENT-TLS.md`). A container image is a reasonable future
  addition.
- **The command signing key** — generated per-deployment
  (`scripts/gen_command_keys.py`), never built into or shipped with the agent.
  The agent receives only the **public** key, at enrollment.
