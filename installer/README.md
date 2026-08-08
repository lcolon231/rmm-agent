# NodeLink RMM Agent — Windows installer

A graphical Inno Setup installer that wraps the existing agent binary so a
non-technical person can install the agent on an endpoint: run the setup, enter
the enrollment token, watch the progress page, and get a clear "Setup
Completed" screen. On an already-enrolled endpoint, setup instead performs a
tokenless in-place upgrade and preserves the existing identity and
configuration. The production server URL is configured automatically; no
terminal or server-address entry is required.

The installer targets **x64 Windows** (`ArchitecturesAllowed=x64compatible`).
Supported Windows versions, editions, and the Server Core CLI path are defined
in [`docs/WINDOWS-SUPPORT-MATRIX.md`](../docs/WINDOWS-SUPPORT-MATRIX.md).

The installer deliberately contains **no service logic of its own** — it shells
out to the agent's built-in CLI verbs (`rmm-agent.exe install|start|uninstall`),
which own service registration, SCM auto-recovery, and idempotent removal. The
agent stays a standard-library-only Go binary; the GUI lives entirely in this
separate artifact.

## Zero-touch: personalized download from the dashboard

An authorized technician can download a **personalized, site-scoped package**
from the dashboard so the person at the endpoint never sees or types a token.
The download is a ZIP containing the stock installer (shipped byte-for-byte,
never re-signed) plus a small sidecar file `nodelink-enroll.token` holding a
**short-lived, single-use** enrollment token.

Extract the ZIP and run the installer **from the extracted folder** (so it sits
beside the sidecar). The installer reads the token automatically and **skips the
token prompt entirely** — the user just clicks through to "Setup Completed". The
token never appears in a URL, filename, window, or log.

Token precedence is `/TOKEN=<token>` argument → sidecar file → interactive
prompt, so:

- **Personalized download:** double-click, zero questions about enrollment.
- **Silent/mass deployment:** `NodeLinkAgentSetup-<v>.exe /VERYSILENT /TOKEN=<token>`,
  or drop the sidecar beside a silent run.
- **Plain stock installer** (no sidecar, no argument): the interactive token
  prompt still appears, unchanged.

> Security: treat a personalized package like a credential until installed — the
> bundled token is single-use and expires quickly, but anyone with the ZIP can
> enroll one machine to that site before it lapses. Do not email it or commit
> it; the dashboard records each download for audit.

The clean-VM validation runbook for this flow is
[`docs/INSTALLER-E2E-WINDOWS.md`](../docs/INSTALLER-E2E-WINDOWS.md).

## What the setup does

1. Requires Administrator (UAC) — registering a Windows service needs elevation.
2. Installs `rmm-agent.exe` to `C:\Program Files\NodeLink\Agent`.
3. Detects whether the selected install directory has a supported protected
   `identity.json` and a usable token-free `config.json`. If so, setup enters
   **upgrade mode**, skips all token handling, and preserves both files. An
   inconsistent existing identity/config pair is blocked before setup changes
   the service or binary.
4. On a fresh install, obtains the one-time **enrollment token** from (in order)
   a `/TOKEN=` argument, a bundled `nodelink-enroll.token` sidecar, or an
   interactive prompt, then writes `config.json` with the fixed production
   origin `https://nodelink-backend-733e.onrender.com` and supplied token.
5. Runs `rmm-agent.exe install -config ...` then `rmm-agent.exe start`, showing
   a status line for each step on the progress page.
6. On uninstall, runs `rmm-agent.exe uninstall` (stops + removes the service)
   before deleting files, and cleans up the runtime files the agent created
   (`config.json`, `identity.json`, `seen_commands.json`,
   `monitoring_state.json`).

Upgrade mode never consumes a supplied sidecar or `/TOKEN=` value and never
rewrites `config.json` or `identity.json`. It deregisters the old service,
replaces the binary, validates the preserved config while registering the new
service, and starts it with the same enrolled identity. A deliberate uninstall
through Apps & Features remains the clean-slate path and removes runtime state.

After successful service-context enrollment, the agent atomically rewrites
`config.json` without the consumed plaintext token. Scripted deployments should
prefer the agent's explicit `enroll --token-env|--token-file|--token-stdin`
inputs, while ensuring enrollment runs under the same account that will later
decrypt the DPAPI-protected identity (LocalSystem for this service).

## Building it

Prerequisites:

- [Inno Setup 6](https://jrsoftware.org/isinfo.php) (6.3 or newer — the script
  uses the `x64compatible` architecture identifier)
- Go (to build the agent binary the installer wraps)

Steps (from the repo root, on Windows):

```powershell
# 1. Build the agent — produces agent\bin\rmm-agent-windows-amd64.exe
cd agent
./build.sh 0.1.0          # from Git Bash / WSL; or plain `go build` per agent/README.md

# 2. Compile the installer
cd ..\installer
$env:NODELINK_VERSION = '0.1.0'
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" NodeLinkAgent.iss
```

The output lands at `installer\Output\NodeLinkAgentSetup-<version>.exe`.

- `NODELINK_VERSION` sets the installer's `AppVersion` and output filename; if
  unset it falls back to `0.0.0-dev` (fine for local experiments).
- The agent binary is sourced from `..\agent\bin\rmm-agent-windows-amd64.exe`
  by default; point elsewhere with `/DAgentExe=<path>` on the `ISCC` command
  line (this is how CI could feed a differently-named build).

In CI, the release workflow (`.github/workflows/release.yml`) builds the
installer on a `windows-latest` runner and attaches it to the GitHub Release
alongside the raw binaries.

## Relation to the CLI install path

The production installer is a wrapper for endpoints; the CLI path in
[`agent/README.md`](../agent/README.md) (`rmm-agent.exe install -config
config.json` from an elevated prompt) remains fully supported and is what the
installer itself calls under the hood. Scripted/mass deployments can keep using
the CLI with a custom server, or drive this setup silently with
`/VERYSILENT /TOKEN=<token>`. The production installer does not accept a custom
server URL; self-hosted deployments should provision `config.json` and use the
CLI path.

The graphical installer does not prompt for optional `tls_spki_pins`.
High-assurance deployments should provision `config.json` through the CLI/mass
deployment path, or add the verified current+next pins to the installed config
and restart the service before relying on pin enforcement. See
[`docs/CERTIFICATE-PINNING.md`](../docs/CERTIFICATE-PINNING.md).

Like the raw binaries, the installer is currently **unsigned** — SmartScreen
may warn on first run until Authenticode signing is added (see
`docs/RELEASING.md`).
