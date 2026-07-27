# NodeLink RMM Agent — Windows installer

A graphical Inno Setup installer that wraps the existing agent binary so a
non-technical person can install the agent on an endpoint: run the setup,
enter the server URL and enrollment token, watch the progress page, and get a
clear "Setup Completed" screen. No terminal required.

The installer targets **x64 Windows** (`ArchitecturesAllowed=x64compatible`).
Supported Windows versions, editions, and the Server Core CLI path are defined
in [`docs/WINDOWS-SUPPORT-MATRIX.md`](../docs/WINDOWS-SUPPORT-MATRIX.md).

The installer deliberately contains **no service logic of its own** — it shells
out to the agent's built-in CLI verbs (`rmm-agent.exe install|start|uninstall`),
which own service registration, SCM auto-recovery, and idempotent removal. The
agent stays a standard-library-only Go binary; the GUI lives entirely in this
separate artifact.

## What the setup does

1. Requires Administrator (UAC) — registering a Windows service needs elevation.
2. Installs `rmm-agent.exe` to `C:\Program Files\NodeLink\Agent`.
3. Prompts for the **server URL** (prefilled `https://`) and the one-time
   **enrollment token**; both are required before you can continue.
4. Writes `config.json` next to the binary from those values.
5. Runs `rmm-agent.exe install -config ...` then `rmm-agent.exe start`, showing
   a status line for each step on the progress page.
6. On uninstall, runs `rmm-agent.exe uninstall` (stops + removes the service)
   before deleting files, and cleans up the runtime files the agent created
   (`config.json`, `identity.json`, `seen_commands.json`).

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

The installer is a wrapper for endpoints; the CLI path in
[`agent/README.md`](../agent/README.md) (`rmm-agent.exe install -config
config.json` from an elevated prompt) remains fully supported and is what the
installer itself calls under the hood. Scripted/mass deployments can keep using
the CLI or drive this setup silently (`/VERYSILENT` is **not** wired to the
config prompts — silent installs should use the CLI path instead).

The graphical installer does not prompt for optional `tls_spki_pins`.
High-assurance deployments should provision `config.json` through the CLI/mass
deployment path, or add the verified current+next pins to the installed config
and restart the service before relying on pin enforcement. See
[`docs/CERTIFICATE-PINNING.md`](../docs/CERTIFICATE-PINNING.md).

Like the raw binaries, the installer is currently **unsigned** — SmartScreen
may warn on first run until Authenticode signing is added (see
`docs/RELEASING.md`).
