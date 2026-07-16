# NodeLink RMM — Agent

A single-binary endpoint agent written in Go with **no external dependencies**
(standard library only). It enrolls once, then checks in on a fixed cadence:
reporting telemetry, picking up commands, verifying each command's Ed25519
signature before running it, and reporting results.

## Why Go / stdlib-only

- One static binary per platform, no runtime to install — drop it on a machine
  and run it.
- No third-party modules means a minimal supply-chain surface, which matters on
  endpoints in regulated environments.
- Cross-compiles to Windows, Linux, and macOS from one machine.

The one dependency is `golang.org/x/sys` — a deliberate exception to the
stdlib-only rule. It is maintained by the Go team and is the standard, correct
way to write a Windows service; it is only compiled into the Windows build
(behind build tags), so the Linux/macOS binaries remain pure stdlib.

## Build

```bash
cd agent
./build.sh 0.1.0          # produces bin/rmm-agent-{windows-amd64.exe,linux-amd64,darwin-arm64}
# or a single target:
GOOS=windows GOARCH=amd64 go build -o rmm-agent.exe ./cmd/agent
```

## Configure & run

```bash
cp config.example.json config.json
# set server_url and paste a one-time enrollment_token from the server
./rmm-agent -config config.json
```

- On first run the agent enrolls, receives its identity + the server's command
  **public key**, and writes `identity.json` (mode 0600) next to the config.
- On later runs it loads `identity.json` and skips enrollment. The
  `enrollment_token` in the config is only used once.
- `-once` runs a single check-in and exits (useful for testing / cron-style use).
- `run` is the default subcommand, so `./rmm-agent -config config.json` and
  `./rmm-agent run -config config.json` are equivalent.

If the server is unreachable, the agent does **not** crash or spin: the check-in
loop retries with exponential backoff + jitter (capped), so a down server just
means "keep trying quietly" until it comes back.

## Running as a Windows service

On Windows the same binary can install itself as an auto-starting service so it
survives reboots and crashes with nobody logged in. The service subcommands are
Windows-only (on Linux/macOS, run the agent in the foreground under
systemd/launchd instead).

```powershell
# From an elevated (Administrator) prompt, next to the binary:
rmm-agent.exe install -config config.json   # register + auto-start at boot, copy config beside the binary
rmm-agent.exe start                          # start it now
rmm-agent.exe stop                           # stop it
rmm-agent.exe uninstall                      # remove it (safe to run even if not installed)
```

- **install** registers the service `NodeLinkAgent` to start automatically at
  boot, copies the given config to `config.json` **next to the binary** (where
  the service reads it from), and configures Windows SCM auto-recovery to restart
  the service on crash with an escalating backoff (5s, 15s, then 60s; the failure
  counter resets after a day of stable running).
- **uninstall** stops (if running) and removes the service. It is idempotent —
  running it when the service isn't installed succeeds quietly.
- When running as a service there is no console, so the agent logs to a
  size-rotated file at `%ProgramData%\NodeLink\logs\rmm-agent.log`
  (10 MB per file, 5 rotations kept). In the foreground it still logs to stdout.
- On service stop the agent stops accepting new commands, lets an in-flight
  command finish (up to a grace period) or force-cancels it so no child process
  is orphaned, then exits.

## What it collects

Each heartbeat reports CPU %, memory %, disk % (system drive), uptime, and the
logged-in user. On Windows these come from CIM/WMI queries via PowerShell; on
Linux from `/proc` and `statfs`.

## Command safety

Every command the agent receives carries an Ed25519 signature from the server.
The agent recomputes the canonical command bytes and verifies the signature
against the public key it got at enrollment. **A command that fails verification
is refused and never executed** — the agent reports a failure result instead.
The canonical encoding matches the server's exactly (sorted keys, no whitespace,
no HTML escaping), which is covered by a test in `internal/verify`.

Two further checks run after signature verification, in the order
signature → TTL → replay → execute:

- **TTL enforcement.** The agent honors the server's `expires_at` and refuses any
  command whose deadline has passed, reporting a failure result. Parsing fails
  closed: a present-but-unparseable timestamp is treated as expired; an empty or
  absent value means "no TTL". Because `expires_at` is not part of the signed
  bytes today, this is defense-in-depth over the server's own expiry (binding it
  into the signature is noted as future work in `docs/threat-model.md`).
- **Replay protection.** The agent persists the set of already-executed command
  IDs to `seen_commands.json` (mode 0600, beside `identity.json`, written
  atomically) and refuses to run the same command ID twice, surviving restarts.
  A replayed command is neither executed nor re-reported, so it cannot clobber
  the original result. Expired IDs are pruned on load.

Supported command kinds: `powershell` (Windows / `pwsh` on Unix), `shell`
(`cmd.exe` / `/bin/sh`), and `collect_inventory`. Commands run with a 5-minute
timeout.

## Layout

```
agent/
├── cmd/agent/main.go            # entry point: subcommand dispatch + foreground run
└── internal/
    ├── config/                  # config + persisted identity
    ├── client/                  # HTTP client for the server API
    ├── telemetry/               # metrics (per-OS build tags)
    ├── executor/                # command execution (per-OS build tags)
    ├── verify/                  # Ed25519 command signature verification
    └── service/                 # OS-independent runtime + Windows service (SCM,
                                 #   install/uninstall/start/stop, auto-recovery,
                                 #   file logging, backoff)
```

## Roadmap

- Agent self-update.
- Persistent WebSocket channel to replace heartbeat command-polling for lower
  command latency.
