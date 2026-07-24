# NodeLink RMM — Agent

A single-binary endpoint agent written in Go with **no external dependencies**
(standard library only). It enrolls once, then checks in on a fixed cadence:
reporting telemetry, picking up commands, verifying each command's Ed25519
signature before running it, and reporting results.

Windows is the primary supported endpoint platform. Linux and macOS builds are
development artifacts for portability testing, not a supported cross-platform
RMM product. The supported Windows versions, editions, and architectures are
defined in [`docs/WINDOWS-SUPPORT-MATRIX.md`](../docs/WINDOWS-SUPPORT-MATRIX.md)
(machine-readable list: [`supported-targets.txt`](supported-targets.txt),
CI-enforced). The agent is not ready for production or regulated endpoints; see
[`docs/DEPLOYMENT-READINESS.md`](../docs/DEPLOYMENT-READINESS.md).

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
  **public key**, and writes `identity.json` next to the config — a versioned
  envelope whose payload is DPAPI-encrypted on Windows (mode 0600 plaintext
  with a declared `none` scheme elsewhere).
- On later runs it loads `identity.json` and skips enrollment; a pre-envelope
  plaintext identity is migrated in place on first load. The
  `enrollment_token` in the config is only used once.
- `-once` runs a single check-in and exits (useful for testing / cron-style use).
- `run` is the default subcommand, so `./rmm-agent -config config.json` and
  `./rmm-agent run -config config.json` are equivalent.

### Optional TLS SPKI pinning

High-assurance deployments may add multiple `tls_spki_pins` to `config.json`:

```json
"tls_spki_pins": [
  "sha256/<base64 SHA-256 of current leaf SPKI>",
  "sha256/<base64 SHA-256 of next leaf SPKI>"
]
```

Pinning is off when the field is absent or empty. When enabled, `server_url`
must use HTTPS; the agent still requires the normal OS trust chain, certificate
validity, and hostname match, then additionally requires one SPKI pin. Pins
stay in `config.json`, so an existing agent picks up an overlap/recovery set on
restart without re-enrollment. Use current+next overlap and rehearse the
out-of-band stale-pin path in [`CERTIFICATE-PINNING.md`](../docs/CERTIFICATE-PINNING.md).

On Windows the persisted identity is DPAPI-encrypted in user scope under the
account that enrolled (LocalSystem for the installed service) and its DACL is
restricted to SYSTEM and Administrators. Enrolling interactively as one user
and then running the service as another yields a clear unprotect error — the
recovery is to delete `identity.json` and re-enroll; there is no plaintext
fallback. The server can quarantine this agent (it keeps beating but executes
nothing) or revoke it (its token stops authenticating; the agent logs the
rejection and retries at capped backoff, keeping the identity on disk for
investigation). The local
`heartbeat_seconds` config field is also not currently applied after enrollment;
the saved server-provided interval is used.

If the server is unreachable, the agent does **not** crash or spin: the check-in
loop retries with exponential backoff + jitter (capped), so a down server just
means "keep trying quietly" until it comes back.

## Running as a Windows service

### GUI install (recommended for endpoints)

For hands-on installs by non-technical users there is a graphical installer
(`NodeLinkAgentSetup-<version>.exe`, published with each release) that wraps
this binary: it prompts for the server URL + enrollment token, writes
`config.json`, and registers + starts the service by calling the CLI verbs
below under the hood. See [`installer/README.md`](../installer/README.md).
The CLI path that follows remains fully supported and is what scripted
deployments should use.

### CLI install

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

Complete hardware/software inventory and Windows security-state inventory are
not implemented. Although the API accepts an optional inventory object, this
agent currently sends `nil`; `collect_inventory` only executes the supplied
script.

## Command safety

Every command the agent receives carries an Ed25519 signature from the server.
The agent recomputes the canonical command bytes and verifies the signature
against the public key it got at enrollment. **A command that fails verification
is refused and never executed** — the agent reports a failure result instead.
The `command-v3` signature covers `envelope_version`, `schema_version`,
`command_id`, `agent_id`, `kind`, `payload`, canonical UTC `issued_at` and
`expires_at`, and a unique nonce. Canonical JSON is UTF-8 with sorted keys, no
whitespace, no HTML escaping, signed 64-bit integers, no floating point, a
16-level nesting limit, and a 64 KiB envelope limit. Both runtimes consume
`contracts/command-v3.schema.json`; v2 remains a compatibility format without
key IDs.

The agent advertises `command-v3` and v2 during enrollment and every heartbeat. It
rejects a server that selects another version and refuses commands with a
missing, unknown, malformed, expired, future-dated, or legacy version before
execution. This is a fail-closed rollout boundary; it does not silently fall
back to the old format.

Checks run after signature verification in the order signature → time window →
command-ID replay → nonce replay → execute. The agent persists both replay keys
to `seen_commands.json` (mode 0600, beside `identity.json`, written atomically)
before starting a process. A replayed command ID is neither executed nor
re-reported, so it cannot clobber the original result. Expired entries are
pruned on load. For v3 the agent replaces its trusted public-key bundle on every
heartbeat, accepts only active/overlap key IDs supplied by the server, and
refuses unknown or retired keys. Operators rotate the server-side registry with
`scripts/rotate_command_key.py` (staged activation/overlap/retire, compromise,
and rollback — see `docs/KEY-ROTATION.md`); they must preserve the registry and audit records
when retiring or rolling back a key.

Supported command kinds: `powershell` (Windows / `pwsh` on Unix), `shell`
(`cmd.exe` / `/bin/sh`), and `collect_inventory`. Commands run with a 5-minute
timeout.

Commands from one heartbeat are executed sequentially and stdout/stderr are
captured in memory up to 256 KiB per stream (384 KiB combined), then uploaded
after completion. Bytes past a cap are counted but never buffered; when the
combined cap binds, stderr is kept whole and stdout trimmed. Truncation is
UTF-8-safe and reported to the server as structured metadata alongside the
original byte totals. Output streaming, queue/admission limits, and a
policy-configured concurrency contract are not implemented.

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

- Per-agent concurrency limits, typed endpoint operations, and signed releases.
- Complete Windows inventory, typed endpoint operations, and signed self-update.
- An interactive transport for lower-latency/streaming workflows while keeping
  heartbeat polling as a resilient fallback.
- Technician-to-end-user chat: a message-only chat window the agent surfaces on
  the endpoint so the machine's user can talk to the technician, carried over
  the interactive transport with endpoint-side accept/close and audited
  sessions — deliberately no command execution or remote control on that
  channel.
