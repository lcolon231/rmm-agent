# NodeLink RMM — Windows support matrix

This is the single source of truth for which Windows versions, editions, and
architectures NodeLink supports for the endpoint agent and installer (issue
#116). The machine-readable target list it mirrors is
[`agent/supported-targets.txt`](../agent/supported-targets.txt); CI
(`tools/check_release_targets.py`) fails if the shipped build targets drift from
that list, and this document must be updated in the same change.

Windows is the only **primary, supported** endpoint platform. Linux and macOS
builds are development/portability artifacts, not a supported cross-platform RMM
product (see [`agent/README.md`](../agent/README.md)).

## Architectures

| Target | Class | Installer | Notes |
|---|---|---|---|
| `windows/amd64` (x64) | **Supported** | `NodeLinkAgentSetup-<version>.exe` (`ArchitecturesAllowed=x64compatible`) | The released product target. Runs on x64 and on ARM64 via x64 emulation (x64-compatible), but native ARM64 is **not** built. |
| `linux/amd64` | Dev only | none | Portability build; not supported on endpoints. |
| `darwin/arm64` | Dev only | none | Portability build; not supported on endpoints. |

Native `windows/arm64` and `windows/386` (32-bit) are **excluded**: not built,
not shipped, not supported. Adding one requires a reviewed change to
`agent/supported-targets.txt`, this matrix, `agent/build.sh`, and the release
workflow (CI enforces they stay in sync).

## Supported Windows versions and editions

Supported means: within the OS vendor's servicing lifecycle, x64, and meeting
the prerequisites below. NodeLink does not extend support to end-of-life Windows.

### Windows client

| Version | Editions | Support class |
|---|---|---|
| Windows 11 (supported servicing channels) | Pro, Enterprise | Supported |
| Windows 10 (supported servicing channels, x64) | Pro, Enterprise | Supported |
| Windows 10/11 Home | — | Not supported (no reliable domain/BitLocker/management assumptions; may work, unqualified) |
| Windows 10 versions past end-of-servicing | — | Excluded |

### Windows Server

| Version | Editions | Support class |
|---|---|---|
| Windows Server 2022 | Standard, Datacenter | Supported |
| Windows Server 2019 | Standard, Datacenter | Supported |
| Server Core (2019/2022) | — | Supported (CLI install path; the GUI installer needs desktop experience) |
| Windows Server 2016 and earlier | — | Not supported |

## CI-tested vs manually qualified

| Target / behavior | Evidence |
|---|---|
| `windows/amd64` build + unit tests | **Continuous CI** (`windows-latest`, `ci.yml` job `agent (Go, Windows)`) |
| Service lifecycle (install/start/stop/restart/refuse-double-install/uninstall) | **Continuous CI** (`ci.yml` job `windows service + installer lifecycle`, issue #23) |
| DPAPI identity + restricted ACL | **Continuous CI** (Windows runner test) |
| Silent installer install/uninstall smoke | **Continuous CI** (Inno Setup on `windows-latest`) |
| Release-target/arch drift | **Continuous CI** (`release-targets` job, this document's list) |
| Specific client editions (Win 10/11 Pro vs Enterprise), Server Core, domain-joined DPAPI under a real service account | **Manual qualification** — `windows-latest` runners approximate but do not cover every edition; qualify on the pilot topology and retain the evidence in the pilot record. |

The hosted `windows-latest` runner is the continuous baseline. Editions and
configurations it does not represent are **manually qualified** on the target
before that configuration is declared supported, and the evidence is retained.

## Per-class expectations

These hold across all supported Windows targets unless noted:

- **Agent:** a single static `windows/amd64` binary, stdlib + `golang.org/x/sys`
  (Windows-only, behind build tags). No runtime to install.
- **Installer:** Inno Setup GUI installer (`x64compatible`, `PrivilegesRequired=admin`)
  for interactive installs; the CLI verbs (`install/start/stop/uninstall`) are
  the supported path for scripted/Server Core deployment.
- **Service identity:** runs as `LocalSystem`, auto-start at boot, SCM
  auto-recovery with escalating backoff.
- **DPAPI scope:** the persisted identity is DPAPI-encrypted in **user scope
  under the enrolling account** (LocalSystem for the installed service).
  Enrolling as one account and running the service as another fails closed —
  delete `identity.json` and re-enroll. See
  [`docs/DEPLOYMENT-READINESS.md`](DEPLOYMENT-READINESS.md).
- **Filesystem/ACL:** `identity.json` DACL is restricted to SYSTEM +
  Administrators; logs under `%ProgramData%\NodeLink\logs` (size-rotated).
- **PowerShell:** Windows PowerShell 5.1 (in-box) is required for telemetry
  (CIM/WMI) and `powershell` command execution; PowerShell 7 is not required.
- **TLS:** the agent uses the OS trust store for the outbound HTTPS connection;
  optional rotation-safe SPKI pinning is available
  ([`docs/CERTIFICATE-PINNING.md`](CERTIFICATE-PINNING.md)).
- **Upgrade/rollback:** installer upgrade-in-place preserves `config.json`/
  `identity.json`; uninstall removes agent-created credential files. Signed,
  staged agent self-update is future work (Milestone 2). Windows artifacts are
  not yet Authenticode-signed (issue #24).

## Support and deprecation policy

- A Windows version is supported only while within the OS vendor's servicing
  lifecycle. When a version reaches end-of-servicing it moves to **Excluded** at
  the next NodeLink release; release notes call out the change.
- A target that is not continuously available in hosted CI (specific editions,
  Server Core, real domain service accounts) is **manually qualified** and
  re-qualified when its prerequisites materially change. Loss of qualification
  evidence downgrades it to unsupported.
- Adding or removing an **architecture** requires updating
  `agent/supported-targets.txt` and this matrix together; CI blocks drift.
- Each release identifies this matrix and any release-specific exceptions in its
  notes (see [`docs/RELEASING.md`](RELEASING.md)).
