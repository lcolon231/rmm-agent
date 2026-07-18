# NodeLink RMM

NodeLink is a self-hosted endpoint-management platform for regulated small
businesses and MSPs. It provides signed remote actions, outbound-only
connectivity, and independently verifiable administrative audit records without
the operational complexity of traditional RMM platforms.

NodeLink is an early-stage, Windows-first project. It is not a full Tactical RMM
clone, is not ready for production or regulated endpoints, and does not claim
HIPAA compliance. The near-term goal is a controlled non-production pilot with
HIPAA-supporting controls and defensible compliance evidence.

## Product direction

NodeLink intends to compete through simpler deployment, policy-controlled and
signed endpoint actions, verifiable audit evidence, and a focused experience for
regulated SMBs and MSPs. General RMM breadth comes later. See the
[competitive strategy](docs/COMPETITIVE-STRATEGY.md) and the
[phased roadmap](docs/ROADMAP.md).

## Current implementation

The code in this repository currently provides:

- A Go agent that runs as a Windows service, connects outbound, and polls the
  FastAPI server through heartbeat responses.
- One-time or limited-use enrollment tokens and long-lived per-agent bearer
  credentials. Server-side token values are stored as SHA-256 hashes.
- Ed25519 signatures over the negotiated `command-v1` envelope: envelope
  version, command ID, agent ID, kind, and payload. Python and Go consume the
  same canonical vectors; agents reject missing, unknown, and downgraded
  envelope versions. Expiry, nonce, issued-at, and key ID are follow-on work.
- Basic CPU, memory, system-disk, uptime, and logged-in-user telemetry.
- Buffered PowerShell or shell execution with a five-minute timeout. Results
  are uploaded only after execution finishes.
- Operator password authentication, JWT sessions, three global roles, token
  generation revocation, and in-process login throttling.
- Client and site records, agent listing, command dispatch/history APIs, and an
  offline-status sweeper.
- A hash-chained audit log plus APIs that create and verify local Merkle
  anchors. Anchors are not automatically published outside the database.
- An Alembic baseline and forward migration, with exact revision enforcement
  on non-debug startup and a disposable PostgreSQL migration test in CI.
- An Inno Setup Windows installer and tagged release workflow. Windows
  binaries and the installer are currently unsigned.
- Linux and macOS development builds of the polling agent. Windows is the only
  primary support target; those builds are not a supported cross-platform RMM.

The [architecture document](docs/ARCHITECTURE.md) is the source of truth for
the implementation and its security boundaries.

## In progress

Milestone 0, Deployment Safety, is the active program: hardening the signed
command envelope's signed time/nonce/key fields, adding credential protection
and agent quarantine, enforcing
production TLS policy, bounding execution resources, making audit ordering and
anchoring operationally verifiable, adding migrations and recovery procedures,
and strengthening Windows and release testing.

## Planned

- **Milestone 1 — Windows RMM MVP:** authenticated Next.js dashboard, complete
  Windows inventory, monitoring and alerts, notification delivery, script
  library, and recurring tasks.
- **Milestone 2 — Patch and Remediation:** Windows Update policies and
  installation, software deployment, endpoint operations, interactive shell,
  streaming output, MeshCentral integration, and agent self-update.
- **Milestone 3 — Compliance Productization:** evidence bundles, approval
  workflows, tenant-scoped authorization, stronger identity controls,
  immutable retention, audit verification tools, and a customer audit portal.
- **Milestone 4 — Scale and Ecosystem:** shared infrastructure, distributed
  execution, high availability, public APIs, integrations, signed extensions,
  and later Linux/macOS support.

## Explicitly not implemented yet

The repository does **not** currently contain:

- A web dashboard, authentication UI, endpoint console, or audit UI.
- WebSocket or other live agent transport, interactive remote shell, or
  streaming command output. Polling remains the only transport.
- Complete hardware, software, Windows Defender, BitLocker, Secure Boot, TPM,
  or local-administrator inventory.
- Monitoring policy/check/alert models, alert acknowledgement, email, or
  webhook notifications.
- Script library, scheduled tasks, patch management, remediation operations,
  file transfer, or remote desktop.
- Agent revocation/quarantine, Windows DPAPI credential protection, command
  output-size limits, signing-key rotation, or certificate pinning.
- Automated backup/restore, an automated external audit-anchor publisher,
  release SBOM/provenance, or Authenticode signing.
- Tenant-scoped authorization, tenant-specific roles or retention, MFA,
  WebAuthn, OIDC/SAML, legal hold, or compliance evidence exports.

## Architecture at a glance

```text
Operator/API client -- JWT --> FastAPI server --> PostgreSQL
                              ^
                              |
Windows agent -- outbound HTTPS heartbeat/poll --+
                signed commands returned in heartbeat response
```

The application does not terminate TLS. The documented deployment topology
places Caddy in front of uvicorn and binds uvicorn to localhost. This is a
deployment procedure today, not an application-level production enforcement
mechanism. See [deployment readiness](docs/DEPLOYMENT-READINESS.md) and the
[TLS runbook](docs/DEPLOYMENT-TLS.md).

## Repository layout

```text
rmm-agent/
├── agent/       # Go endpoint agent and Windows service integration
├── server/      # FastAPI API and persistence layer
├── installer/   # Inno Setup Windows installer
├── deploy/      # Current reverse-proxy example
├── contracts/   # Versioned schemas and shared Go/Python canonical vectors
├── docs/        # Architecture, security, roadmap, and operations documents
└── .github/     # CI, release automation, and contribution templates
```

Future `dashboard/` and `tools/` directories are planned. No
disruptive reorganization is part of the current planning change.

## Local development

See [server/README.md](server/README.md) to run the backend,
[agent/README.md](agent/README.md) to build and enroll an agent, and
[installer/README.md](installer/README.md) for the Windows installer.

Before any pilot, review the [threat model](docs/threat-model.md),
[security roadmap](docs/SECURITY-ROADMAP.md), and
[deployment-readiness checklist](docs/DEPLOYMENT-READINESS.md).

## Contributing

Development work is organized through phased GitHub milestones and actionable
issues. Security-sensitive changes require tests, and architecture/security
documentation must be updated in the same pull request as behavior changes.
See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

NodeLink RMM Community Edition is licensed under the GNU Affero General
Public License v3.0 only. See [LICENSE](LICENSE).

SPDX-License-Identifier: AGPL-3.0-only

Commercial licensing may be offered separately for organizations that need
to embed, redistribute, modify, or operate NodeLink under terms other than
the AGPL.

The NodeLink name, logos, product identity, and branding are not licensed
under the AGPL. See [TRADEMARKS.md](TRADEMARKS.md).
