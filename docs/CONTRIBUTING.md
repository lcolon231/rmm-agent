# Contributing to NodeLink

NodeLink is security-sensitive endpoint-management software. Small, reviewable
changes with explicit tests and documentation are preferred over broad feature
passes.

## Start with the source of truth

Before changing behavior, read:

1. [ARCHITECTURE.md](ARCHITECTURE.md)
2. [threat-model.md](threat-model.md)
3. [ROADMAP.md](ROADMAP.md)
4. [SECURITY-ROADMAP.md](SECURITY-ROADMAP.md) for trust-boundary work
5. [DEPLOYMENT-READINESS.md](DEPLOYMENT-READINESS.md) for deployment/release work

Code is the final authority on what exists. If documentation and code differ,
correct the documentation in the same pull request and call out the drift.

## Choose an issue

Roadmap work should have one milestone, one `phase:*` label, relevant `area:*`
labels, one `type:*` label, and one priority. Large designs must be split into
implementable issues. An issue is actionable when it defines:

- Summary and why the work matters.
- In-scope behavior and explicit out-of-scope behavior.
- Affected components, schemas, migrations, APIs, security boundaries, and
  likely dependencies.
- Objectively verifiable acceptance criteria.
- Unit, integration, Windows, security, and end-to-end testing requirements as
  applicable.
- Documentation updates and linked dependencies.

Use `needs-design` when an interface or security decision is genuinely open.
Use `blocked` only with a link to the issue or maintainer decision that prevents
progress.

## Development rules

- Preserve working functionality and compatibility unless the issue explicitly
  defines a migration or removal.
- Do not claim a feature exists until code and verification support the claim.
- Do not claim HIPAA compliance. Use precise language such as
  “HIPAA-supporting controls,” “designed for regulated environments,” or
  “compliance evidence.”
- Keep Windows as the primary support target until the cross-platform milestone
  changes that policy.
- Prefer typed endpoint operations with validated inputs over arbitrary shell
  commands.
- Keep polling as a resilient fallback when live transport is introduced.
- Integrate MeshCentral for remote desktop; do not create a proprietary remote
  desktop protocol.
- Do not add a major dependency without documenting ownership, update cadence,
  security boundary, license, deployment impact, and why existing dependencies
  are insufficient.
- Never commit credentials, command-signing private keys, enrollment tokens,
  agent identities, production data, or test artifacts containing secrets.

## Security-sensitive changes

Changes to authentication, authorization, enrollment, command schemas,
canonicalization, signing, execution, endpoint storage, transport, audit,
tenancy, updates, releases, or recovery require:

- Threat-boundary analysis in the pull request.
- Negative tests and malformed/unauthorized input tests.
- Compatibility, rollout, and rollback notes.
- Audit-event and redaction review.
- Windows tests when endpoint or installer behavior changes.
- Synchronized architecture, threat-model, readiness, and runbook updates.

Never change command canonicalization on only one side. Version protocol changes
and use shared vectors consumed by both server and agent tests.

## Local checks

Server:

```bash
cd server
pip install -r requirements.txt pytest pytest-asyncio httpx aiosqlite
python scripts/gen_command_keys.py
pytest -q
```

Agent:

```bash
cd agent
gofmt -w .
go vet ./...
go build ./...
go test ./...
```

Before committing, inspect the diff for generated binaries, local databases,
keys, `.env`, `config.json`, `identity.json`, and replay-store files. Do not add
them.

## Pull requests

Keep a pull request focused on its issue. The description must cover purpose,
current state, what changed, known limitations, security implications,
verification, documentation, migrations/deployment impact, and follow-up work.

Mark incomplete or design-stage changes as draft. Do not merge with failing
required checks or unresolved critical/high security findings. If a test cannot
run, explain why and what evidence substitutes for it; “not tested” is not
acceptable for a security-sensitive endpoint change.

## Documentation language

Use four explicit states where relevant:

- **Implemented now:** present and verified in the repository.
- **In progress:** actively tracked but not complete.
- **Planned:** accepted roadmap scope without implementation.
- **Not implemented:** named explicitly when readers might otherwise infer it.

Avoid future-tense architecture prose that reads like a current guarantee.
