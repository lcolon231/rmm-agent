# NodeLink RMM — Credential Redaction Audit

This document is the reproducible evidence required by the Milestone 0
controlled-pilot gate for issues **#112** (logs, diagnostics, command results,
uninstall) and **#115** (audit-event detail). It records the credential
inventory, every surface that can handle those credentials, the enforced
redaction boundaries, the tests that keep them honest, and the residual
limitations under the current threat model.

The two issues split cleanly by surface, because the audit chain has a
constraint the other surfaces do not: it is hashed and externally published, so
its redaction must be **deterministic** to keep verification reproducible.

## Credential inventory

| Secret | Where it lives | Notes |
|---|---|---|
| Operator password | Argon2/bcrypt hash in DB; plaintext only in the login request body | Never stored or logged in plaintext |
| Operator JWT (access token) | Issued to the browser/session; `Authorization: Bearer` header | JWT-shaped |
| Agent bearer token | SHA-256 hash server-side; plaintext in agent `identity.json` | `secrets.token_urlsafe(32)` shape |
| Enrollment token | SHA-256 hash server-side; plaintext once in the enroll response and in agent `config.json` | One-time/limited-use |
| Command signing private key | PEM file on disk outside the DB (`COMMAND_SIGNING_KEY_PATH`) | Never in DB, API, or audit detail |
| Backup passphrase | Operator-supplied to backup/restore tooling | Never persisted by the app |
| Command stdout/stderr | `commands.stdout` / `commands.stderr` columns | Endpoint-side content; classified sensitive (below) |

Public, non-secret values that **must not** be redacted because accountability
and verification depend on them: agent IDs, command IDs, key **IDs**
(`signing_key_id`), command **public** keys, replay nonces, Merkle roots, event
hashes, envelope SHA-256 digests, actor emails, actions, timestamps, counts.

## Enforced boundaries

### Server — audit detail (`app/core/redaction.py`, issue #115)

`audit.record` runs every event's `detail` through `redact_detail` before it is
hashed and persisted. Redaction is deterministic and structure-preserving:

- **Key-based:** any value whose key contains a sensitive part
  (`password`, `passphrase`, `secret`, `token`, `authorization`, `bearer`,
  `credential`, `private_key`, `api_key`, `session_key`, `cookie`) is replaced
  with `[redacted]`, at any nesting depth and inside arrays.
- **Value-shape, narrow:** PEM private-key blocks and JWTs are redacted
  regardless of key (a private key or operator token that leaks in under an
  innocuous name is still caught).
- **Deliberately preserved:** hex and URL-safe-base64 blobs. Nonces share the
  bearer-token shape and Merkle roots/hashes are 64-hex; redacting by shape
  would erase accountability and break anchor verification.
- **Fail-closed structure:** `bytes` are never persisted, recursion is bounded
  (over-deep subtrees become `[redacted:too-deep]`), and a malformed
  (non-mapping) detail is wrapped under `_value` rather than trusted.

Because redaction happens before hashing, the stored (redacted) representation
is the only one ever hashed. Clean-room chain and anchor verification therefore
remain reproducible over the redacted form.

### Server — logs, diagnostics, API errors (issue #112)

- The server logs very little at runtime; there is no request/response body
  logging and no framework debug logging in production
  (`ENVIRONMENT=production` rejects `DEBUG=true`).
- `app/core/redaction.py` additionally exposes `scrub_text`, an
  intentionally aggressive free-text scrubber (bearer headers, `key=value`
  secrets, PEM blocks, JWTs) for any diagnostic or error string that folds in
  untrusted or secret-adjacent text. Over-redaction is acceptable here because
  no verification depends on the exact text.

### Server — command output classification (issue #112)

`commands.stdout` / `commands.stderr` are classified **sensitive** at the model
(`app/models/models.py`): captured output can contain endpoint secrets. It is
returned **only** through the role-gated command-detail endpoint, whose reads
are audited as `command_detail.viewed`, and it is **never** copied into
audit-event detail (`command.completed` records IDs, exit code, status,
truncation flags, and byte totals — not the output), a log line, or an error
message.

### Agent — logs and errors (`agent/internal/redact`, issue #112)

- The runner logs command **IDs**, kinds, and agent IDs — never payloads,
  output, or tokens. The bearer token lives only in the `Authorization` header
  and is never formatted into a log or error.
- Server error bodies are the one place untrusted text enters an agent error
  string. `client.go` now passes that text through `redact.Text` (same pattern
  set as the server scrubber) before constructing a `StatusError`.

### Installer — uninstall (`installer/NodeLinkAgent.iss`, issue #112)

`[UninstallDelete]` removes the credential-bearing files the agent creates at
runtime: `config.json` (plaintext enrollment token), `identity.json` (the
DPAPI-wrapped agent token — ciphertext, not plaintext, and still removed), and
`seen_commands.json`. On Windows the persisted identity is DPAPI-encrypted, so
no plaintext token copy survives uninstall. Operational logs under
`%ProgramData%\NodeLink\logs` are intentionally **retained** for post-uninstall
forensics; they are non-credential-bearing by the logging discipline above.

## Tests

| Surface | Test | What it proves |
|---|---|---|
| Audit detail | `server/tests/test_redaction.py` | key/value redaction across nesting, arrays, casing; PEM/JWT shapes; malformed/deep input; **accountable fields and nonces/roots preserved**; every producer shape cannot persist a sentinel; chain still verifies |
| Server free text | `server/tests/test_redaction.py::test_scrub_*` | bearer/kv/PEM/JWT scrubbed, ordinary text preserved |
| Agent | `agent/internal/redact/redact_test.go` | bearer, `key=value`, PEM, JWT scrubbed; command IDs/nonces/status preserved |
| Chain integrity | `server/tests/test_audit_sequence.py`, `test_anchoring.py`, `test_anchor_publish.py` | redaction did not break sequence, hash, or anchor verification |

All tests seed a fixed sentinel (`nlk-SENTINEL-SECRET-...`) and fail if it
appears where it must not.

## Residual limitations

- **Audit path is key-scoped, not universal shape-scoped.** A secret placed as a
  bare string under an *innocuous* key (and not shaped like a PEM/JWT) is
  preserved. This is a deliberate trade: shape-based redaction of high-entropy
  blobs would destroy nonces/roots and break verification. Producers are
  expected to key credential-bearing values with a recognizable name; the
  boundary is the backstop, not a licence to pass secrets under bland keys.
- **Free-text scrubbing is best-effort.** `scrub_text` / `redact.Text` catch
  known shapes; a novel secret format in a log line is not guaranteed caught.
  The primary control remains *not logging secrets in the first place*.
- **Retained logs.** Uninstall keeps operational logs by design; they are
  non-credential-bearing but are not scrubbed retroactively.
- **Non-Windows agent identity** is `0600` plaintext by declared scheme; the
  installer and DPAPI protection are Windows-only. Non-Windows builds are
  development artifacts, not a supported endpoint.

## Reproducing the evidence

```bash
# Server (audit detail + free-text scrubbing + chain integrity)
cd server && pytest tests/test_redaction.py tests/test_audit_sequence.py \
    tests/test_anchoring.py -q

# Agent (log/error scrubbing)
cd agent && go test ./internal/redact/ ./internal/client/
```
