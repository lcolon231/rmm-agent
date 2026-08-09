# Controlled file transfer and registry remediation

Issue #59 adds administrator-only, signed, typed Windows remediation without
turning file or registry input into shell text. The feature uses the ordinary
polling command pipeline, replay journal, result outbox, command history, and
tamper-evident audit chain. It does not add a second endpoint transport.

## Support and compatibility

The agent advertises `file-transfer-v1` and `registry-operations-v1` at
enrollment and on every heartbeat. The server refuses a remediation dispatch
with `409 agent_capability_unsupported` unless the target advertises the
required capability. Rollback requires both capabilities because a backup ID
does not reveal its resource class to the server. This makes an old agent an
explicit unsupported state; there is no script or legacy-command fallback.

These command kinds are added to command-v2 and command-v3:

| Kind | Required capability | Purpose |
| --- | --- | --- |
| `file_upload` | `file-transfer-v1` | Atomic digest-verified write |
| `file_download` | `file-transfer-v1` | Bounded read with digest evidence |
| `registry_read` | `registry-operations-v1` | Typed value read |
| `registry_write` | `registry-operations-v1` | Typed value write with backup |
| `registry_delete` | `registry-operations-v1` | Confirmed value delete with backup |
| `remediation_rollback` | both | Restore an endpoint-local backup ID |

The command payload remains limited by the signed-envelope contract. There is
no separate schema table: revision `0030` only adds PostgreSQL `commandkind`
enum values; SQLite stores the existing enum strings. No backfill is needed.

## Authorization and audit evidence

Only an authenticated `admin` may dispatch these kinds. `operator` and
`readonly` fail before signing or queueing, and the allow/deny decision is
recorded with policy `privileged_remediation`. Endpoint quarantine/revocation,
queue admission, signed-envelope negotiation, expiry, and replay rules still
apply.

Permanent audit detail contains the command kind, payload key names, signed
envelope hash/times/key ID, actor, completion state, byte totals, and
truncation flags. It never contains a path, file bytes, registry key/value
name, registry data, or downloaded content. Those values exist in the
authorized command record/result and the endpoint-local rollback journal.
Command-detail reads remain separately audited. Because remediation payloads
and results may contain file or registry content, their detail endpoint is
also administrator-only; a lower-role attempt returns 403 and records
`command_detail.access_denied`. History metadata remains readable by the
ordinary command-history roles.

## File contract and policy

File paths must be absolute drive paths under exactly one of:

- `C:\ProgramData\NodeLink\Managed`
- `C:\Windows\Temp\NodeLink`

The server and agent reject relative paths, `..`, UNC paths, `\\?\` and
`\\.\` device paths, alternate data streams, NUL/control characters, and
paths outside those roots. Before access, the Windows agent walks existing
components and rejects any reparse point (including symlinks and junctions).

`file_upload` requires `path`, canonical `content_base64`, lowercase `sha256`,
and explicit `overwrite`. Content is limited to 32 KiB. Both sides verify the
digest. The agent captures an existing regular file (at most 1 MiB) into its
local rollback journal, writes a same-directory temporary file, flushes it,
and commits with a write-through atomic move. An overwrite is refused if the
prior file cannot be backed up. Success returns size, digest, and `backup_id`.

`file_download` requires `path` and accepts optional `expected_sha256`. It
reads at most 64 KiB and returns base64 content, exact byte size, and SHA-256.
A size or expected-digest mismatch fails without returning partial content.
Neither operation retries a side effect: the ordinary command ID/nonce replay
journal guarantees at-most-once execution, while the durable result outbox
retries only delivery of the exact retained result.

## Registry contract and policy

Registry operations allow only `HKLM` and `HKCU`, only 32-bit or 64-bit view,
and only the `Software\NodeLink\Managed` subtree. They address exactly one
value (the empty string is the default value name). Key traversal, protected
system subtrees, path separators in value names, unknown fields, unsupported
views, and unsupported native types fail closed.

Supported types are `string`, `expand_string`, `dword`, `qword`,
`multi_string`, and `binary`. Strings and binary values are bounded to 16 KiB;
multi-string input is capped at 256 entries; integer ranges are checked.
Binary data is canonical base64. Reads return the typed value and a SHA-256 of
canonical `{type,data}` JSON. Writes and deletes accept optional
`expected_current_sha256` for compare-and-set/delete. Deletes additionally
require `confirm: true`.

Before a write or delete, the agent captures existence, type, and value in an
endpoint-local journal under `C:\ProgramData\NodeLink\Rollback`, then returns
its opaque 32-hex-character ID. If journal persistence fails after mutation,
the agent immediately restores the captured state and reports failure.

## Rollback and recovery

`remediation_rollback` accepts only `{"backup_id":"<32 lowercase hex>"}`.
The agent loads that exact local journal record, revalidates the recorded path
or registry policy, verifies backed-up file content by digest, and restores the
old value/file atomically. If the resource did not exist before the mutation,
rollback removes the newly created resource/value. Journal records are kept so
a repeated, separately authorized rollback is deterministic.

Operational recovery:

1. Stop further dispatches to the endpoint and preserve the failed command ID.
2. Read its authorized command detail and copy the returned `backup_id`.
3. Dispatch `remediation_rollback` to the same endpoint.
4. Verify the rollback command succeeds, then issue a read/download with the
   expected digest. Preserve both command IDs and their audit event IDs.

The database migration is forward-only. Rolling the server back across `0030`
requires the normal exact-revision database restore or a forward fix. During a
mixed rollout, deploy the server first, then canary agents; capability gating
keeps old agents unavailable rather than unsafe. Removing the new dashboard
alone does not disable the API, so pause dispatch through access controls when
responding to an incident.

## Reproducible verification

- Server validation, authorization, capability, traversal/device, tamper,
  oversize, hive/view/type/protected-key, delete-confirmation, and rollback-ID
  tests: `server/tests/test_controlled_remediation.py`.
- Agent lexical path abuse tests: `agent/internal/remediation/policy_test.go`.
- Windows reparse-point test and Windows compilation:
  `agent/internal/remediation/reparse_windows_test.go` and Windows CI.
- Dashboard validation and role visibility:
  `dashboard/test/command-console-core.test.ts`.
- Migration head/forward-only verification: `server/tests/test_migrations.py`.

Real Windows qualification must additionally exercise file upload/download,
all registry types in both views, local rollback after write/delete, service
restart before result delivery, and denial through a real junction. Passing
portable tests is not a substitute for that Windows evidence.
