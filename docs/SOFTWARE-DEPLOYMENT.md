# MSI / EXE software deployment

Issue #56 adds one typed command, `deploy_software`, that downloads an MSI or EXE
installer over HTTPS, verifies it, runs it under a bounded policy, and applies a
reboot decision. It uses the existing signed `command-v3` transport and durable
result path; it never accepts a script or falls back to shell execution.

## Contract

```json
{
  "url": "https://cdn.example.com/app-14.2.msi",
  "sha256": "<64 lowercase hex>",
  "installer_type": "msi",
  "arguments": ["/quiet", "TRANSFORMS=custom.mst"],
  "signer_thumbprint": "9A1B...40hex",
  "timeout_seconds": 1800,
  "success_exit_codes": [0, 3010],
  "reboot": { "policy": "if_required", "delay_seconds": 300, "requires_no_user": true }
}
```

- `url` must be **https** (1–2048 bytes, no control characters). The agent's
  downloader refuses any redirect that leaves HTTPS.
- `sha256` is **mandatory** — a lowercase SHA-256 of the exact installer bytes.
  A mismatch after download fails closed (`tampered`) and the installer never runs.
- `installer_type` is `msi` or `exe`.
- `arguments` (≤32, each ≤256 printable bytes) are passed as argv — installers
  run without a shell, so there is no quoting/injection surface. MSI always runs
  `msiexec /i <file> /qn /norestart <args>`; EXE runs `<file> <args>` (the
  operator supplies the silent switch).
- `signer_thumbprint` (optional, 40-hex) pins an Authenticode signer: the agent
  verifies the downloaded file has a **Valid** Authenticode signature whose signer
  certificate thumbprint matches, and fails closed otherwise.
- `timeout_seconds` (30–3600) bounds the install run; a timeout kills the process.
- `success_exit_codes` (optional, ≤32, 0–65535) overrides the default success set
  `{0}`. Reboot-required codes `1641`/`3010` are always treated as success.
- `reboot` (optional) reuses the #53 post-install reboot shape
  (`never`/`if_required`/`forced`, consent-aware); `delay_seconds` 60–3600.

## States and failure behavior

| Status | Meaning |
| --- | --- |
| `succeeded` | Installer exited with a success code. |
| `succeeded_reboot_required` | Success with a `1641`/`3010` reboot-required code. |
| `failed` | Installer exited with a non-success code (mapped, command exit 1). |
| `tampered` | Downloaded bytes did not match `sha256`; installer not run. |
| `signature_mismatch` | Authenticode signer did not match `signer_thumbprint`. |
| `signature_unavailable` | Authenticode verification could not be performed. |
| `download_failed` | Transfer error, non-200, or the byte cap was exceeded. |
| `run_failed` | The installer process could not run or timed out. |
| `invalid` | Payload malformed / out of bounds (also rejected `422` at the API). |
| `unsupported` | Non-Windows agent. |

The installer is downloaded to a bounded (≤1 GiB) temp file that is always removed
after the run. Integrity is fail-closed: digest first, optional signer second, and
only then execution.

## Rollback metadata

For a successful MSI, the result includes the `product_code`, giving an operator
the value needed to uninstall later (`msiexec /x {ProductCode}`). The result also
carries the artifact `sha256`, `exit_code`, and reboot decision. This evidence
rides the durable, admin-only command-detail view; there is no separate table.

## Authorization

`deploy_software` is **administrator-only** — it runs arbitrary vendor code on the
endpoint, the broadest trust boundary in the operations plane. It also requires
the `software-deployment-v1` capability; dispatch to an agent that has not
advertised it fails closed with `409 agent_capability_unsupported`.

## Audit and evidence

`software_deployment.dispatched` records `installer_type`, the artifact `sha256`,
the source `url_sha256` (the URL is prose and never stored in the clear),
`argument_count`, `timeout_seconds`, `signer_pinned`, `success_code_override`, and
`reboot_policy`. See [`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Compatibility, migration, and rollback

- **No schema change.** The command and its result (including rollback metadata)
  ride the existing signed `Command` model — no Alembic revision.
- **Mixed-version fleets are safe.** The kind is gated by `software-deployment-v1`;
  an older agent never advertises it, so the server refuses dispatch, and the
  agent also rejects the kind at signature/kind validation.
- **Rollback** for a deployed MSI is an operator uninstall via the recorded
  `product_code`; there is no automatic uninstall in v1.

## Platform support

Windows x64 only. MSI installs run through `msiexec`; Authenticode verification
uses `Get-AuthenticodeSignature`; MSI `ProductCode` is read via the
WindowsInstaller COM object. Non-Windows agents report `unsupported`.

## Deferred

- Dashboard UI for deployment dispatch and results.
- Server-hosted artifact storage (v1 downloads from an operator-provided HTTPS
  source with a mandatory digest).
- Automatic uninstall/rollback execution and per-source allowlist policy.
