# Accessible PDF and signed evidence packages (issue #80)

Status: **implemented server side and verified by automated tests.** NodeLink
renders the version-1 tenant evidence document from issue #79 as a tagged PDF
summary or a deterministic, domain-separated Ed25519-signed ZIP. This is a
compliance-supporting export, not a certification or a claim that a report is
complete for a particular legal or regulatory purpose.

## API contract

`GET /api/v1/evidence/bundles/export` retains the issue #79 authentication,
single-tenant authorization, sequence bounds, record limit, anti-oracle 404,
and `no-store` behavior. Two additional encodings are supported:

- `format=pdf` returns `application/pdf`; and
- `format=zip` returns `application/zip` and the
  `X-NodeLink-Evidence-Package-ID` header.

The response always carries the logical bundle ID and resolved audit sequence.
Every successful export emits `evidence_bundle.exported`. The event records the
encoding and response digest; signed packages also record the package ID and
signing-key ID. Payload values, output content, and private keys never enter the
response, audit event, filename, error, or log.

Use the returned `X-NodeLink-Audit-Through-Seq` as `through_seq` to reproduce
byte-identical PDF and ZIP output while the current tenant inventory and policy
rows remain unchanged; ZIP reproduction also requires the same active signing
key. Ed25519 signatures are deterministic, and the ZIP has a fixed entry order,
timestamp, permissions, encoding, and stored method.

## PDF accessibility contract

The direct PDF is a human-readable summary of the logical evidence document.
It contains:

- document title, language, and display-title metadata;
- a structure tree, marked content, logical `H1`/`H2`/paragraph tags, and
  screen-reader `ActualText` values;
- tenant and sequence scope, bundle ID, verification state, section counts,
  redaction treatment, and independent-verification guidance; and
- deterministic pagination with page-number artifacts outside the reading
  order.

The renderer intentionally avoids raw action payloads, stdout/stderr, policy
free text, and other record-level sensitive content. The tagged summary is
designed for keyboard/screen-reader workflows but does not claim PDF/UA
certification. The standalone PDF is not signed; use the ZIP when authenticity
is required because its manifest binds the exact PDF bytes.

## Signed ZIP version 1

The normative manifest schema is
[`contracts/evidence-package-v1.schema.json`](../contracts/evidence-package-v1.schema.json),
with a golden logical vector at
[`contracts/test-vectors/evidence-package-v1.json`](../contracts/test-vectors/evidence-package-v1.json).
The archive has exactly seven regular files in this order:

| Path | Purpose |
|---|---|
| `package-manifest.json` | Canonical package scope, member ledger, signing metadata, and package ID. |
| `signature.json` | Canonical Ed25519 signature record for the manifest. |
| `evidence/evidence.json` | Canonical issue #79 logical evidence document. |
| `reports/evidence-summary.pdf` | Tagged human-readable summary. |
| `receipts/anchor-receipts.json` | Canonical copy of the exact anchor/receipt evidence. |
| `keys/evidence-signing-key.pem` | Public key that verifies package integrity; not self-authenticating. |
| `VERIFY.txt` | Independent verification command and trust warning. |

The manifest lists each of the five content members by fixed path, media type,
byte size, and SHA-256. `package_id` is SHA-256 over the canonical manifest
without that field. `signature.json` binds the manifest hash and the hash of the
actual signed payload.

The active issue #14 Ed25519 key signs:

```text
nodelink-evidence-package:v1:<canonical package-manifest.json bytes>
```

The context prevents an evidence-package signature from being interpreted as a
command or agent-update signature. Active/overlap/retired key IDs and rotation
continue to use the existing operator-run keyring. Build fails closed when the
active private/public pair is missing or mismatched.

## Independent trust and verification

The public key copied into the archive proves only self-contained consistency.
It is not a trust anchor: an attacker could otherwise replace the archive, key,
and signature together. Obtain the deployment public key through a separately
authenticated channel and run:

```powershell
python server/scripts/verify_evidence_package.py evidence.zip `
  --trusted-public-key trusted-evidence-public.pem
```

The reference verifier imports no NodeLink application or database code. It
uses Python's standard ZIP/JSON libraries, the pinned `cryptography` dependency
for Ed25519, and the issue #79 clean-room verifier. It checks:

- exact member count, safe fixed paths/order, no duplicates, traversal,
  symlinks, encryption, compression, comments, or noncanonical metadata;
- per-member and total size limits before reading content;
- canonical manifest/signature/evidence/receipt JSON and all member digests;
- package ID, signing context, signature, included key fingerprint, and an
  exact match to the externally trusted key;
- evidence section digests, audit hashes/links, Merkle root, and receipt
  digests; and
- PDF accessibility/identity markers and cross-reference pointer.

Success establishes that the separately trusted key signed the manifest and
the manifest binds the included evidence. It does not contact or attest to the
continued availability of an external WORM destination.

## Bounds and failure behavior

The logical record limit remains 10,000 by default and 50,000 maximum. A PDF is
limited to 2 MiB. ZIPs are stored rather than compressed to remove
decompression-bomb ambiguity. A package is limited to seven entries, 48 MiB
per member, and 64 MiB total. It is refused, never silently truncated.

In addition to the issue #79 errors:

| HTTP | Code/state | Meaning |
|---|---|---|
| `413` | `evidence_package_size_exceeded` / `limit_exceeded` | A member or completed archive exceeds its bound. |
| `422` | request validation | The requested encoding is not `json`, `csv`, `pdf`, or `zip`. |
| `500` | `evidence_pdf_render_failed` / `invalid` | The bounded PDF renderer or its structural self-check failed. No bytes are returned. |
| `503` | `evidence_package_signing_unavailable` / `unavailable` | The active Ed25519 private/public pair cannot be loaded or does not match. |
| `500` | `evidence_package_verification_failed` / `invalid` | The server's final self-verification rejected the generated package. No bytes are returned. |

Malformed archives and incorrect trust keys make the reference verifier exit
nonzero with a bounded failure reason. It never extracts files to disk.

## Compatibility, rollout, and recovery

- No database migration, agent change, dashboard change, polling change, or
  persisted export row is required. JSON/CSV clients are unchanged.
- Rollout is a server deploy. Rollback removes PDF/ZIP encoding support; prior
  signed packages remain independently verifiable.
- Rotate or recover the evidence signing key through the existing issue #14
  keyring runbook. Keep retired public keys available through a trusted archive
  so historical packages remain verifiable.
- An unavailable private key affects ZIP only when its public-key registry entry
  remains readable. Loss of the public keyring also blocks JSON, CSV, and PDF
  because their verification-key evidence would be incomplete.
- Issue #81 adds immutable package storage, retention, and legal hold. Issue #82
  packages the verifier as a supported cross-platform product. Neither is
  implied by this computed-download implementation.

## Verification evidence

`server/tests/test_evidence_bundles.py` covers PDF content/accessibility and
pinned bytes, manifest/schema vectors, exact archive completeness, deterministic
signatures, payload/signature tamper, traversal, incorrect trusted keys,
unavailable signing, size refusal, a 2,500-record package, audited download, and
clean-room subprocess verification.
