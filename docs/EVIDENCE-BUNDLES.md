# Deterministic tenant evidence bundles (issue #79)

Status: **implemented server side and verified by automated tests.** NodeLink
exports one tenant at a time as canonical JSON or normalized CSV through a
versioned manifest. Issue #80 also renders that same document as a tagged PDF
or deterministic signed ZIP. This is a compliance-supporting evidence capability; it is
not a compliance certification or a claim that an export is complete for a
customer's particular legal or regulatory purpose.

## API and authorization contract

`GET /api/v1/evidence/bundles/export` requires an authenticated operator with
the global `readonly` role or higher and a visible tenant under the issue #66
membership boundary. Required query parameter:

- `organization_id`: the `Client`/tenant to export.

Optional parameters:

- `format=json|csv|pdf|zip` (default `json`); PDF/ZIP packaging is specified in
  [`EVIDENCE-PACKAGES.md`](EVIDENCE-PACKAGES.md);
- `from_seq` (default `1`), the first tenant audit sequence included;
- `through_seq`, the pinned global audit prefix. When omitted, NodeLink resolves
  the current tail before appending the download event; and
- `record_limit` (default `10000`, maximum `50000`), covering the total logical
  records in the artifact.

A foreign or nonexistent tenant is always `404`, preserving the anti-oracle
boundary. Readonly membership is sufficient because export is a read; the
download is still audited as `evidence_bundle.exported` with the tenant,
manifest ID, sequence bounds, record count, encoding, and response SHA-256.

Example:

```text
GET /api/v1/evidence/bundles/export?organization_id=<tenant-id>&format=json
```

The response is `no-store`, has a content-addressed filename and ETag, and
returns the resolved snapshot in `X-NodeLink-Audit-Through-Seq`. Repeat the
request with that value to reproduce byte-identical output while the current
tenant inventory/policy rows remain unchanged.

## Version 1 logical document

The normative JSON Schema is
[`contracts/evidence-bundle-v1.schema.json`](../contracts/evidence-bundle-v1.schema.json)
and the golden vector is
[`contracts/test-vectors/evidence-bundle-v1.json`](../contracts/test-vectors/evidence-bundle-v1.json).
The format identifier is `nodelink-evidence-bundle`, version `1`.

The manifest contains:

- a single-tenant scope and audit sequence bounds;
- the terminal event hash/time for the pinned prefix;
- each section's record count and SHA-256 over its canonical ordered JSON array;
- explicit audit-chain, anchor/publication, command-key, and redaction states;
  and
- `bundle_id`, the SHA-256 of the canonical manifest without that field. The ID
  therefore binds every section digest and all verification metadata.

Ordered sections are:

1. `tenant` — the selected client identity;
2. `actors` — current tenant members plus historical/system identities observed
   in selected evidence;
3. `sites` and `endpoints` — safe identity, state, version, capability, and
   credential-lifetime metadata, never bearer hashes or raw inventory;
4. `policies` — every applicable global/client/site/agent monitoring and patch
   revision, with credential-shaped values redacted and free-form change notes
   represented only by digest and byte count;
5. `signed_actions` — command identity, provenance, envelope version, nonce,
   signature, key ID, and stored envelope digest; payload values are withheld;
6. `results` — lifecycle, exit code, bounds, byte counts, and truncation state;
   stdout/stderr content and content digests are withheld;
7. `audit_events` — the exact already-sanitized stored representation for the
   tenant, including hash schema, sequence, previous hash, and event hash;
8. `audit_hashes` — only `(seq, event_id, event_hash)` for the complete global
   prefix, allowing a tenant verifier to reproduce a global Merkle anchor
   without receiving another tenant's actors, actions, or details;
9. `anchors` — the newest applicable verified anchor and public publication
   receipts; and
10. `verification_keys` — public command-signing keys and lifecycle state.

Audit selection includes events explicitly anchored to the tenant and legacy or
system-produced events whose `agent_id` resolves to one of the tenant's
endpoints. Other-tenant details never enter the artifact.

## Canonical encodings

JSON is UTF-8 with recursively sorted object keys, no insignificant whitespace,
no ASCII-only escaping, no NaN/Infinity, and no trailing newline. CSV is a
long-form projection with the fixed header:

```text
section,ordinal,record_sha256,record_json
```

The first row is the manifest. Subsequent rows follow the manifest's section
order and use one-based contiguous ordinals. `record_json` is the exact
canonical JSON object and `record_sha256` binds it. Reconstructing the arrays
produces the same logical document and `bundle_id` as JSON.

## Verification and failure states

`server/scripts/verify_evidence_bundle.py` is a standard-library reference
verifier requiring no NodeLink database or application imports. It verifies
canonical encoding, section digests/counts, the manifest ID, selected audit
event hashes/links, the complete hash prefix, the Merkle root, and publication
receipt digests for JSON and CSV.

```powershell
python server/scripts/verify_evidence_bundle.py bundle.json
python server/scripts/verify_evidence_bundle.py bundle.csv
```

The exporter fails closed with stable states:

| HTTP | Code | Meaning |
|---|---|---|
| `401` | authentication required | No valid operator bearer token was supplied. |
| `403` | insufficient role | The operator lacks the global readonly role. |
| `404` | tenant not found | Tenant is absent or not visible to the caller. |
| `409` | `evidence_snapshot_unavailable` | `through_seq` is beyond the current chain. |
| `409` | `audit_chain_not_intact` | A covered event/link/hash is inconsistent. |
| `409` | `audit_anchor_not_intact` | The newest applicable anchor does not reproduce. |
| `409` | `anchor_receipt_not_intact` | A stored external receipt digest differs. |
| `413` | `evidence_record_limit_exceeded` | The complete artifact exceeds the requested bound; it is never silently truncated. |
| `422` | `evidence_sequence_range_invalid` | The requested sequence range is impossible. |
| `422` | request validation | The encoding is unsupported or a query bound is malformed/out of range. |
| `503` | `evidence_signing_keys_unavailable` | Public verification key material cannot be read. |

No anchor is a supported but prominent `unavailable` verification state; the
artifact remains internally hash-verifiable but does not claim external
immutability. Missing historical command keys are reported as `incomplete`.
Command payloads remain withheld, so v1 reports command signature evidence as
metadata-only rather than falsely claiming offline signature verification.

## Resource bounds, compatibility, and operations

- Exports are synchronous and bounded to 50,000 logical records. A complete
  global hash prefix is included, so deployments beyond that bound must use a
  future streaming/multiproof format rather than weakening completeness.
- No pagination or retry token is needed: `through_seq` is the idempotency and
  reproducibility key. A client retries the same pinned request.
- Version 1 is additive and needs no agent change, protocol change, or database
  migration. It reads the issue #50 task provenance, issue #66 tenant anchors,
  and issue #76 publication receipts already present.
- Rollout is an application deploy. Rollback removes the route; no data rollback
  is required. Previously downloaded artifacts remain independently verifiable.
- Monitoring should alert on repeated `409`, `413`, or `503` responses and on
  anchor publication lag; export audit events provide the operator trail.

## Verified scope and follow-ups

`server/tests/test_evidence_bundles.py` covers schema/golden vector stability,
canonical ordering, pinned reproducibility, a 2,500-record artifact, central
redaction, cross-tenant denial, limit/unavailable states, chain/anchor tamper,
JSON/CSV reconstruction, and clean-room verification.

Issue #80 implements tagged PDF and deterministic signed-ZIP packaging over
this document. Issue #81 adds immutable bundle storage, retention, and legal
hold. Issue #82 packages a standalone cross-platform verification product.
Those persistence and productized-CLI capabilities are not implied by this
computed export.
