# Moderated community script repository (issue #74)

This document is the contract for signed community script packages: how a
publisher's script reaches an endpoint, what is verified where, every state and
refusal, and how operators recover. It is server- and dashboard-side only; the
agent and the signed command envelope are unchanged.

## Scope and non-goals

In scope: an **in-deployment** catalog. Publishers sign packages offline with
Ed25519 keys an admin registered for their namespace, upload signed
submissions to this server, a second admin moderates them, and an admin
installs an approved version into the local [script library](SCRIPT-LIBRARY.md).

Not implemented (do not cite this document as evidence for them):

- No remote feed or federation. The server never fetches packages from the
  network, so there is no SSRF or egress surface.
- No agent-side sandbox. Capabilities are declared, moderated, and enforced at
  dispatch (interpreter, platform, exact content). The script's internal
  behaviour is not confined; moderation is accountable review, not semantic
  analysis.
- No package dependencies. A package is one script. "Dependency confusion" is
  addressed as namespace/name confusion (below).
- No tenant-scoped catalogs. Like the script library, the repository is
  deployment-wide and governed by operator roles; execution remains tenant- and
  scope-checked at dispatch.

## Trust chain

```
admin registers publisher slug ──► admin registers Ed25519 public key (bound to that slug forever)
publisher (offline) builds manifest + content ──► signs canonical manifest bytes
operator submits {manifest, content, key_id, signature}
   server: manifest shape, capability rules, content digest, key ∈ manifest.publisher, key+publisher active, signature
second admin moderates (≠ submitter) ── re-verifies signature + key state; acknowledges capability escalation
admin installs approved version ── re-verifies everything; must accept the exact capability set
   ⇒ new script_library_items row + script_versions row (community_package_version_id set) + approved review
dispatch / scheduler ── re-checks trust state, kind, agent platform, and exact content digest on EVERY run
```

## Signed manifest (`nodelink.community-package/v1`)

Exactly these keys; any extra or missing key is `manifest_invalid`:

| Field | Rule |
|---|---|
| `schema` | `nodelink.community-package/v1` |
| `publisher`, `name` | slug `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$` |
| `version` | strict `MAJOR.MINOR.PATCH`, no leading zeros, each ≤ 6 digits |
| `language` | `powershell` or `shell` |
| `content_sha256`, `content_bytes` | SHA-256 and byte length of the UTF-8 canonical content |
| `description` | string ≤ 2000 or `null` |
| `tags` | script-library tag rules, already normalized (lowercase, unique, sorted) |
| `supported_platforms` | non-empty, unique, sorted subset of `windows`, `linux`, `macos` |
| `capabilities` | sorted, unique, allowlisted (below) |
| `parameters` | script-library parameter definitions (`ScriptParameterInput`) |

Content must already be canonical (LF line endings, no outer whitespace, no
control/bidi characters, ≤ 57,344 bytes and 5,000 lines); otherwise
`content_not_canonical`. Manifests are bounded to 64 KiB.

**Canonical bytes** are `b"nodelink-community-package:v1\n"` followed by
`json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False)` in UTF-8. The signature is a base64 Ed25519 signature
(64 bytes) over those bytes. `server/scripts/sign_community_package.py`
(`keygen`, `sign`) produces submissions; a test pins its encoding byte-for-byte
to `app.core.community_packages.canonical_manifest_bytes`.

### Capabilities

| Capability | Meaning / enforcement |
|---|---|
| `script.run.powershell`, `script.run.shell` | exactly one, must match `language`; dispatch kind must match |
| `platform.windows`, `platform.linux`, `platform.macos` | must equal `supported_platforms`; dispatch refuses agents on other platforms |
| `requires.elevation`, `network.egress`, `filesystem.write`, `registry.write`, `service.control` | declared side effects; moderated and acknowledged, shown to installers |

**Escalation.** For a moderation approval, the escalation set is the version's
capabilities minus those of the newest approved, unrevoked, older version. For
a first approval it is every declared side-effect capability. A non-empty set
requires `acknowledge_capability_escalation: true`, otherwise
`409 capability_escalation_unacknowledged` (with the list). Installs, updates,
and rollbacks must send `accepted_capabilities` equal to the declared set, so a
stale screen can never silently accept an escalation.

## States

- Publisher: `active` → `revoked` (terminal, idempotent by `request_id`).
- Publisher key: `active` → `revoked` (terminal). A key fingerprint is unique
  across all publishers and a key ID is never reused within a publisher, so old
  signatures can never be re-attributed.
- Package version, as reported by the API (`state`), in precedence order:
  `blocked` (its key or publisher is revoked) > `revoked` (version revoked) >
  moderation outcome `approved` / `rejected` > `submitted`.
- Versions are immutable. Re-sending an identical signed submission is
  idempotent; reusing a version number with different bytes is
  `package_version_exists`; a version not greater than every existing one is
  `package_version_not_monotonic`.

## API (`/api/v1/community`)

| Method / path | Role | Notes |
|---|---|---|
| `GET /publishers`, `GET /packages`, `GET /packages/{id}`, `GET /packages/{id}/versions/{v}`, `GET /installs` | readonly | version detail includes manifest, signature, content; catalog and detail reads are audited |
| `POST /publishers` | admin | `{slug, display_name}` |
| `POST /publishers/{id}/keys` | admin | `{key_id, public_key_pem}` (PEM Ed25519 only) |
| `POST /publishers/{id}/keys/{key_id}/revoke`, `POST /publishers/{id}/revoke` | admin | `{request_id, reason}` |
| `POST /submissions` | operator | `{manifest, content, key_id, signature}` |
| `POST /packages/{id}/versions/{v}/moderation` | admin, ≠ submitter | `{state, reason, acknowledge_capability_escalation}` |
| `POST /packages/{id}/versions/{v}/revoke` | admin | `{request_id, reason}` |
| `POST /installs` | admin | `{package_id, version, accepted_capabilities, request_id, library_name?}` |
| `POST /installs/{id}/update`, `POST /installs/{id}/rollback` | admin | `{version, accepted_capabilities, request_id}` |

Errors are `{"detail": {"code": ...}}`. Validation errors are 422, missing
resources 404, role failures 403, state conflicts 409.

| Code | When |
|---|---|
| `signature_invalid` | signature does not verify (submission 422; moderation/install/dispatch re-verification 409) |
| `content_digest_mismatch`, `content_not_canonical`, `manifest_invalid` | content/manifest binding or shape |
| `capability_unknown`, `capability_language_mismatch`, `capability_platform_mismatch` | capability rules |
| `publisher_unknown`, `publisher_key_unknown`, `manifest_publisher_mismatch` | unregistered namespace/key, or a key registered to a different namespace |
| `publisher_revoked`, `publisher_key_revoked` | revoked signer at submission/key registration |
| `publisher_key_invalid`, `publisher_key_exists`, `publisher_slug_exists` | registration |
| `package_version_exists`, `package_version_not_monotonic` | immutability |
| `moderation_self_review_forbidden` (403), `moderation_already_final`, `capability_escalation_unacknowledged` | moderation |
| `package_version_not_approved`, `package_version_revoked`, `community_package_blocked` | install/update/rollback of an untrusted version |
| `install_capabilities_mismatch`, `library_name_shadowed`, `package_already_installed`, `install_request_conflict` | install |
| `install_downgrade_requires_rollback`, `install_rollback_requires_older_version` | update/rollback direction |
| `community_package_blocked`, `community_capability_denied`, `community_content_mismatch` | dispatch, scheduled run, schedule creation |
| `community_*_limit_reached`, `publisher_key_limit_reached`, `package_version_limit_reached` | resource bounds |

Resource bounds (settings): `COMMUNITY_MAX_PUBLISHERS` (200),
`COMMUNITY_MAX_KEYS_PER_PUBLISHER` (5), `COMMUNITY_MAX_PACKAGES` (2,000),
`COMMUNITY_MAX_VERSIONS_PER_PACKAGE` (100), plus the script-library item and
version limits for installs.

## Install, update, rollback

An install creates a new library item named `publisher/name` (or
`library_name`). It never adopts an existing local script: if any local item
already has that name, the install fails with `library_name_shadowed`. One
package has at most one install. The installed `script_versions` row records
`community_package_version_id` and receives an approved
`script_version_reviews` row whose reason digest names the moderation decision.

Update moves to a strictly newer approved version. Rollback moves to a strictly
older approved, unrevoked, unblocked version. Both append a new library version
(the library stays append-only), so the run history shows exactly which bytes
ran when. Each transition is idempotent by `request_id`.

## Dispatch enforcement

`POST /agents/{id}/commands` with a `script_version_id` that has community
provenance, a scheduled run of such a version, and the creation of such a
schedule all call `core/community_packages.check_dispatch`/`check_run_definition`:

1. the package version is `approved` (not revoked, not blocked) and its stored
   manifest still verifies under the stored key, with content digest intact;
2. the command kind matches the declared `script.run.*`;
3. the agent's reported OS maps to a declared `platform.*` (dispatch and
   scheduler only; an unrecognized OS is refused);
4. `payload.script` hashes to the signed `content_sha256`.

A refusal is audited as `community.dispatch_refused` (`source` = `dispatch` or
`scheduler`) and returned as `409` with the code; the scheduler skips that
agent for the tick. Revocation therefore takes effect on the next run, not only
the next install. All ordinary command authorization (role, script execution
scope, tenant, approvals) still applies unchanged.

## Audit evidence

Every mutation and refusal is audited (`community.*`, see
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md)). Script content, signatures, and
moderator/revocation reasons are never stored in audit detail; reasons are
SHA-256 + byte count. Refused submissions are committed despite the refusal
and store only digests of the unauthenticated publisher/name/version claims.

## Schema, compatibility, rollout

Revision `0050` is additive: six new tables and a nullable
`script_versions.community_package_version_id`. Older binaries never read them;
existing library versions have `NULL` provenance and are unaffected by every
check above. No agent upgrade is needed and mixed agent versions are fine,
because the command envelope does not change. The dashboard page `/community`
is additive.

## Operations and recovery

- **Onboard a publisher:** admin registers the slug, then the publisher's
  `.pub` from `sign_community_package.py keygen`. Verify the fingerprint
  out of band before registering it.
- **Key compromise:** revoke the key (`/keys/{key_id}/revoke`). Every version it
  signed reads `blocked` and stops dispatching immediately; register a new key,
  and have the publisher re-sign and submit a new version number.
- **Malicious or broken version:** revoke the version; dispatch stops. Roll the
  install back to a previous approved version (appends a library version), or
  deprecate the library item.
- **Publisher compromise:** revoke the publisher; all of its packages block.
- **Schema rollback:** migrations are forward-only. Back out the capability by
  revoking publishers/versions; crossing below `0050` requires the
  exact-revision restore in [`ROLLBACK.md`](ROLLBACK.md).

## Verification

`server/tests/test_community_packages.py` covers tampered content and manifests,
forged and cross-namespace signatures, non-Ed25519 keys, revoked keys and
publishers (submission, install, dispatch), capability escalation and exact
acceptance, dispatch kind/platform/content refusals, dependency/name confusion,
moderation separation of duties and finality, immutability and monotonic
versions, update/rollback, idempotency, scheduler enforcement, the role matrix,
and digest-only audit evidence. `server/tests/test_migrations.py` covers
`0050`. Dashboard parsers, BFF handlers, and the view are covered by
`dashboard/test/community-packages.test.ts` and
`dashboard/test/ui/community-repository-view.test.tsx`.
