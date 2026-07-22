# Release rollback runbook

This runbook is for a bad NodeLink release. It is deliberately conservative:
automatic rollout must be paused first, database migrations are forward-only,
and a schema rollback is a restore with an explicit data-loss decision. The
compatibility planner records the decision but never changes a deployment.

## Release compatibility record

Before every production-intended tag, copy this table into the release notes
and fill it with immutable identifiers. Do not use `latest` or a mutable branch.

| Component | Release being deployed | Last known good rollback target N |
|---|---|---|
| Server | Git tag and commit | Git tag and commit |
| Agent | Version plus all artifact SHA-256 digests | Version plus all artifact SHA-256 digests |
| Windows installer | Filename plus SHA-256 digest | Filename plus SHA-256 digest |
| Database | Alembic head(s) | Alembic head(s) and matching backup manifest |
| Protocol | Command-envelope versions | Command-envelope versions |

At this revision, the server requires Alembic `0008` and agents use
`command-v3` (with `command-v2` only for a staged mixed-version rollout). The
existing public `v0.1.0` and `v0.1.1` tags predate Alembic and are **not** a
supported server/database rollback target for a database created by current
`main`. The first production-intended release must establish N by retaining its
filled compatibility record, artifacts, checksums, and a verified backup.

## Non-reversible migration policy

NodeLink Alembic revisions are forward-only. Never run `alembic downgrade` and
never edit `alembic_version` to make an old server start. Choose one of:

1. **Forward fix:** preferred when a safe fix can keep the current schema.
2. **Component redeploy:** allowed when the current database revision exactly
   matches N's required revision.
3. **Restore N:** required when the current schema differs from N. Restore the
   matching N backup and explicitly accept loss of every write after its
   timestamp. Preserve a separate backup of the failed N+1 state first.

If no verified backup exactly matches the target server revision, schema
rollback is blocked. Continue with a forward fix.

## Procedure

### 1. Stop reapplication and freeze writes

1. Declare the incident, start an append-only incident record, and name the
   decision maker.
2. Disable the external software-deployment policy, RMM job, package feed, or
   other automation that installed N+1. Remove N+1 from its rollout channel.
   NodeLink currently has no built-in self-updater, so external deployment is
   the only automatic reapplication path; record the control and screenshot or
   log proving it is paused.
3. Pin server deployment automation to a specific ref and disable automatic
   promotion from `main`.
4. Stop the NodeLink server and other database writers. Do not stop PostgreSQL
   until the evidence backup finishes.

### 2. Preserve the failed state

Record UTC times, current server commit, agent/installer versions, artifact
digests, current schema revision, deployment logs, release workflow URL,
operator actions, and the last externally published audit anchor and receipt.
Take a new encrypted backup of the failed N+1 database into an incident-only
location before restoring N. Do not overwrite the known-good N backup.

Copy the N and N+1 manifests, encrypted artifacts, verification JSON, external
anchor artifacts/receipts, and relevant logs to immutable incident storage.
These records may contain operational metadata; apply the incident retention
and access policy.

### 3. Make and record the compatibility decision

Read the live revision and N's revision from its retained backup manifest, then
run the planner with the exact compatibility record values:

```bash
CURRENT_REV="$(psql "$NODELINK_DB_URL" -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
TARGET_REV="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['schema_revision'])" nodelink-N.manifest.json)"

cd server
python scripts/plan_release_rollback.py \
  --backup-manifest ../nodelink-N.manifest.json \
  --current-schema-revision "$CURRENT_REV" \
  --target-schema-revision "$TARGET_REV" \
  --target-server-version '<N server tag+commit>' \
  --target-agent-version '<N agent version+SHA256SUMS digest>' \
  --target-installer-version '<N installer filename+digest>' \
  --agent-rollout-paused \
  --accept-data-loss \
  --evidence-output ../incident/rollback-plan.json
```

Omit `--accept-data-loss` when revisions match. When they differ, obtain the
named decision maker's approval for the backup timestamp-to-incident recovery
point before adding the flag. Exit code 2 means stop: do not restore or deploy.

### 4. Restore and validate N in isolation

Follow [`BACKUP-RESTORE.md`](BACKUP-RESTORE.md) to create a fresh isolated
database and restore N. Before promotion, run:

```bash
cd server
python scripts/verify_restore.py \
  --database-url 'postgresql+asyncpg://.../nodelink_restore' \
  --expected-schema-revision "$TARGET_REV" \
  --min-operators '<release-record count>' \
  --min-agents '<release-record count>' \
  --min-commands '<release-record count>' \
  --min-audit-events '<release-record count>' \
  --evidence-output ../incident/restore-verification.json
```

The command must report the expected schema, readable operators/agents/commands,
an intact audit chain, and intact stored anchors. Compare counts to the N
backup-time record and cross-check the restored last anchor against the retained
external anchor/receipt. Any mismatch blocks promotion.

### 5. Promote and redeploy the named components

1. Keep N+1 rollout and server automation paused.
2. Promote the validated database using the controlled procedure in
   `BACKUP-RESTORE.md`; retain the untouched failed-state database/backup.
3. Deploy the exact N server tag+commit and confirm its startup revision guard
   passes before enabling traffic.
4. Redeploy the exact N agent artifact to the staged canary endpoints first,
   using its retained checksum/provenance. For Windows reinstall/repair with the
   named N installer; merely changing the release channel does not downgrade an
   already installed service.
5. Expand only after the canary verification below succeeds. Keep N+1 blocked
   until a reviewed forward fix is ready.

### 6. Post-rollback verification

Record every result and UTC timestamp:

- server startup passes the exact Alembic revision guard;
- a known operator can authenticate and authorization still applies;
- canary agents check in with N and no endpoint reports N+1;
- a benign command sent to an owned canary completes exactly once;
- queue/error rates are stable and no external rollout reapplies N+1;
- `verify_restore.py` evidence remains `verified`;
- the audit chain and stored anchors verify, and external publication resumes
  from the preserved chain without overwriting prior receipts;
- recovery point, observed data-loss window, and recovery time are recorded.

If any check fails, stop expansion, keep writers quiesced where possible, and
choose a forward fix or another independently verified backup. Do not improvise
an in-place schema downgrade.

## Rehearsal evidence and remaining production work

`server/tests/test_backup_restore.py::test_release_rollback_rehearsal` performs
the complete data path against disposable PostgreSQL in CI: backup at N, add a
post-backup audit event and incompatible N+1 revision, prove the startup guard
fails, make the paused/approved compatibility decision, restore N, verify the
schema/operators/agents/commands/audit chain/anchor, and prove the N+1 event was
discarded. Negative planner tests cover unpaused rollout, absent data-loss
approval, incompatible backup revision, and malformed manifests.

The reproducible scenario and example evidence are recorded under
`deploy/backup/rehearsal/issue-26-ci.md`. This is an automated rehearsal, not a
claim that a production deployment, real external rollout system, or operator
incident drill has been exercised. A timed production-topology drill remains
required before production readiness can be marked complete.
