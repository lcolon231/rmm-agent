# Issue #26 CI rollback rehearsal evidence

This file describes **automated rehearsal evidence**, not a production drill.
The executable source of truth is
`server/tests/test_backup_restore.py::test_release_rollback_rehearsal`, run by
the PostgreSQL-backed server CI job.

## Scenario

| Step | Rehearsed evidence |
|---|---|
| Release N | Current Alembic head is seeded with an operator, agent, completed command, five audit events, and an anchor; an encrypted backup and manifest are created |
| Bad N+1 | A post-backup audit event is added and `alembic_version` is set to an unsupported rehearsal value; the production startup guard refuses it |
| Decision | The planner names `server-n-rehearsal`, `agent-n-rehearsal`, `installer-n-rehearsal`, and N's manifest schema; rollout pause and data loss are explicit |
| Restore | N is restored to a fresh isolated PostgreSQL database; encrypted and plaintext checksums and manifest revision must match |
| Verification | `verify_restore.py` first refuses a deliberately wrong expected schema, then emits JSON showing N's schema, nonzero operator/agent/command/audit counts, intact audit chain, and intact anchor |
| Data-loss proof | The deliberately post-backup N+1 audit event is absent after restoring N |

The planner evidence has this shape (timestamps and schema head are generated
by the test run):

```json
{
  "format": "nodelink-release-rollback-plan",
  "status": "ready",
  "action": "restore_backup_then_redeploy",
  "target": {
    "server_version": "server-n-rehearsal",
    "agent_version": "agent-n-rehearsal",
    "installer_version": "installer-n-rehearsal",
    "schema_revision": "0008"
  },
  "agent_rollout_paused": true,
  "restore_required": true,
  "data_loss_accepted": true
}
```

The restore verifier evidence has this shape:

```json
{
  "format": "nodelink-restore-verification",
  "status": "verified",
  "schema_revision": "0008",
  "audit_chain_intact": true,
  "failures": []
}
```

Reproduce in the repository's Linux CI-equivalent environment with PostgreSQL
16 and PostgreSQL client tools on `PATH`:

```bash
cd server
TEST_POSTGRES_URL='postgresql+asyncpg://rmm:rmm@127.0.0.1:5432/rmm_test' \
  pytest -q tests/test_backup_restore.py::test_release_rollback_rehearsal
```
