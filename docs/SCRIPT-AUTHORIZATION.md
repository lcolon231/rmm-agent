# Arbitrary script authorization

NodeLink treats arbitrary PowerShell and shell execution as a separate,
high-impact capability. An `operator` or `admin` role alone does not authorize
it. Every operator starts with no script permission, including newly created
admins and operators that existed before Alembic revision `0010`.

Typed operations are authorized independently. Today `collect_inventory` is
the only typed operation: `operator` and `admin` roles may dispatch it without
an arbitrary-script grant, while `readonly` may only view command records.

## Permission scopes

An admin may give an eligible operator exactly one script scope:

| Scope | Effect |
|---|---|
| `global` | PowerShell and shell commands may be dispatched to any active agent |
| `site` | Scripts may be dispatched only to agents in the named site |
| `agent` | Scripts may be dispatched only to the named agent |

Scopes are persistent until replaced or revoked. NodeLink does not yet support
multiple simultaneous scopes, expiration, tenant roles, approval workflows, or
per-script allowlists. Use the narrowest scope and revoke it when the work is
complete.

## Admin workflow

List operators and their current scope:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://nodelink.example/api/v1/auth/operators
```

Grant or replace a scope. A reason is mandatory:

```bash
curl -X PUT \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/auth/operators/OPERATOR_ID/script-permission \
  -d '{"scope":"site","scope_id":"SITE_ID","reason":"Approved maintenance window INC-1234"}'
```

For `global`, send `"scope_id": null`. For `site` or `agent`, the target must
exist. A `readonly` account cannot receive a grant.

Revoke the grant after the maintenance window:

```bash
curl -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://nodelink.example/api/v1/auth/operators/OPERATOR_ID/script-permission/revoke \
  -d '{"reason":"Maintenance window complete INC-1234"}'
```

The endpoint-detail API reports `script_execution_allowed` for the signed-in
operator and that endpoint. The dashboard uses this to hide arbitrary script
choices, but the FastAPI dispatch route is the security boundary.

## Fail-closed behavior and audit evidence

Authorization runs after the target agent is resolved but before an envelope is
created, signed, or queued. A refused request returns HTTP 403 with
`script_execution_not_authorized` and creates no command row.

The following hash-chained events are retained:

- `operator.script_permission_changed` and
  `operator.script_permission_revoked`, including the admin, target operator,
  old/new scope, and mandatory reason.
- `command.authorization_allowed` and `command.authorization_denied`,
  including operator, role, command kind, target site/agent, policy, and
  decision reason.

Authorization events never contain the command payload or script. Successful
dispatch continues to create the existing `command.dispatched` event with
payload key names and an envelope digest, not payload values.

## Rollout and recovery

Apply Alembic revision `0010` before starting the new server. The nullable
permission columns intentionally migrate every operator to default deny; no
existing role is grandfathered into arbitrary script execution. Grant only
after reviewing the operator and requested scope.

The agent protocol and binaries do not change. Rolling back the server requires
pausing dispatch and restoring a database backup at the rollback target's exact
revision; migrations are forward-only. Prefer a forward fix.
