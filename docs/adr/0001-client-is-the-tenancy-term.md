# Client is the tenancy term; tenant_id and organization_id are frozen aliases

Status: accepted

The unit of isolation is called a **Client** (see `GLOSSARY.md`), matching the data model, routes and dashboard. Two older names for the same id are already fixed in places we cannot cheaply rename: `tenant_id` in the public `evidence-bundle-v1` and `webhook-event-v1` contracts (and the `tenant_*` policy tables), and `organization_id` on audit events, whose rows are hash-chained and cannot be rewritten. We keep both as aliases that always hold a Client id, and use `client_id` for every new field, column and contract; a frozen name is renamed only when its contract gets a new version.

## Considered Options

- **Make "tenant" canonical.** Consistent with the public v1 contracts and `tenant_scope`, but contradicts ~460 internal `client_id` uses and the MSP vocabulary operators already see.
- **Rename now with dual-write.** Breaks published v1 consumers or forces an early v2, and still cannot change audit rows already in the chain.
- **Use `tenant_id` for new public fields** to match v1. Rejected: it spreads the alias instead of containing it.

## Consequences

- Readers of an evidence bundle, webhook event or audit row must know `tenant_id` and `organization_id` mean the Client id; contract docs should say so.
- `tenant_scope` and the "tenant" wording in security docs are historical; new code and docs say "client boundary".
- An audit event with no `organization_id` should mean deployment-wide (for example a platform admin's setting change). Today it can also mean the producer forgot to set it; #327 makes the intended meaning hold.
