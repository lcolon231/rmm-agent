# NodeLink audit-event contracts

This is the authoritative producer inventory and stored-detail contract for the
tamper-evident audit chain. It completes issue #115's requirement that every
event producer be reviewed, bounded, and documented.

`audit.record` calls `sanitize_audit_detail` before it allocates a sequence
number, hashes content, or adds an `AuditEvent` to the database. The boundary:

- rejects an unregistered action;
- requires the exact top-level fields listed below (missing or extra fields
  fail);
- rejects non-string keys, nested producer objects, nested arrays, bytes,
  unsupported objects, non-finite numbers, oversized strings, and oversized
  lists;
- redacts PEM private keys, JWTs, and credential-labelled values in readable
  scalar fields; and
- converts operator/agent-controlled prose to a UTF-8 SHA-256 plus byte count.

The last rule retains correlation evidence without making arbitrary prose
permanent. A field such as `reason` becomes `reason_sha256` and
`reason_bytes`; its plaintext is never hashed into or stored in the chain.
Public evidence needed for accountability and independent verification—actor,
action, target IDs, policy decision codes, nonces, key IDs, timestamps, counts,
and SHA-256/Merkle roots—remains readable.

## Registered actions

| Action | Producer | Stored detail fields |
|---|---|---|
| `agent.enrolled` | `api/agents.py` enrollment | `hostname_sha256`, `hostname_bytes`, `os_sha256`, `os_bytes`, `site_id`, `command_envelope_version`, `supported_command_envelope_versions` |
| `agent.command_envelope_capabilities_changed` | `api/agents.py` heartbeat | `previous`, `current` |
| `agent.offline` | `core/tasks.py` offline sweep | `last_seen_at` |
| `agent.quarantined` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.restored` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.revoked` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.commands_expired_on_revoke` | `api/management.py` revoke cleanup | `command_ids` |
| `audit.anchored` | `api/management.py` local anchor creation | `anchor_id`, `merkle_root`, `event_count` |
| `client_navigation.list_viewed` | `api/management.py` navigation list | `client_count`, `truncated` |
| `client_navigation.client_viewed` | `api/management.py` client view | `client_id` |
| `client_navigation.site_viewed` | `api/management.py` site view | `site_id`, `client_id` |
| `command.authorization_allowed` | `api/management.py` dispatch policy | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.authorization_denied` | `api/management.py` dispatch policy | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.completed` | `api/agents.py` result acceptance | `command_id`, `kind`, `exit_code`, `status`, `agent_completed_at`, `stdout_truncated`, `stderr_truncated`, `stdout_total_bytes`, `stderr_total_bytes` |
| `command.dispatched` | `api/management.py` signed dispatch | `command_id`, `kind`, `payload_keys`, `envelope_version`, `schema_version`, `issued_at`, `expires_at`, `nonce`, `signing_key_id`, `envelope_sha256` |
| `command.result_pending` | `api/agents.py` durable-result notice | `command_id`, `kind`, `agent_completed_at` |
| `command_detail.viewed` | `api/management.py` sensitive result view | `command_id`, `status` |
| `endpoint_detail.viewed` | `api/management.py` endpoint detail | `history_hours`, `history_limit`, `history_count`, `history_truncated`, `script_execution_allowed` |
| `endpoint_list.viewed` | `api/management.py` endpoint list | `client_id`, `site_id`, `status`, `search`, `sort`, `direction`, `page`, `page_size`, `result_count` |
| `operator.script_permission_changed` | `api/auth.py` permission grant/change | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `new_scope`, `new_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.script_permission_revoked` | `api/auth.py` permission revoke | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.tokens_revoked` | `api/auth.py` token-generation bump | `operator_id`, `by` |

`server/tests/test_redaction.py` parses the production source and compares every
literal producer (plus the typed trust-transition helper) with
`AUDIT_DETAIL_SCHEMAS`. A new action without a schema, sample, and documentation
fails the test suite. The same suite attempts to inject nested sentinel
credentials into every action, verifies that no rejected append consumes a
sequence number, persists one valid event for every action, and then verifies
the complete hash chain and its Merkle anchor over the stored safe form.

## Compatibility and recovery

This policy changes only new event input. Existing rows retain their original
canonical detail and continue to verify under their recorded hash schema. No
database migration or history rewrite is performed.

If a deployment fails after adding or changing a producer, treat an
`AuditDetailError` as a contract mismatch: stop that operation, correct the
producer/schema/documentation together, and deploy forward. Never bypass the
boundary or edit historical audit rows.
