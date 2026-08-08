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
| `agent.enrolled` | `api/agents.py` enrollment | `hostname_sha256`, `hostname_bytes`, `agent_name_sha256`, `agent_name_bytes`, `os_sha256`, `os_bytes`, `architecture`, `site_id`, `environment`, `command_envelope_version`, `supported_command_envelope_versions`, `public_key_supplied` |
| `agent.enrollment_failed` | `api/agents.py` rejected enrollment | `reason`, `hostname_sha256`, `hostname_bytes`, `agent_name_sha256`, `agent_name_bytes` |
| `agent.credential_renewed` | `api/agents.py` credential renewal | `credential_fingerprint`, `credential_generation` |
| `agent.credential_renewal_rejected` | `api/agents.py` credential renewal | `reason` |
| `agent.command_envelope_capabilities_changed` | `api/agents.py` heartbeat | `previous`, `current` |
| `agent.offline` | `core/tasks.py` offline sweep | `last_seen_at` |
| `agent.quarantined` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.restored` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.revoked` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.commands_expired_on_revoke` | `api/management.py` revoke cleanup | `command_ids` |
| `audit.anchored` | `api/management.py` local anchor creation | `anchor_id`, `merkle_root`, `event_count` |
| `audit_timeline.viewed` | `api/management.py` audit timeline list | `event_type`, `actor_filter`, `agent_id`, `organization_id`, `date_from`, `date_to`, `before_seq`, `page`, `page_size`, `result_count`, `total` |
| `audit_event.viewed` | `api/management.py` audit event detail | `event_id`, `action`, `seq` |
| `inventory.received` | `api/agents.py` inventory submission | `stored_sections`, `unchanged_sections`, `schema_version`, `total_bytes` |
| `inventory.rejected` | `api/agents.py` inventory submission | `reason`, `section`, `byte_size` |
| `inventory.viewed` | `api/management.py` inventory view | `sections`, `missing_sections` |
| `inventory.diff_viewed` | `api/management.py` inventory diff | `section`, `from_snapshot`, `to_snapshot` |
| `client_navigation.list_viewed` | `api/management.py` navigation list | `client_count`, `truncated` |
| `client_navigation.client_viewed` | `api/management.py` client view | `client_id` |
| `client_navigation.site_viewed` | `api/management.py` site view | `site_id`, `client_id` |
| `client.created` | `api/management.py` client creation | `client_id`, `name_sha256`, `name_bytes` |
| `site.created` | `api/management.py` site creation | `site_id`, `client_id`, `name_sha256`, `name_bytes` |
| `monitoring_policy.created` | `api/management.py` policy creation | `policy_id`, `scope`, `scope_id`, `enabled`, `check_count`, `name_sha256`, `name_bytes`, `change_note_sha256`, `change_note_bytes` |
| `monitoring_policy.revised` | `api/management.py` policy revision | `policy_id`, `version`, `enabled`, `check_count`, `change_note_sha256`, `change_note_bytes` |
| `monitoring_policy.deleted` | `api/management.py` policy deletion | `policy_id`, `scope`, `scope_id`, `name_sha256`, `name_bytes` |
| `monitoring_policy.viewed` | `api/management.py` policy detail view | `policy_id`, `version`, `check_count`, `revision_count` |
| `monitoring_alert.acknowledged` | `api/management.py` technician acknowledgement | `alert_id`, `generation`, `request_id`, `from_state`, `to_state`, `comment_sha256`, `comment_bytes`, `comment_redacted` |
| `monitoring_alert.assigned` | `api/management.py` technician assignment | `alert_id`, `generation`, `request_id`, `assigned_to_operator_id`, `assigned_to_email_sha256`, `assigned_to_email_bytes`, `comment_sha256`, `comment_bytes`, `comment_redacted` |
| `monitoring_alert.commented` | `api/management.py` technician comment | `alert_id`, `generation`, `request_id`, `state`, `comment_sha256`, `comment_bytes`, `comment_redacted` |
| `monitoring_alert.resolved` | `api/management.py` manual resolution | `alert_id`, `generation`, `request_id`, `from_state`, `to_state`, `comment_sha256`, `comment_bytes`, `comment_redacted` |
| `monitoring_alert_email.retried` | `api/management.py` operator-requested failed-delivery retry | `delivery_id`, `alert_id`, `request_id`, `previous_status`, `recipient_sha256`, `recipient_bytes` |
| `webhook_endpoint.created` | `api/management.py` endpoint creation | `endpoint_id`, `name_sha256`, `name_bytes`, `url_sha256`, `url_bytes`, `enabled`, `event_types`, `secret_version` |
| `webhook_endpoint.updated` | `api/management.py` endpoint revision | `endpoint_id`, `request_id`, `previous_version`, `version`, `name_sha256`, `name_bytes`, `url_sha256`, `url_bytes`, `enabled`, `event_types` |
| `webhook_endpoint.deleted` | `api/management.py` endpoint soft deletion | `endpoint_id`, `request_id`, `previous_version`, `version`, `name_sha256`, `name_bytes`, `url_sha256`, `url_bytes` |
| `webhook_endpoint.secret_rotated` | `api/management.py` signing-secret rotation | `endpoint_id`, `request_id`, `previous_version`, `version`, `previous_secret_version`, `secret_version` |
| `monitoring_alert_webhook.retried` | `api/management.py` operator-requested failed webhook retry | `delivery_id`, `alert_id`, `endpoint_id`, `request_id`, `previous_status`, `destination_sha256`, `destination_bytes` |
| `script_library.list_viewed` | `api/script_library.py` bounded register read | `page`, `page_size`, `result_count`, `total` |
| `script_library.item_viewed` | `api/script_library.py` item/version-ledger read | `script_id`, `version_count` |
| `script_library.version_viewed` | `api/script_library.py` exact source read | `script_id`, `version`, `content_sha256`, `content_bytes` |
| `script_library.created` | `api/script_library.py` stable identity and v1 draft | `script_id`, `version`, `language`, `content_sha256`, `content_bytes`, `tags`, `supported_platforms`, `parameter_count`, `name_sha256`, `name_bytes` |
| `script_library.version_created` | `api/script_library.py` immutable version append | `script_id`, `version`, `language`, `content_sha256`, `content_bytes`, `tags`, `supported_platforms`, `parameter_count` |
| `script_library.parameter_values_prepared` | `api/script_library.py` encrypted per-run parameter values | `script_id`, `version`, `parameter_value_set_id`, `request_id`, `provided_keys`, `defaulted_keys`, `secret_keys`, `values_fingerprint`, `expires_at` |
| `script_library.reviewed` | `api/script_library.py` final review | `script_id`, `version`, `state`, `reason_sha256`, `reason_bytes` |
| `script_library.deprecated` | `api/script_library.py` terminal idempotent deprecation | `script_id`, `request_id`, `previous_record_version`, `record_version`, `reason_sha256`, `reason_bytes` |
| `maintenance_window.created` | `api/management.py` maintenance-window creation | `maintenance_window_id`, `scope`, `scope_id`, `starts_at`, `ends_at`, `name_sha256`, `name_bytes` |
| `maintenance_window.deleted` | `api/management.py` maintenance-window deletion | `maintenance_window_id`, `scope`, `scope_id`, `name_sha256`, `name_bytes` |
| `command.authorization_allowed` | `api/management.py` dispatch policy | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.authorization_denied` | `api/management.py` dispatch policy | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.completed` | `api/agents.py` result acceptance | `command_id`, `kind`, `exit_code`, `status`, `agent_completed_at`, `stdout_truncated`, `stderr_truncated`, `stdout_total_bytes`, `stderr_total_bytes` |
| `command.dispatched` | `api/management.py` signed dispatch | `command_id`, `kind`, `payload_keys`, `envelope_version`, `schema_version`, `issued_at`, `expires_at`, `nonce`, `signing_key_id`, `envelope_sha256`, `script_version_id`, `script_parameter_value_set_id` |
| `command.result_pending` | `api/agents.py` durable-result notice | `command_id`, `kind`, `agent_completed_at` |
| `command_detail.viewed` | `api/management.py` sensitive result view | `command_id`, `status` |
| `endpoint_detail.viewed` | `api/management.py` endpoint detail | `history_hours`, `history_limit`, `history_count`, `history_truncated`, `script_execution_allowed` |
| `endpoint_list.viewed` | `api/management.py` endpoint list | `client_id`, `site_id`, `status`, `search`, `sort`, `direction`, `page`, `page_size`, `result_count` |
| `enrollment_token.created` | `api/management.py` token creation | `site_id`, `name_sha256`, `name_bytes`, `expires_at`, `max_uses`, `has_hostname_restriction`, `has_agent_name_restriction`, `labels` |
| `enrollment_token.revoked` | `api/management.py` token revocation | `site_id`, `reason_sha256`, `reason_bytes` |
| `operator.script_permission_changed` | `api/auth.py` permission grant/change | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `new_scope`, `new_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.script_permission_revoked` | `api/auth.py` permission revoke | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.created` | `api/auth.py` operator creation | `operator_id`, `operator_role`, `email_sha256`, `email_bytes` |
| `operator.role_changed` | `api/auth.py` global-role change | `operator_id`, `previous_role`, `new_role`, `script_permission_revoked`, `reason_sha256`, `reason_bytes` |
| `operator.status_changed` | `api/auth.py` disable/re-enable | `operator_id`, `previous_disabled`, `new_disabled`, `reason_sha256`, `reason_bytes` |
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
