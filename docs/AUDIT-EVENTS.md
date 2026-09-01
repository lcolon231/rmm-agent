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
| `agent.version_changed` | `api/agents.py` heartbeat | `previous`, `current` |
| `agent.offline` | `core/tasks.py` offline sweep | `last_seen_at` |
| `agent.quarantined` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.restored` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.revoked` | `api/management.py` trust transition | `previous_trust_state`, `trust_state`, `reason_sha256`, `reason_bytes` |
| `agent.commands_expired_on_revoke` | `api/management.py` revoke cleanup | `command_ids` |
| `shell_session.opened` | `api/shell_sessions.py` session open (issue #61) | `session_id`, `capability_version`, `output_bytes_limit`, `absolute_deadline`, `idle_deadline` |
| `shell_session.viewed` | `api/shell_sessions.py` session status read | `session_id`, `status` |
| `shell_session.activated` | `api/shell_sessions.py` authenticated agent attach | `session_id`, `capability_version` |
| `shell_session.denied` | `api/shell_sessions.py` fail-closed open refusal | `session_id`, `reason`, `policy`, `trust_state` |
| `shell_session.closed` | `api/shell_sessions.py` operator close | `session_id`, `status`, `reason`, `output_bytes_total`, `frames_in`, `frames_out` |
| `shell_session.timed_out` | `core/tasks.py` shell session sweep | `session_id`, `reason`, `output_bytes_total`, `frames_in`, `frames_out` |
| `shell_session.failed` | `api/shell_sessions.py` fail-closed transport/process/output termination | `session_id`, `reason`, `output_bytes_total`, `output_bytes_limit`, `frames_in`, `frames_out` |
| `meshcentral.launch_requested` | `api/meshcentral.py` authorized remote-desktop launch record created (issue #62) | `launch_id`, `agent_id`, `meshcentral_node_id`, `mapping_id` |
| `meshcentral.session_launched` | `api/meshcentral.py` MeshCentral minted a scoped single-device access URL | `launch_id`, `agent_id`, `meshcentral_node_id`, `mapping_id`, `expires_at`, `meshcentral_session_ref`, `reason_sha256`, `reason_bytes` |
| `meshcentral.launch_denied` | `api/meshcentral.py` fail-closed launch refusal | `launch_id`, `agent_id`, `reason`, `policy`, `trust_state` |
| `meshcentral.launch_failed` | `api/meshcentral.py` MeshCentral unavailable/rejected the mint | `launch_id`, `agent_id`, `meshcentral_node_id`, `reason` |
| `meshcentral.session_closed` | `api/meshcentral.py` operator close (best-effort MeshCentral revoke) | `launch_id`, `agent_id`, `meshcentral_node_id`, `status`, `reason_sha256`, `reason_bytes` |
| `meshcentral.mapping_created` | `api/management.py` admin creates a manual agent-to-node mapping | `mapping_id`, `agent_id`, `meshcentral_node_id`, `origin` |
| `meshcentral.mapping_deleted` | `api/management.py` admin deletes a mapping | `mapping_id`, `agent_id`, `meshcentral_node_id` |
| `meshcentral.mapping_synced` | `api/management.py` reconciliation run summary (counts only) | `reconciled`, `active`, `stale`, `unmapped`, `conflict` |
| `meshcentral.mapping_stale` | `api/management.py` reconciliation aged a mapping | `mapping_id`, `agent_id`, `meshcentral_node_id`, `previous_state`, `state` |
| `audit.anchored` | `api/management.py` local anchor creation | `anchor_id`, `merkle_root`, `event_count` |
| `audit_timeline.viewed` | `api/management.py` audit timeline list | `event_type`, `actor_filter`, `agent_id`, `organization_id`, `date_from`, `date_to`, `before_seq`, `page`, `page_size`, `result_count`, `total` |
| `audit_event.viewed` | `api/management.py` audit event detail | `event_id`, `action`, `seq` |
| `inventory.received` | `api/agents.py` inventory submission | `stored_sections`, `unchanged_sections`, `schema_version`, `total_bytes` |
| `inventory.rejected` | `api/agents.py` inventory submission | `reason`, `section`, `byte_size`, `fields` |
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
| `patch_approval_policy.created` | `api/management.py` patch policy creation (issue #52) | `policy_id`, `scope`, `scope_id`, `enabled`, `rule_count`, `name_sha256`, `name_bytes`, `change_note_sha256`, `change_note_bytes` |
| `patch_approval_policy.revised` | `api/management.py` patch policy revision | `policy_id`, `version`, `enabled`, `rule_count`, `change_note_sha256`, `change_note_bytes` |
| `patch_approval_policy.deleted` | `api/management.py` patch policy deletion | `policy_id`, `scope`, `scope_id`, `name_sha256`, `name_bytes` |
| `patch_install.gated` | `api/management.py` install_updates approval gate | `policy_id`, `outcome`, `install_all`, `requested`, `approved`, `denied`, `deferred`, `window_required`, `window_present` |
| `patch_install.reboot_authorized` | `api/management.py` signed reboot evidence injected into an approved install (issue #53) | `policy_id`, `reboot_policy`, `delay_seconds`, `requires_no_user`, `window_present`, `user_present` |
| `patch_compliance.viewed` | `api/management.py` patch compliance summary or list view (issue #54) | `client_id`, `site_id`, `state`, `view`, `result_count` |
| `patch_compliance.exported` | `api/management.py` patch compliance CSV/JSON export (issue #54) | `client_id`, `site_id`, `state`, `format`, `row_count` |
| `evidence_bundle.exported` | `api/evidence.py` tenant evidence JSON/CSV/PDF/signed-ZIP download (issues #79/#80) | `bundle_id`, `package_id`, `signing_key_id`, `tenant_id`, `format`, `from_seq`, `through_seq`, `record_count`, `content_sha256` |
| `package_install.gated` | `api/management.py` package install/upgrade gate (issue #55) | `provider`, `operation`, `requested`, `source_present`, `source_digest`, `signer_present` |
| `package_scan.dispatched` | `api/management.py` package discovery dispatch (issue #55) | `provider` |
| `software_deployment.dispatched` | `api/management.py` MSI/EXE deployment dispatch (issue #56) | `installer_type`, `sha256`, `url_sha256`, `argument_count`, `timeout_seconds`, `signer_pinned`, `success_code_override`, `reboot_policy` |
| `service_control.dispatched` | `api/management.py` service control dispatch (issue #57) | `action`, `service`, `reason_sha256`, `reason_bytes` |
| `process_terminate.dispatched` | `api/management.py` process termination dispatch (issue #57) | `pid`, `expected_name_present`, `reason_sha256`, `reason_bytes` |
| `agent_update.release_published` | `api/agent_updates.py` signed agent release publication (issue #63) | `release_id`, `version`, `channel`, `platform`, `artifact_sha256`, `artifact_size_bytes`, `artifact_url_sha256`, `min_supported_version`, `signer_pinned`, `manifest_sha256`, `signing_key_id`, `failure_threshold_percent`, `min_attempts_before_halt` |
| `agent_update.rollout_advanced` | `api/agent_updates.py` staged rollout widened (issue #63) | `release_id`, `version`, `channel`, `rollout_percent`, `dispatched`, `truncated` |
| `agent_update.dispatched` | `api/agent_updates.py` signed self-update command queued for one endpoint (issue #63) | `release_id`, `command_id`, `version`, `channel`, `from_version`, `artifact_sha256`, `rollout_bucket` |
| `agent_update.rollout_paused` | `api/agent_updates.py` rollout paused (issue #63) | `release_id`, `rollout_percent` |
| `agent_update.rollout_resumed` | `api/agent_updates.py` rollout resumed (issue #63) | `release_id`, `rollout_percent` |
| `agent_update.rollout_halted` | `api/agent_updates.py` rollout halted by operator or canary rule (issue #63) | `release_id`, `version`, `channel`, `reason`, `rollout_percent` |
| `agent_update.halt_reason_recorded` | `api/agent_updates.py` operator halt justification (issue #63) | `release_id`, `reason_sha256`, `reason_bytes` |
| `agent_update.rollback_dispatched` | `api/management.py` operator-requested rollback to the retained previous build (issue #63) | `reason_sha256`, `reason_bytes`, `expected_current_version`, `current_version` |
| `agent_update.outcome_reported` | `api/agent_updates.py` endpoint post-restart resolution (issue #63) | `release_id`, `command_id`, `status`, `reason`, `from_version`, `to_version`, `observed_version`, `health_attempts`, `recorded` |
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
| `command.authorization_allowed` | `api/management.py` dispatch policy, including power-operation role decisions | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.authorization_denied` | `api/management.py` dispatch policy | `operator_id`, `operator_role`, `kind`, `site_id`, `policy`, `reason`, `permission_scope`, `permission_scope_id` |
| `command.completed` | `api/agents.py` result acceptance | `command_id`, `kind`, `exit_code`, `status`, `agent_completed_at`, `stdout_truncated`, `stderr_truncated`, `stdout_total_bytes`, `stderr_total_bytes` |
| `command.dispatched` | `api/management.py` signed dispatch; power intent is durable here before pickup | `command_id`, `kind`, `payload_keys`, `envelope_version`, `schema_version`, `issued_at`, `expires_at`, `nonce`, `signing_key_id`, `envelope_sha256`, `script_version_id`, `script_parameter_value_set_id` |
| `command.result_pending` | `api/agents.py` durable-result notice | `command_id`, `kind`, `agent_completed_at` |
| `event_log_query.dispatched` | `api/management.py` event log query dispatch (issue #58) | `channel`, `tier`, `time_window_seconds`, `max_events`, `provider_filter`, `level_filter`, `event_id_filter`, `paginated` |
| `command_detail.viewed` | `api/management.py` sensitive result view | `command_id`, `status` |
| `command_detail.access_denied` | `api/management.py` privileged remediation detail denial | `command_id`, `kind`, `operator_role`, `reason` |
| `endpoint_detail.viewed` | `api/management.py` endpoint detail | `history_hours`, `history_limit`, `history_count`, `history_truncated`, `script_execution_allowed` |
| `endpoint_list.viewed` | `api/management.py` endpoint list | `client_id`, `site_id`, `status`, `search`, `sort`, `direction`, `page`, `page_size`, `result_count` |
| `enrollment_token.created` | `api/management.py` token creation | `site_id`, `name_sha256`, `name_bytes`, `expires_at`, `max_uses`, `has_hostname_restriction`, `has_agent_name_restriction`, `labels` |
| `enrollment_token.revoked` | `api/management.py` token revocation | `site_id`, `reason_sha256`, `reason_bytes` |
| `installer_package.created` | `api/management.py` personalized installer download | `site_id`, `download_id`, `enrollment_token_id`, `artifact_version`, `artifact_sha256`, `token_expires_at` |
| `installer_package.rejected` | `api/management.py` personalized installer download | `site_id`, `reason` |
| `operator.script_permission_changed` | `api/auth.py` permission grant/change | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `new_scope`, `new_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.script_permission_revoked` | `api/auth.py` permission revoke | `operator_id`, `operator_role`, `previous_scope`, `previous_scope_id`, `reason_sha256`, `reason_bytes` |
| `operator.created` | `api/auth.py` operator creation | `operator_id`, `operator_role`, `email_sha256`, `email_bytes` |
| `operator.role_changed` | `api/auth.py` global-role change | `operator_id`, `previous_role`, `new_role`, `script_permission_revoked`, `reason_sha256`, `reason_bytes` |
| `operator.status_changed` | `api/auth.py` disable/re-enable | `operator_id`, `previous_disabled`, `new_disabled`, `reason_sha256`, `reason_bytes` |
| `operator.tokens_revoked` | `api/auth.py` token-generation bump | `operator_id`, `by` |
| `operator.session_started` | `api/auth.py` sign-in opening a tracked session (#69) | `operator_id`, `session_id`, `auth_methods`, `break_glass` |
| `operator.session_revoked` | `api/admin_sessions.py` self, other-devices, or administrative session revocation (#69) | `operator_id`, `session_id`, `by`, `reason_sha256`, `reason_bytes`, `session_count` |
| `break_glass.account_created` | `api/admin_sessions.py` emergency credential provisioned (#69); the credential itself is never recorded | `account_id`, `operator_id`, `label_sha256`, `label_bytes`, `credential_fingerprint`, `reason_sha256`, `reason_bytes` |
| `break_glass.credential_rotated` | `api/admin_sessions.py` emergency credential rotated (#69) | `account_id`, `label_sha256`, `label_bytes`, `previous_fingerprint`, `credential_fingerprint`, `reason_sha256`, `reason_bytes` |
| `break_glass.account_state_changed` | `api/admin_sessions.py` emergency credential disabled or re-enabled (#69) | `account_id`, `label_sha256`, `label_bytes`, `disabled`, `reason_sha256`, `reason_bytes` |
| `break_glass.activated` | `api/admin_sessions.py` emergency access used (#69) — the loudest event in the system | `account_id`, `activation_id`, `operator_id`, `session_id`, `label_sha256`, `label_bytes`, `credential_fingerprint`, `reason_sha256`, `reason_bytes` |
| `break_glass.activation_failed` | `api/admin_sessions.py` refused activation (#69); `reason` is a coded value, never the submitted credential | `reason` |
| `break_glass.activation_reviewed` | `api/admin_sessions.py` activation signed off (#69) | `activation_id`, `account_id`, `note_sha256`, `note_bytes` |
| `operator.tenant_membership_granted` | `api/auth.py` client-membership grant (#66) | `operator_id`, `client_id`, `previous_role`, `new_role`, `reason_sha256`, `reason_bytes` |
| `operator.tenant_membership_revoked` | `api/auth.py` client-membership revoke (#66) | `operator_id`, `client_id`, `previous_role`, `reason_sha256`, `reason_bytes` |
| `operator.platform_admin_changed` | `api/auth.py` platform-admin toggle (#66) | `operator_id`, `previous`, `new`, `reason_sha256`, `reason_bytes` |
| `tenant.access_denied` | `api/management.py` cross-tenant dispatch attempt (#66) | `operator_id`, `resource`, `agent_id`, `client_id` |
| `mfa.second_factor_required` | `api/auth.py` login that stopped at the password step | `operator_id`, `enrollment_required`, `methods` |
| `mfa.credential_registered` | `api/mfa.py` WebAuthn enrolment | `operator_id`, `credential_id`, `name_sha256`, `name_bytes`, `algorithm`, `aaguid`, `attestation_format`, `backup_eligible` |
| `mfa.credential_renamed` | `api/mfa.py` device rename | `operator_id`, `credential_id`, `previous_name_sha256`, `previous_name_bytes`, `new_name_sha256`, `new_name_bytes` |
| `mfa.credential_revoked` | `api/mfa.py` device revoke | `operator_id`, `credential_id`, `name_sha256`, `name_bytes`, `reason_sha256`, `reason_bytes`, `by` |
| `mfa.authentication_failed` | `api/mfa.py` refused ceremony; `reason` is a coded rule name, never a submitted value | `operator_id`, `method`, `reason` |
| `mfa.authentication_succeeded` | `api/mfa.py` accepted assertion | `operator_id`, `credential_id`, `method`, `purpose` |
| `mfa.step_up_succeeded` | `api/mfa.py` re-assertion for a sensitive operation | `operator_id`, `credential_id` |
| `mfa.recovery_codes_generated` | `api/mfa.py` recovery batch mint; the codes themselves are never recorded | `operator_id`, `batch_id`, `code_count` |
| `mfa.recovery_code_used` | `api/mfa.py` recovery login; which code was spent is deliberately not recorded | `operator_id`, `codes_remaining` |
| `mfa.reset` | `api/mfa.py` administrative MFA reset after device loss | `operator_id`, `credentials_revoked`, `recovery_codes_invalidated`, `reason_sha256`, `reason_bytes`, `by` |
| `scheduled_task.created` | `api/scheduled_tasks.py` task schedule creation | `scheduled_task_id`, `name_sha256`, `name_bytes`, `target_type`, `target_id`, `cron_expression`, `timezone`, `next_run_at`, `actor`, `actor_user_id`, `source_ip`, `user_agent` |
| `scheduled_task.updated` | `api/scheduled_tasks.py` task schedule update | `scheduled_task_id`, `name_sha256`, `name_bytes`, `enabled`, `next_run_at`, `actor`, `actor_user_id`, `source_ip`, `user_agent` |
| `scheduled_task.deleted` | `api/scheduled_tasks.py` task schedule deletion | `scheduled_task_id`, `name_sha256`, `name_bytes`, `target_type`, `target_id`, `actor`, `actor_user_id`, `source_ip`, `user_agent` |
| `scheduled_task.toggled` | `api/scheduled_tasks.py` task schedule enable/disable | `scheduled_task_id`, `name_sha256`, `name_bytes`, `enabled`, `actor`, `actor_user_id`, `source_ip`, `user_agent` |
| `scheduled_task.manually_triggered` | `api/scheduled_tasks.py` manual run-now trigger | `scheduled_task_id`, `name_sha256`, `name_bytes`, `dispatched_count`, `actor`, `actor_user_id`, `source_ip`, `user_agent` |
| `scheduled_task.dispatched` | `core/scheduler.py` cron dispatch tick | `scheduled_task_id`, `scheduled_task_name_sha256`, `scheduled_task_name_bytes`, `command_id`, `kind`, `target_type`, `target_id` |
| `scheduled_task.misfire_skipped` | `core/scheduler.py` misfire handling | `scheduled_task_id`, `scheduled_task_name_sha256`, `scheduled_task_name_bytes`, `scheduled_for`, `detected_at` |


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
