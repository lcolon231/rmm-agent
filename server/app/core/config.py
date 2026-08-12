# SPDX-License-Identifier: AGPL-3.0-only
"""Application configuration loaded from environment variables."""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseConfigurationError(RuntimeError):
    """Raised when DATABASE_URL cannot select a supported database driver."""


def normalize_database_url(database_url: str) -> str:
    """Return a SQLAlchemy async URL without exposing credentials in errors."""
    value = database_url.strip()
    if value.startswith("postgresql+asyncpg://"):
        return value
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    if value.startswith("postgres://"):
        return value.replace("postgres://", "postgresql+asyncpg://", 1)
    if value.startswith("sqlite+aiosqlite://"):
        return value

    if value.startswith(("http://", "https://")):
        raise DatabaseConfigurationError(
            "DATABASE_URL must be a PostgreSQL connection string, not a "
            "Supabase project/API URL. In Supabase, open Connect, copy the "
            "Session pooler connection string, and store it in Render as "
            "DATABASE_URL."
        )
    raise DatabaseConfigurationError(
        "DATABASE_URL must use postgresql+asyncpg://, postgresql://, or "
        "postgres://. sqlite+aiosqlite:// is supported only for development "
        "and tests."
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Core ---
    app_name: str = "NodeLink RMM"
    environment: str = "development"
    debug: bool = True

    # Public HTTPS base URL clients use to reach this deployment (through the
    # TLS-terminating proxy), e.g. https://rmm.example.com. Required in
    # production, where it must be https://.
    public_base_url: str | None = None

    # Whether to trust X-Forwarded-For from the immediate upstream when
    # deriving the client IP (rate limiting, audit). Enable ONLY when uvicorn
    # is reachable exclusively through the trusted proxy — with this on, a
    # directly-reachable app port lets any caller spoof their address.
    trust_proxy_headers: bool = False

    # --- Database ---
    # Example: postgresql+asyncpg://rmm:rmm@localhost:5432/rmm
    database_url: str = "postgresql+asyncpg://rmm:rmm@localhost:5432/rmm"

    # --- Security ---
    # Used to sign server-issued JWTs (dashboard sessions + agent command tokens).
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Failed logins allowed per (client IP, email) within the window before
    # further attempts are rejected with 429.
    login_max_failures: int = 5
    login_window_seconds: int = 300
    # Enrollment attempts (successful or failed) allowed per source IP in the
    # process-local window. Multi-worker deployments require the shared limiter
    # tracked in docs/agent-enrollment/open-issues.md.
    enrollment_rate_limit_attempts: int = 10
    enrollment_rate_limit_window_seconds: int = 60
    enrollment_token_default_expiry_hours: int = 24
    enrollment_token_max_expiry_days: int = 30
    enrollment_token_max_uses: int = 100

    # Agent credential lifetime and loss-safe renewal (issue #125). An enrolled
    # agent holds a bearer credential with a finite lifetime and renews it before
    # expiry. On renewal the just-superseded credential stays valid for a bounded
    # overlap window so a lost renewal response cannot strand a healthy endpoint:
    # the agent keeps working on the old credential and simply retries. Keep the
    # overlap well below the lifetime — it only needs to cover a renewal retry.
    agent_credential_lifetime_seconds: int = 86_400  # 24h
    agent_credential_overlap_seconds: int = 600  # 10 min

    # --- Personalized agent installer downloads (issue #9) ---
    # Path to the pre-built, signed stock Windows installer the server bundles
    # into a personalized download. The server never rebuilds or re-signs it — it
    # ships the verified artifact as-is and only adds a sidecar token file. Unset
    # disables the feature (the download endpoint returns 503).
    installer_artifact_path: str | None = None
    # Optional expected SHA-256 (hex) of the artifact. When set, a mismatch fails
    # closed so a tampered stock installer is never distributed.
    installer_artifact_sha256: str | None = None
    # Human-facing version label recorded with each download for audit/lineage.
    installer_artifact_version: str = "unknown"
    # Lifetime of the short-lived, single-use enrollment token minted into a
    # personalized download. Kept small so a leaked package expires quickly.
    installer_token_ttl_seconds: int = 3_600  # 1h

    # Ed25519 private key (PEM) used to SIGN commands sent to agents.
    # Agents hold the matching public key and verify every command before executing.
    # Generate a keypair with the helper in scripts/gen_command_keys.py
    command_signing_key_path: str = "command_signing_key.pem"
    # Stable identifier for the single-key fallback. For staged rotation,
    # point this at a JSON registry containing active/overlap/retired keys.
    command_signing_key_id: str = "default"
    command_signing_keyring_path: str | None = None

    # --- Agent policy ---
    heartbeat_interval_seconds: int = 60
    # Endpoint is flagged offline after this many missed heartbeats.
    offline_after_missed: int = 3

    # --- Command concurrency and admission ---
    # Admission control: the maximum number of *outstanding* commands (queued,
    # dispatched, running, or result-pending — anything not in a terminal
    # state) an agent may have at once. Dispatching past this is refused, so an
    # operator or a bug
    # cannot pile unbounded work on one endpoint.
    max_outstanding_commands_per_agent: int = 100
    # Delivery pacing: the most commands handed to an agent in a single
    # heartbeat. The agent executes one at a time (its concurrency contract),
    # so a large backlog drains over several beats instead of arriving at once.
    max_commands_per_heartbeat: int = 10
    # A dispatched command is eligible for safe re-delivery after this lease.
    # New agents durably reserve before execution, so re-delivery repairs a
    # lost heartbeat response or stop-before-start without duplicate execution.
    command_redelivery_seconds: int = 120

    # --- Interactive shell sessions (issue #61) ---
    # Server-authoritative bounds for a live shell session. The absolute
    # lifetime caps total duration; the idle timeout ends a session with no I/O.
    # The output cap bounds total streamed bytes (fail closed on exceed). At most
    # one active session per agent is admitted. The poll timeout bounds how long
    # a long-poll waits for a frame before returning empty.
    shell_session_max_lifetime_seconds: int = 1800
    shell_session_idle_timeout_seconds: int = 300
    shell_session_output_byte_limit: int = 1024 * 1024
    shell_session_max_concurrent_per_agent: int = 1
    shell_session_poll_timeout_seconds: int = 25
    shell_session_max_frame_bytes: int = 16 * 1024
    shell_session_relay_buffer_bytes: int = 128 * 1024
    shell_session_input_buffer_bytes: int = 64 * 1024
    shell_session_relay_max_frames: int = 128

    @property
    def offline_threshold_seconds(self) -> int:
        return self.heartbeat_interval_seconds * self.offline_after_missed

    # --- External audit-anchor publication (issue #76) ---
    # Backend that publishes anchor Merkle roots to an external immutable
    # destination. "none" disables publication (a loud warning is logged in
    # production). "filesystem" writes to an append-only directory (real
    # immutability only on a WORM/object-lock mount). "s3" writes to an
    # S3-compatible bucket with Object Lock.
    anchor_publish_backend: str = "none"  # none | filesystem | s3
    # How often the scheduler creates a new anchor (if events accrued) and
    # publishes any unpublished ones.
    anchor_publish_interval_seconds: int = 3600
    # Warn when the oldest unpublished anchor is older than this — the window
    # during which a database-owning attacker could rewrite history unnoticed.
    anchor_publish_lag_alert_seconds: int = 7200

    # filesystem backend
    anchor_publish_dir: str = "/var/lib/nodelink/anchors"

    # s3 backend (credentials come from the standard AWS chain — env,
    # instance profile, etc. — never from settings, never stored in receipts)
    anchor_s3_bucket: str | None = None
    anchor_s3_prefix: str = "nodelink/anchors"
    anchor_s3_region: str | None = None
    anchor_s3_endpoint_url: str | None = None  # set for MinIO/Backblaze/etc.
    # Object Lock retention applied to each published object. GOVERNANCE lets a
    # privileged user bypass with a special permission; COMPLIANCE cannot be
    # bypassed by anyone until the window elapses. Days = 0 disables setting
    # retention (bucket-default or none).
    anchor_s3_object_lock_mode: str = "COMPLIANCE"  # GOVERNANCE | COMPLIANCE
    anchor_s3_retain_days: int = 3650

    # --- Storage growth / retention (issue #114) ---
    # Telemetry (heartbeats) is high-volume, non-compliance data. Rows older
    # than this are pruned. 0 disables pruning (unbounded — not recommended).
    telemetry_retention_days: int = 30
    # Captured command stdout/stderr can be the largest single data class. Past
    # this age the *text* is cleared from terminal commands while the row and
    # its accountability metadata (exit code, truncation totals) — and the audit
    # events — are kept. 0 disables clearing. Audit events, anchors, and anchor
    # receipts are NEVER pruned, so chain/anchor verification is unaffected.
    command_output_retention_days: int = 90
    # How many historical snapshots to keep per (agent, section). The newest is
    # never pruned regardless of this value: it is the endpoint's current
    # reported state, not history, and deleting it would make a managed machine
    # look like it had never reported. 0 disables inventory pruning.
    inventory_history_per_section: int = 50
    # Phase-1 monitoring bounds (issue #41). Schema validation applies the
    # hard per-policy/check limits; these settings cap deployment-wide growth
    # and the retained result history for each endpoint/check pair.
    monitoring_max_policies: int = 500
    monitoring_max_checks_per_policy: int = 100
    monitoring_check_interval_min_seconds: int = 30
    monitoring_check_interval_max_seconds: int = 86_400
    check_result_history_per_key: int = 100
    monitoring_max_maintenance_windows: int = 500

    # --- Patch installation and reboot policy (issue #53) ---
    # Defaults applied when a patch policy revision leaves them unset. Reboot
    # stays fail-safe (never) at the policy level; these bound the values a
    # policy may carry.
    patch_install_default_max_attempts: int = 2
    patch_reboot_default_delay_seconds: int = 300

    # --- Patch compliance reporting (issue #54) ---
    # A scan older than this is reported "stale". The scope size is capped so a
    # single report cannot iterate an unbounded fleet; history is bounded to the
    # retained snapshots.
    patch_compliance_stale_after_hours: int = 24
    patch_compliance_max_endpoints: int = 5000
    patch_compliance_history_limit: int = 50

    # --- Alert email delivery (issue #45) ---
    # "disabled" is the safe default. "resend" uses the HTTPS Email API;
    # credentials remain environment-only and are never persisted or returned.
    email_alert_provider: str = "disabled"  # disabled | resend
    email_alert_resend_api_key: str | None = None
    email_alert_sender: str | None = None
    # Comma-separated, deployment-owned distribution list (maximum 50).
    email_alert_recipients: str = ""
    # Optional dashboard origin used for alert links in messages. When absent,
    # messages contain the alert id but no clickable link.
    email_alert_dashboard_base_url: str | None = None
    email_alert_poll_interval_seconds: int = 15
    email_alert_batch_size: int = 25
    email_alert_max_attempts: int = 5
    email_alert_backoff_base_seconds: int = 30
    email_alert_backoff_max_seconds: int = 3600
    email_alert_claim_timeout_seconds: int = 300
    email_alert_request_timeout_seconds: int = 10

    # --- Signed webhook delivery (issue #46) ---
    # Base64url-encoded 32-byte AES-GCM key used only to encrypt endpoint
    # signing secrets at rest. Endpoint creation and rotation fail closed when
    # it is absent or malformed; the value is never returned or persisted.
    webhook_secret_encryption_key: str | None = None
    webhook_poll_interval_seconds: int = Field(default=15, ge=1, le=3600)
    webhook_batch_size: int = Field(default=25, ge=1, le=100)
    webhook_max_attempts: int = Field(default=5, ge=1, le=20)
    webhook_backoff_base_seconds: int = Field(default=30, ge=1, le=3600)
    webhook_backoff_max_seconds: int = Field(default=3600, ge=1, le=86_400)
    webhook_claim_timeout_seconds: int = Field(default=300, ge=30, le=3600)
    webhook_request_timeout_seconds: int = Field(default=10, ge=1, le=30)
    webhook_dns_timeout_seconds: int = Field(default=5, ge=1, le=30)
    webhook_max_endpoints: int = Field(default=50, ge=1, le=100)

    # --- Immutable script library (issue #47) ---
    script_library_max_items: int = Field(default=1_000, ge=1, le=10_000)
    script_library_max_versions_per_script: int = Field(
        default=100, ge=1, le=1_000
    )
    script_library_max_content_bytes: int = Field(
        default=57_344, ge=1_024, le=57_344
    )
    # Separate 32-byte AES-GCM key for expiring per-run parameter values. It
    # must remain stable while prepared value sets may still be consumed.
    script_parameter_encryption_key: str | None = None
    script_parameter_value_ttl_seconds: int = Field(
        default=86_400, ge=300, le=604_800
    )
    script_parameter_max_values_bytes: int = Field(
        default=32_768, ge=1_024, le=65_536
    )
    script_parameter_max_sets_per_version: int = Field(
        default=10_000, ge=1, le=100_000
    )

    # How often the retention sweep runs.
    retention_sweep_interval_seconds: int = 86_400  # daily
    # Filesystem path whose free space is reported/alerted in /storage/status
    # (server host disk backing logs, backups, and — for local DBs — data).
    retention_disk_path: str = "/"

    # Observability thresholds: a breach sets an alert flag in /storage/status
    # and logs a warning from the retention sweeper. They do not delete data.
    heartbeat_backlog_alert: int = 5_000_000    # total heartbeat rows
    command_backlog_alert: int = 1_000_000      # total command rows
    disk_free_alert_bytes: int = 1_073_741_824  # 1 GiB free remaining


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
