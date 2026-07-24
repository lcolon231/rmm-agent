# SPDX-License-Identifier: AGPL-3.0-only
"""Application configuration loaded from environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # dispatched, or running — anything not in a terminal state) an agent may
    # have at once. Dispatching past this is refused, so an operator or a bug
    # cannot pile unbounded work on one endpoint.
    max_outstanding_commands_per_agent: int = 100
    # Delivery pacing: the most commands handed to an agent in a single
    # heartbeat. The agent executes one at a time (its concurrency contract),
    # so a large backlog drains over several beats instead of arriving at once.
    max_commands_per_heartbeat: int = 10

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
