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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
